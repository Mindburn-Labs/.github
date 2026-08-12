"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const worker = require("../scripts/docs_truth_trusted_worker.js");

const BASE_SHA = "a".repeat(40);
const HEAD_SHA = "b".repeat(40);
const MERGE_SHA = "c".repeat(40);

function run(overrides = {}) {
  return {
    id: 71,
    run_attempt: 1,
    repository: { full_name: worker.EXPECTED_REPOSITORY },
    head_repository: { full_name: worker.EXPECTED_REPOSITORY },
    workflow_id: worker.EXPECTED_WORKFLOW_ID,
    name: worker.EXPECTED_WORKFLOW_NAME,
    path: worker.EXPECTED_WORKFLOW_PATH,
    event: "pull_request",
    status: "completed",
    conclusion: "success",
    head_sha: HEAD_SHA,
    ...overrides,
  };
}

function pull(overrides = {}) {
  return {
    number: 17,
    state: "open",
    base: { ref: "main", sha: BASE_SHA, repo: { full_name: worker.EXPECTED_REPOSITORY } },
    head: { sha: HEAD_SHA, repo: { full_name: worker.EXPECTED_REPOSITORY } },
    merge_commit_sha: MERGE_SHA,
    ...overrides,
  };
}

function harness({ apiRun = run(), associated = [pull()], livePull = pull() } = {}) {
  const statuses = [];
  const github = {
    paginate: async () => associated,
    rest: {
      actions: { getWorkflowRun: async () => ({ data: apiRun }) },
      pulls: { get: async () => ({ data: livePull }) },
      repos: {
        createCommitStatus: async (status) => {
          statuses.push(status);
        },
      },
    },
  };
  const context = { eventName: "workflow_run", payload: { workflow_run: run() } };
  return { context, github, statuses };
}

test("admission binds one exact same-repository pull request and publishes pending", async () => {
  const { context, github, statuses } = harness();
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "docs-truth-admission-"));
  const admissionPath = path.join(root, "admission.json");
  try {
    const snapshot = await worker.admit({
      github,
      context,
      admissionPath,
      targetUrl: "https://example.test/run/1",
    });
    assert.equal(snapshot.admission.head.sha, HEAD_SHA);
    assert.deepEqual(JSON.parse(fs.readFileSync(admissionPath, "utf8")), snapshot.admission);
    assert.equal(fs.statSync(admissionPath).mode & 0o777, 0o600);
    assert.deepEqual(statuses.map(({ state, context: name, sha }) => ({ state, name, sha })), [
      { state: "pending", name: worker.STATUS_CONTEXT, sha: HEAD_SHA },
    ]);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("forks, workflow mismatches, and ambiguous pull requests fail before status publication", async () => {
  const cases = [
    harness({ apiRun: run({ workflow_id: 1 }) }),
    harness({ associated: [pull(), pull({ number: 18 })] }),
    harness({ livePull: pull({ head: { sha: HEAD_SHA, repo: { full_name: "attacker/app-helm-docs" } } }) }),
  ];
  for (const current of cases) {
    await assert.rejects(() => worker.deriveSnapshot(current));
    assert.deepEqual(current.statuses, []);
  }
});

test("finalization publishes success only after an unchanged live snapshot", async () => {
  const current = harness();
  const expected = await worker.deriveSnapshot(current);
  await worker.finalize({
    github: current.github,
    context: current.context,
    expected,
    workerSucceeded: true,
    targetUrl: "https://example.test/run/1",
  });
  assert.equal(current.statuses.at(-1).state, "success");
  assert.equal(current.statuses.at(-1).sha, HEAD_SHA);
});

test("a changed pull request publishes failure on the originally admitted head", async () => {
  const initial = harness();
  const expected = await worker.deriveSnapshot(initial);
  const moved = harness({
    livePull: pull({
      base: { ref: "main", sha: "d".repeat(40), repo: { full_name: worker.EXPECTED_REPOSITORY } },
      merge_commit_sha: "e".repeat(40),
    }),
  });
  await assert.rejects(() =>
    worker.finalize({
      github: moved.github,
      context: moved.context,
      expected,
      workerSucceeded: true,
      targetUrl: "https://example.test/run/1",
    }),
  );
  assert.equal(moved.statuses.at(-1).state, "failure");
  assert.equal(moved.statuses.at(-1).sha, HEAD_SHA);
});

test("a failed computation publishes failure after final freshness validation", async () => {
  const current = harness();
  const expected = await worker.deriveSnapshot(current);
  await assert.rejects(() =>
    worker.finalize({
      github: current.github,
      context: current.context,
      expected,
      workerSucceeded: false,
      targetUrl: "https://example.test/run/1",
    }),
  );
  assert.equal(current.statuses.at(-1).state, "failure");
  assert.equal(current.statuses.at(-1).sha, HEAD_SHA);
});
