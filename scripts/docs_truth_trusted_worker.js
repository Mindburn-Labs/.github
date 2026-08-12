"use strict";

const fs = require("fs");

const EXPECTED_REPOSITORY = "Mindburn-Labs/app-helm-docs";
const EXPECTED_WORKFLOW_ID = 305654002;
const EXPECTED_WORKFLOW_NAME = "Docs Truth";
const EXPECTED_WORKFLOW_PATH = ".github/workflows/docs-truth.yml";
const STATUS_CONTEXT = "docs-truth-trusted";
const SHA_PATTERN = /^[0-9a-f]{40}$/;

function reject(message) {
  throw new Error(`docs-truth admission rejected: ${message}`);
}

function requirePositiveInteger(value, label) {
  if (!Number.isSafeInteger(value) || value <= 0) reject(`${label} must be a positive integer`);
  return value;
}

function requireSha(value, label) {
  if (typeof value !== "string" || !SHA_PATTERN.test(value)) reject(`${label} must be a lowercase SHA`);
  return value;
}

function requireRun(run, label) {
  if (!run || typeof run !== "object") reject(`${label} is missing`);
  if (run.repository?.full_name !== EXPECTED_REPOSITORY) reject(`${label}.repository mismatch`);
  if (run.head_repository?.full_name !== EXPECTED_REPOSITORY) reject(`${label}.head_repository mismatch`);
  if (run.workflow_id !== EXPECTED_WORKFLOW_ID) reject(`${label}.workflow_id mismatch`);
  if (run.name !== EXPECTED_WORKFLOW_NAME) reject(`${label}.name mismatch`);
  if (run.path !== EXPECTED_WORKFLOW_PATH) reject(`${label}.path mismatch`);
  if (run.event !== "pull_request") reject(`${label}.event must be pull_request`);
  if (run.status !== "completed" || run.conclusion !== "success") {
    reject(`${label} must be a successful completed run`);
  }
  requirePositiveInteger(run.id, `${label}.id`);
  requirePositiveInteger(run.run_attempt, `${label}.run_attempt`);
  requireSha(run.head_sha, `${label}.head_sha`);
}

async function deriveSnapshot({ github, context }) {
  if (context.eventName !== "workflow_run") reject("caller event must be workflow_run");
  const eventRun = context.payload?.workflow_run;
  requireRun(eventRun, "event.workflow_run");

  const [owner, repo] = EXPECTED_REPOSITORY.split("/");
  const response = await github.rest.actions.getWorkflowRun({
    owner,
    repo,
    run_id: eventRun.id,
    exclude_pull_requests: false,
  });
  const run = response.data;
  requireRun(run, "api.workflow_run");
  if (run.id !== eventRun.id) reject("workflow run id changed across snapshots");
  if (run.run_attempt !== eventRun.run_attempt) reject("workflow run attempt changed across snapshots");
  if (run.head_sha !== eventRun.head_sha) reject("workflow run head changed across snapshots");

  const associated = await github.paginate(
    "GET /repos/{owner}/{repo}/commits/{commit_sha}/pulls",
    { owner, repo, commit_sha: run.head_sha, per_page: 100 },
  );
  const candidates = associated.filter(
    (pull) =>
      pull.state === "open" &&
      pull.base?.ref === "main" &&
      pull.base?.repo?.full_name === EXPECTED_REPOSITORY &&
      pull.head?.repo?.full_name === EXPECTED_REPOSITORY &&
      pull.head?.sha === run.head_sha,
  );
  if (candidates.length !== 1) reject("head SHA must identify exactly one open same-repository PR to main");

  const prNumber = requirePositiveInteger(candidates[0].number, "pull_request.number");
  const pullResponse = await github.rest.pulls.get({ owner, repo, pull_number: prNumber });
  const pull = pullResponse.data;
  if (pull.state !== "open") reject("pull request must remain open");
  if (pull.base?.ref !== "main" || pull.base?.repo?.full_name !== EXPECTED_REPOSITORY) {
    reject("pull request base mismatch");
  }
  if (pull.head?.repo?.full_name !== EXPECTED_REPOSITORY) reject("fork pull requests are not admitted");
  const baseSha = requireSha(pull.base?.sha, "pull_request.base.sha");
  const headSha = requireSha(pull.head?.sha, "pull_request.head.sha");
  const mergeSha = requireSha(pull.merge_commit_sha, "pull_request.merge_commit_sha");
  if (headSha !== run.head_sha) reject("pull request head does not match workflow run head");

  return {
    workflow_run_id: run.id,
    workflow_run_attempt: run.run_attempt,
    admission: {
      schema: "mindburn.authority-pr-admission/v1",
      repository: EXPECTED_REPOSITORY,
      pr_number: prNumber,
      base: { ref: "main", sha: baseSha },
      head: { repository: EXPECTED_REPOSITORY, sha: headSha },
      merge_sha: mergeSha,
      workflow_run_head_sha: run.head_sha,
    },
  };
}

function sameSnapshot(left, right) {
  return (
    left.workflow_run_id === right.workflow_run_id &&
    left.workflow_run_attempt === right.workflow_run_attempt &&
    left.admission.repository === right.admission.repository &&
    left.admission.pr_number === right.admission.pr_number &&
    left.admission.base.ref === right.admission.base.ref &&
    left.admission.base.sha === right.admission.base.sha &&
    left.admission.head.repository === right.admission.head.repository &&
    left.admission.head.sha === right.admission.head.sha &&
    left.admission.merge_sha === right.admission.merge_sha &&
    left.admission.workflow_run_head_sha === right.admission.workflow_run_head_sha
  );
}

async function publishStatus({ github, snapshot, state, description, targetUrl }) {
  const [owner, repo] = EXPECTED_REPOSITORY.split("/");
  await github.rest.repos.createCommitStatus({
    owner,
    repo,
    sha: snapshot.admission.head.sha,
    state,
    context: STATUS_CONTEXT,
    description,
    target_url: targetUrl,
  });
}

async function admit({ github, context, admissionPath, targetUrl }) {
  const snapshot = await deriveSnapshot({ github, context });
  fs.writeFileSync(admissionPath, `${JSON.stringify(snapshot.admission)}\n`, {
    encoding: "utf8",
    mode: 0o600,
    flag: "wx",
  });
  await publishStatus({
    github,
    snapshot,
    state: "pending",
    description: "Trusted Docs Truth evaluation is in progress.",
    targetUrl,
  });
  return snapshot;
}

async function finalize({ github, context, expected, workerSucceeded, targetUrl }) {
  let validationError;
  try {
    const observed = await deriveSnapshot({ github, context });
    if (!sameSnapshot(expected, observed)) reject("pull request bindings changed during evaluation");
  } catch (error) {
    validationError = error;
  }

  const succeeded = workerSucceeded && validationError === undefined;
  await publishStatus({
    github,
    snapshot: expected,
    state: succeeded ? "success" : "failure",
    description: succeeded
      ? "Trusted Docs Truth passed for the exact pull request head."
      : "Trusted Docs Truth failed or the pull request changed.",
    targetUrl,
  });

  if (validationError) throw validationError;
  if (!workerSucceeded) throw new Error("trusted Docs Truth computation failed");
}

module.exports = {
  EXPECTED_REPOSITORY,
  EXPECTED_WORKFLOW_ID,
  EXPECTED_WORKFLOW_NAME,
  EXPECTED_WORKFLOW_PATH,
  STATUS_CONTEXT,
  admit,
  deriveSnapshot,
  finalize,
  sameSnapshot,
};
