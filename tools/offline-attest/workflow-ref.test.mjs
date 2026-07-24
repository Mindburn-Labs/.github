import assert from "node:assert/strict";
import { test } from "node:test";

import { parseWorkflowRef } from "./workflow-ref.mjs";

test("parses a normal branch ref", () => {
  const result = parseWorkflowRef(
    "Mindburn-Labs/.github/.github/workflows/ci.yml@refs/heads/main",
  );
  assert.deepEqual(result, {
    repository: "Mindburn-Labs/.github",
    path: ".github/workflows/ci.yml",
    ref: "refs/heads/main",
  });
});

test("parses a tag ref", () => {
  const result = parseWorkflowRef(
    "Mindburn-Labs/.github/.github/workflows/ci.yml@refs/tags/v1.2.3",
  );
  assert.deepEqual(result, {
    repository: "Mindburn-Labs/.github",
    path: ".github/workflows/ci.yml",
    ref: "refs/tags/v1.2.3",
  });
});

test("anchors on the /.github/workflows/ marker, not the last @, when the ref itself contains @", () => {
  // Regression for ATTEST_WORKFLOW_REF_AT_PARSE: a branch such as
  // `release@2026` must not truncate the workflow path or get silently
  // dropped from the parsed ref.
  const result = parseWorkflowRef(
    "Mindburn-Labs/.github/.github/workflows/ci.yml@refs/heads/release@2026",
  );
  assert.deepEqual(result, {
    repository: "Mindburn-Labs/.github",
    path: ".github/workflows/ci.yml",
    ref: "refs/heads/release@2026",
  });
});

test("returns null when the /.github/workflows/ marker is absent", () => {
  assert.equal(parseWorkflowRef("not-a-workflow-ref"), null);
});

test("returns null when there is no @ after the marker", () => {
  assert.equal(
    parseWorkflowRef("Mindburn-Labs/.github/.github/workflows/ci.yml"),
    null,
  );
});

test("returns null when the marker starts at position 0 (no repository segment)", () => {
  assert.equal(
    parseWorkflowRef("/.github/workflows/ci.yml@refs/heads/main"),
    null,
  );
});

test("parses a workflow filename containing @", () => {
  const result = parseWorkflowRef(
    "Mindburn-Labs/.github/.github/workflows/ci@nightly.yml@refs/heads/main",
  );
  assert.deepEqual(result, {
    repository: "Mindburn-Labs/.github",
    path: ".github/workflows/ci@nightly.yml",
    ref: "refs/heads/main",
  });
});

test("parses @ in both the filename and the branch name", () => {
  const result = parseWorkflowRef(
    "Mindburn-Labs/.github/.github/workflows/ci@nightly.yml@refs/heads/release@2026",
  );
  assert.deepEqual(result, {
    repository: "Mindburn-Labs/.github",
    path: ".github/workflows/ci@nightly.yml",
    ref: "refs/heads/release@2026",
  });
});

test("rejects a ref without the fully-qualified refs/ prefix", () => {
  assert.equal(
    parseWorkflowRef(
      "Mindburn-Labs/.github/.github/workflows/ci.yml@main",
    ),
    null,
  );
});
