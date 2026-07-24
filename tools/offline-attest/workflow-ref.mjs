// GitHub sets GITHUB_WORKFLOW_REF to
//   <owner>/<repo>/.github/workflows/<name>.yml@<ref>
// where <ref> is itself a ref path such as `refs/heads/<branch>` or
// `refs/tags/<tag>`. Branch and tag names may legally contain "@" (e.g. a
// release train named `release@2026`), so the split between the workflow
// path and the ref must not be found by scanning for the *last* "@" in the
// whole string — that finds an "@" inside the ref instead of the "@" that
// actually separates the workflow path from the ref, silently truncating
// the workflow path and corrupting provenance metadata.
//
// Workflow *filenames* may also legally contain "@" (they cannot contain
// "/"), so neither the first nor the last "@" is a safe separator by
// itself. The workflow identity after the separator has exactly two legal
// shapes: a fully-qualified ref ("refs/heads/...", "refs/tags/...",
// "refs/pull/...") or an immutable 40-hex commit SHA (reusable workflows
// and this estate's own ruleset-pinned permit invocations). A slash-free
// filename can produce neither shape as the full remainder of the string,
// so the separator is the first "@" after the marker whose remainder
// matches one of them.
export const WORKFLOW_REF_MARKER = "/.github/workflows/";

const REF_SUFFIX = /^refs\/.+$/;
const SHA_SUFFIX = /^[0-9a-f]{40}$/;

/**
 * Parses a GITHUB_WORKFLOW_REF value into its repository, workflow path,
 * and ref components.
 *
 * @param {string} workflowRef
 * @returns {{ repository: string, path: string, ref: string } | null}
 *   `null` when `workflowRef` does not identify a GitHub Actions workflow
 *   (no `/.github/workflows/` marker, empty workflow filename, or no "@"
 *   after the marker followed by a fully-qualified ref or 40-hex SHA).
 */
export function parseWorkflowRef(workflowRef) {
  const markerIndex = workflowRef.indexOf(WORKFLOW_REF_MARKER);
  if (markerIndex <= 0) {
    return null;
  }
  const filenameStart = markerIndex + WORKFLOW_REF_MARKER.length;
  let separatorIndex = workflowRef.indexOf("@", filenameStart);
  while (separatorIndex !== -1) {
    const remainder = workflowRef.slice(separatorIndex + 1);
    if (REF_SUFFIX.test(remainder) || SHA_SUFFIX.test(remainder)) {
      break;
    }
    separatorIndex = workflowRef.indexOf("@", separatorIndex + 1);
  }
  if (separatorIndex === -1 || separatorIndex === filenameStart) {
    return null;
  }
  return {
    repository: workflowRef.slice(0, markerIndex),
    path: workflowRef.slice(markerIndex + 1, separatorIndex),
    ref: workflowRef.slice(separatorIndex + 1),
  };
}
