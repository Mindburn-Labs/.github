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
// Anchor on the `/.github/workflows/` marker instead: the separator is the
// first "@" that appears *after* that marker.
export const WORKFLOW_REF_MARKER = "/.github/workflows/";

/**
 * Parses a GITHUB_WORKFLOW_REF value into its repository, workflow path,
 * and ref components.
 *
 * @param {string} workflowRef
 * @returns {{ repository: string, path: string, ref: string } | null}
 *   `null` when `workflowRef` does not identify a GitHub Actions workflow
 *   (no `/.github/workflows/` marker, or no "@" after the marker).
 */
export function parseWorkflowRef(workflowRef) {
  const markerIndex = workflowRef.indexOf(WORKFLOW_REF_MARKER);
  const separatorIndex =
    markerIndex === -1
      ? -1
      : workflowRef.indexOf("@", markerIndex + WORKFLOW_REF_MARKER.length);
  if (markerIndex <= 0 || separatorIndex === -1) {
    return null;
  }
  return {
    repository: workflowRef.slice(0, markerIndex),
    path: workflowRef.slice(markerIndex + 1, separatorIndex),
    ref: workflowRef.slice(separatorIndex + 1),
  };
}
