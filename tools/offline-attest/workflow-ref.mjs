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
// "/"), so the first "@" after the marker is ambiguous too. The only
// unambiguous anchor is the "@refs/" boundary: GITHUB_WORKFLOW_REF always
// carries a fully-qualified ref ("refs/heads/...", "refs/tags/...",
// "refs/pull/..."), and "@refs/" cannot occur inside a slash-free filename.
// The separator is therefore the first "@refs/" after the marker.
export const WORKFLOW_REF_MARKER = "/.github/workflows/";

/**
 * Parses a GITHUB_WORKFLOW_REF value into its repository, workflow path,
 * and ref components.
 *
 * @param {string} workflowRef
 * @returns {{ repository: string, path: string, ref: string } | null}
 *   `null` when `workflowRef` does not identify a GitHub Actions workflow
 *   (no `/.github/workflows/` marker, or no "@refs/" ref boundary after
 *   the marker).
 */
export function parseWorkflowRef(workflowRef) {
  const markerIndex = workflowRef.indexOf(WORKFLOW_REF_MARKER);
  const separatorIndex =
    markerIndex === -1
      ? -1
      : workflowRef.indexOf("@refs/", markerIndex + WORKFLOW_REF_MARKER.length);
  if (markerIndex <= 0 || separatorIndex === -1) {
    return null;
  }
  return {
    repository: workflowRef.slice(0, markerIndex),
    path: workflowRef.slice(markerIndex + 1, separatorIndex),
    ref: workflowRef.slice(separatorIndex + 1),
  };
}
