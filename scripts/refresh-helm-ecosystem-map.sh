#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
workspace_root="${MINDBURN_WORKSPACE_ROOT:-$(cd "${repo_root}/.." && pwd)}"

# Regeneration uses manifest entries. The retired root inventory script is not
# a prerequisite; current ecp reports cannot substitute for its legacy files.
# --output scopes writes to an owned checkout; --legacy-snapshots is explicit.
ruby "${repo_root}/scripts/generate-helm-ecosystem-map.rb" --write "$@"
ruby "${repo_root}/scripts/generate-helm-ecosystem-map.rb" --check "$@"
