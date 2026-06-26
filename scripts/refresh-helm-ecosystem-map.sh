#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
workspace_root="${MINDBURN_WORKSPACE_ROOT:-$(cd "${repo_root}/.." && pwd)}"

ruby "${workspace_root}/scripts/estate-control-plane.rb"
ruby "${repo_root}/scripts/generate-helm-ecosystem-map.rb" --write
ruby "${repo_root}/scripts/generate-helm-ecosystem-map.rb" --check
