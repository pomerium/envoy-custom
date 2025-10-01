#!/usr/bin/env bash

set -euo pipefail

_dir="$(git rev-parse --show-toplevel)"

if [[ $# -gt 0 ]]; then
  _tag="$1"
else
  # Default to the first tag number from the envoy repo.
  _tag="$(curl -fsS https://api.github.com/repos/envoyproxy/envoy/tags | jq -r '.[0].name')"
  echo "using latest tag: $_tag"
fi

# Get the commit hash corresponding to the tag.
_commit="$(curl -fsS https://api.github.com/repos/envoyproxy/envoy/git/ref/tags/$_tag | jq -r .object.sha)"
echo "new commit hash: $_commit"

# Compute new SHA-256 hash of the envoy repo archive.
echo "downloading repo archive..."
_hash="$(curl -fL https://github.com/envoyproxy/envoy/archive/$_commit.zip | shasum -a 256 | cut -d' ' -f1)"

# Update envoy version in the WORKSPACE file.
sed "s/^envoy_version = .*/envoy_version = \"$_commit\"/" "$_dir/WORKSPACE" |
   sed "/name = \"envoy\"/,/sha256 = / { s/sha256 = .*/sha256 = \"$_hash\",/; }" > WORKSPACE.tmp
mv WORKSPACE.tmp "$_dir/WORKSPACE"

# Update envoy .bazelrc file.
curl -fsSL https://raw.githubusercontent.com/envoyproxy/envoy/$_commit/.bazelrc > "$_dir/envoy.bazelrc"

# Replay our local customizations to the upstream .bazelrc file
git apply "$_dir/patches/envoy.bazelrc.patch"
