#!/usr/bin/env bash
# Bump version, commit and tag: scripts/release.sh 0.2.0 && git push --follow-tags
set -euo pipefail
v=${1:?usage: release.sh <version>}
cd "$(dirname "$0")/.."
[ -z "$(git status --porcelain)" ] || { echo "working tree not clean" >&2; exit 1; }
npm pkg set version="$v"
sed -i '' "s/^version = \".*\"/version = \"$v\"/" src-tauri/Cargo.toml
cargo update --manifest-path src-tauri/Cargo.toml -p infra-tracker --offline >/dev/null
git commit -am "Release v$v"
git tag -a "v$v" -m "v$v"
