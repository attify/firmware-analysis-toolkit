#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output="${1:-$repo_root/target/release-metadata/third-party-licenses.json}"
required_version="cargo-about 0.8.2"

actual_version="$(cargo about --version 2>/dev/null || true)"
if [[ "$actual_version" != "$required_version" ]]; then
  echo "cargo-about 0.8.2 is required; install it with: cargo install cargo-about --version 0.8.2 --locked" >&2
  exit 1
fi

mkdir -p "$(dirname "$output")"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/fat-cargo-about.XXXXXX")"
raw="$scratch/raw.json"
trap 'rm -rf -- "$scratch"' EXIT
cargo about generate \
  --config "$repo_root/about.toml" \
  --manifest-path "$repo_root/Cargo.toml" \
  --workspace \
  --all-features \
  --locked \
  --fail \
  --format json \
  --output-file "$raw"
python3 "$repo_root/scripts/sanitize-cargo-about.py" "$raw" "$output"
test -s "$output"
if grep -Eq '"(manifest_path|source_path)"|/Users/|/home/|[A-Za-z]:\\\\' "$output"; then
  echo "generated dependency license report contains a host-specific absolute path" >&2
  exit 1
fi
printf 'generated dependency license report: %s\n' "$output"
