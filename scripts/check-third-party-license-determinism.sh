#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/fat-license-determinism.XXXXXX")"
trap 'rm -rf -- "$scratch"' EXIT

for root in source-a source-b; do
  mkdir -p "$scratch/$root"
  cat > "$scratch/$root/raw.json" <<JSON
{
  "licenses": [{"id":"MIT","name":"MIT License","text":"MIT text","source_path":"/$root/cache/LICENSE","used_by":[]}],
  "crates": [{"package":{"name":"example","version":"1.0.0","source":"registry+https://github.com/rust-lang/crates.io-index","license":"MIT","repository":"https://example.invalid/example","manifest_path":"/$root/cache/Cargo.toml","targets":[{"src_path":"/$root/cache/src/lib.rs"}]},"license":"MIT"}]
}
JSON
  python3 "$repo_root/scripts/sanitize-cargo-about.py" \
    "$scratch/$root/raw.json" "$scratch/$root/public.json"
done

cmp "$scratch/source-a/public.json" "$scratch/source-b/public.json"
if grep -Eq '/source-[ab]/|manifest_path|source_path|src_path' "$scratch/source-a/public.json"; then
  echo "sanitized license report leaks source paths" >&2
  exit 1
fi

printf 'verified deterministic host-independent third-party license schema\n'
