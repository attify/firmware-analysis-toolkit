#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/fat-kernel-contract.XXXXXX")
tmp=$(CDPATH= cd -- "$tmp" && pwd)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

mkdir -p "$tmp/profiles/recipes" "$tmp/profiles/source-locks" "$tmp/profiles/builders" "$tmp/output"
printf 'pinned source archive\n' >"$tmp/linux.tar.xz"
archive_digest=$(sha256_file "$tmp/linux.tar.xz")
cat >"$tmp/profiles/source-locks/source.json" <<EOF
{"archive_digest":"sha256:$archive_digest"}
EOF
cat >"$tmp/profiles/builders/builder.json" <<'EOF'
{"image":"example.invalid/fat-builder@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
EOF
cat >"$tmp/profiles/recipes/recipe.json" <<'EOF'
{"source_lock_id":"source","builder_id":"builder"}
EOF

cat >"$tmp/fake-engine" <<'EOF'
#!/bin/sh
printf '%s\n' "$@" >"$FAT_FAKE_ENGINE_LOG"
EOF
chmod +x "$tmp/fake-engine"

FAT_FAKE_ENGINE_LOG="$tmp/engine.log" \
    "$repo_root/scripts/fat-kernel-build.sh" \
    --engine "$tmp/fake-engine" \
    --source "$tmp/linux.tar.xz" \
    --source-lock "$tmp/profiles/source-locks/source.json" \
    --builder "$tmp/profiles/builders/builder.json" \
    --recipe "$tmp/profiles/recipes/recipe.json" \
    --profiles "$tmp/profiles" \
    --output "$tmp/output" \
    --contract-only

grep -Fx -- '--network' "$tmp/engine.log" >/dev/null
grep -Fx -- 'none' "$tmp/engine.log" >/dev/null
grep -Fx -- '--read-only' "$tmp/engine.log" >/dev/null
grep -F -- "$tmp/linux.tar.xz:/input/linux.tar.xz:ro" "$tmp/engine.log" >/dev/null
grep -F -- "$tmp/profiles:/profiles:ro" "$tmp/engine.log" >/dev/null
grep -F -- "$tmp/output:/output:rw" "$tmp/engine.log" >/dev/null
grep -Fx -- 'example.invalid/fat-builder@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' "$tmp/engine.log" >/dev/null

printf '{"archive_digest":"sha256:%064d"}\n' 0 >"$tmp/profiles/source-locks/source.json"
: >"$tmp/engine.log"
if FAT_FAKE_ENGINE_LOG="$tmp/engine.log" \
    "$repo_root/scripts/fat-kernel-build.sh" \
    --engine "$tmp/fake-engine" \
    --source "$tmp/linux.tar.xz" \
    --source-lock "$tmp/profiles/source-locks/source.json" \
    --builder "$tmp/profiles/builders/builder.json" \
    --recipe "$tmp/profiles/recipes/recipe.json" \
    --profiles "$tmp/profiles" \
    --output "$tmp/output" \
    --contract-only >/dev/null 2>&1; then
    echo "source digest mismatch unexpectedly succeeded" >&2
    exit 1
fi
test ! -s "$tmp/engine.log"

for machine in "$repo_root"/profiles/kernels/machines/*.json; do
    jq -e '
      .schema_version == "1.0" and
      (.id | startswith("mch-")) and
      (.qemu_version | length > 0) and
      (.machine | length > 0) and
      (.cpu | length > 0) and
      (.classes | length > 0) and
      .capability_tier == "fixture-validated"
    ' "$machine" >/dev/null
done

echo "kernel recipe contract: passed"
