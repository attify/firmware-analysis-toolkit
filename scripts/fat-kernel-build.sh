#!/bin/sh
set -eu

usage() {
    echo "usage: fat-kernel-build.sh --engine ENGINE --source ARCHIVE --source-lock JSON --builder JSON --recipe JSON --profiles DIR --output DIR [--contract-only]" >&2
    exit 2
}

engine=podman
source_archive=
source_lock=
builder=
recipe=
profiles=
output=
contract_only=false
while [ "$#" -gt 0 ]; do
    case "$1" in
        --engine) engine=$2; shift 2 ;;
        --source) source_archive=$2; shift 2 ;;
        --source-lock) source_lock=$2; shift 2 ;;
        --builder) builder=$2; shift 2 ;;
        --recipe) recipe=$2; shift 2 ;;
        --profiles) profiles=$2; shift 2 ;;
        --output) output=$2; shift 2 ;;
        --contract-only) contract_only=true; shift ;;
        *) usage ;;
    esac
done

[ -n "$source_archive" ] && [ -n "$source_lock" ] && [ -n "$builder" ] && \
    [ -n "$recipe" ] && [ -n "$profiles" ] && [ -n "$output" ] || usage

absolute_file() {
    directory=$(CDPATH= cd -- "$(dirname -- "$1")" && pwd)
    printf '%s/%s\n' "$directory" "$(basename -- "$1")"
}
absolute_dir() {
    (CDPATH= cd -- "$1" && pwd)
}

source_archive=$(absolute_file "$source_archive")
source_lock=$(absolute_file "$source_lock")
builder=$(absolute_file "$builder")
recipe=$(absolute_file "$recipe")
profiles=$(absolute_dir "$profiles")
mkdir -p "$output"
output=$(absolute_dir "$output")

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
"$script_dir/fat-kernel-verify-source.sh" "$source_archive" "$source_lock" >/dev/null
builder_image=$(jq -er '.image | select(test("@sha256:[0-9a-f]{64}$"))' "$builder")

"$engine" run --rm \
    --pull never \
    --network none \
    --read-only \
    --cap-drop all \
    --security-opt no-new-privileges \
    --tmpfs /tmp:rw,nosuid,nodev,exec,size=16g \
    --env SOURCE_DATE_EPOCH=1767225600 \
    --env KBUILD_BUILD_TIMESTAMP="2026-01-01 00:00:00 UTC" \
    --env KBUILD_BUILD_USER=fat \
    --env KBUILD_BUILD_HOST=builder \
    --env KBUILD_BUILD_VERSION=1 \
    -v "$source_archive:/input/linux.tar.xz:ro,z" \
    -v "$source_lock:/input/source-lock.json:ro,z" \
    -v "$builder:/input/builder.json:ro,z" \
    -v "$recipe:/input/recipe.json:ro,z" \
    -v "$profiles:/profiles:ro,z" \
    -v "$output:/output:rw,Z" \
    "$builder_image" \
    /opt/fat/build-kernel.sh

if [ "$contract_only" = true ]; then
    exit 0
fi
test -f "$output/manifest.json" || { echo "builder did not emit manifest.json" >&2; exit 1; }
