#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: fat-kernel-verify-source.sh ARCHIVE SOURCE_LOCK.json" >&2
    exit 2
fi

archive=$1
source_lock=$2
test -f "$archive" || { echo "source archive not found: $archive" >&2; exit 1; }
test -f "$source_lock" || { echo "source lock not found: $source_lock" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "jq is required" >&2; exit 1; }

expected=$(jq -er '.archive_digest | select(startswith("sha256:")) | ltrimstr("sha256:")' "$source_lock")
if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$archive" | awk '{print $1}')
else
    actual=$(shasum -a 256 "$archive" | awk '{print $1}')
fi

if [ "$actual" != "$expected" ]; then
    echo "source archive SHA-256 mismatch: expected $expected, observed $actual" >&2
    exit 1
fi
printf 'verified source archive: sha256:%s\n' "$actual"
