#!/usr/bin/env bash
# Publish the FAT workspace crates to crates.io in dependency order.
#
# crates.io throttles new crate names (a burst of five, then one name per ten
# minutes) but allows version updates at a burst of thirty, so only the first
# publish needs long waits. The script is resumable: it skips versions already
# visible in the sparse index and waits for each crate to appear there before
# publishing a dependent.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

dry_run=false
for argument in "$@"; do
    case "$argument" in
        --dry-run) dry_run=true ;;
        *)
            printf 'usage: %s [--dry-run]\n' "$0" >&2
            exit 2
            ;;
    esac
done

version="$(awk -F'"' '/^version = "/ { print $2; exit }' Cargo.toml)"
index_base="${FAT_CRATES_INDEX:-https://index.crates.io}"
new_name_burst=5
throttle_pause=600
index_attempts=60
index_interval=5

# Dependency order: leaves first, the CLI last.
crates=(
    fat-toolkit-core
    fat-toolkit-family
    fat-toolkit-package
    fat-toolkit-extract
    fat-toolkit-plugin-api
    fat-toolkit-backend
    fat-toolkit-bootloader
    fat-toolkit-query
    fat-toolkit-emulate
    fat-toolkit-analyze
    fat-toolkit-taint
    fat-toolkit-plugin-host
    firmware-analysis-toolkit
)

index_path() {
    local name="$1"
    if ((${#name} == 1)); then
        printf '1/%s' "$name"
    elif ((${#name} == 2)); then
        printf '2/%s' "$name"
    elif ((${#name} == 3)); then
        printf '3/%s/%s' "${name:0:1}" "$name"
    else
        printf '%s/%s/%s' "${name:0:2}" "${name:2:2}" "$name"
    fi
}

index_body() {
    curl -fsS --max-time 30 "$index_base/$(index_path "$1")" 2>/dev/null || true
}

indexed() {
    index_body "$1" | grep -q "\"vers\":\"$version\""
}

crate_exists() {
    [[ -n "$(index_body "$1")" ]]
}

wait_for_index() {
    local name="$1" attempt
    for ((attempt = 1; attempt <= index_attempts; attempt++)); do
        if indexed "$name"; then
            return 0
        fi
        sleep "$index_interval"
    done
    printf 'error: %s %s did not appear in the index\n' "$name" "$version" >&2
    return 1
}

publish() {
    local name="$1" attempt
    for attempt in 1 2 3; do
        if cargo publish --locked -p "$name"; then
            return 0
        fi
        printf 'retrying %s after a throttled or transient failure ...\n' "$name" >&2
        sleep "$throttle_pause"
    done
    return 1
}

new_names=0
for name in "${crates[@]}"; do
    if indexed "$name"; then
        printf '%s %s is already published\n' "$name" "$version"
        continue
    fi
    if crate_exists "$name"; then
        printf 'publishing update %s %s\n' "$name" "$version"
    else
        new_names=$((new_names + 1))
        if ((new_names > new_name_burst)) && [[ "$dry_run" == false ]]; then
            printf 'waiting for the crates.io new-crate limit before %s ...\n' "$name"
            sleep "$throttle_pause"
        fi
        printf 'publishing new crate %s %s\n' "$name" "$version"
    fi
    if [[ "$dry_run" == true ]]; then
        printf 'dry run: skipping upload\n'
        continue
    fi
    publish "$name"
    wait_for_index "$name"
done

printf 'workspace %s is published\n' "$version"
