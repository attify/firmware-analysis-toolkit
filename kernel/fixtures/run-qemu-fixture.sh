#!/bin/sh
set -eu

usage() {
    echo "usage: run-qemu-fixture.sh --bundle DIR --qemu PATH --machine-profile JSON --timeout SECONDS --result JSON [--predicted OUTCOME]" >&2
    exit 2
}

bundle= qemu= machine_profile_file= timeout= result=
predicted=userspace-reached
while [ "$#" -gt 0 ]; do
    case "$1" in
        --bundle) bundle=$2; shift 2 ;;
        --qemu) qemu=$2; shift 2 ;;
        --machine-profile) machine_profile_file=$2; shift 2 ;;
        --timeout) timeout=$2; shift 2 ;;
        --result) result=$2; shift 2 ;;
        --predicted) predicted=$2; shift 2 ;;
        *) usage ;;
    esac
done
[ -n "$bundle" ] && [ -n "$qemu" ] && [ -n "$machine_profile_file" ] && \
    [ -n "$timeout" ] && \
    [ -n "$result" ] || usage

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print "sha256:"$1}';
    else shasum -a 256 "$1" | awk '{print "sha256:"$1}'; fi
}

manifest="$bundle/manifest.json"
bundle_id=$(jq -er '.id' "$manifest")
class=$(jq -er '.class' "$manifest")
machine_profile=$(jq -er '.id' "$machine_profile_file")
machine=$(jq -er '.machine' "$machine_profile_file")
cpu=$(jq -er '.cpu' "$machine_profile_file")
expected_qemu_version=$(jq -er '.qemu_version' "$machine_profile_file")
jq -e --arg class "$class" '.classes | index($class) != null' \
    "$machine_profile_file" >/dev/null || {
    echo "machine profile $machine_profile does not declare class $class" >&2
    exit 1
}
qemu_version_line=$("$qemu" --version | head -1)
case "$qemu_version_line" in
    *"$expected_qemu_version"*) ;;
    *) echo "QEMU version does not match machine profile: $qemu_version_line" >&2; exit 1 ;;
esac
kernel_relative=$(jq -er '.kernel_image.path' "$manifest")
expected_kernel=$(jq -er '.kernel_image.digest' "$manifest")
kernel="$bundle/$kernel_relative"
actual_kernel=$(sha256_file "$kernel")
[ "$actual_kernel" = "$expected_kernel" ] || {
    echo "kernel digest mismatch before QEMU launch" >&2
    exit 1
}
initrd_relative=$(jq -er '.declared_files[] | select(.role == "fixture-initramfs") | .path' "$manifest")
expected_initrd=$(jq -er '.declared_files[] | select(.role == "fixture-initramfs") | .digest' "$manifest")
initrd="$bundle/$initrd_relative"
actual_initrd=$(sha256_file "$initrd")
[ "$actual_initrd" = "$expected_initrd" ] || {
    echo "fixture initramfs digest mismatch before QEMU launch" >&2
    exit 1
}
qemu_digest=$(sha256_file "$qemu")
serial_log="${result%.json}.serial.log"
mkdir -p "$(dirname -- "$result")"
: >"$serial_log"

case "$class" in
    mips32-o32-le-r1-page4k|mips32-o32-be-r1-page4k)
        console=ttyS0
        ;;
    arm32-eabi-le-v7-page4k)
        console=ttyAMA0
        ;;
    *) echo "unsupported fixture class: $class" >&2; exit 1 ;;
esac

if command -v setsid >/dev/null 2>&1; then
    setsid "$qemu" -M "$machine" -cpu "$cpu" -m 256 -kernel "$kernel" \
        -initrd "$initrd" -nographic -no-reboot \
        -append "console=$console,115200 rdinit=/init" \
        >"$serial_log" 2>&1 &
else
    # POSIX::setsid keeps the same process-group ownership contract on macOS.
    perl -MPOSIX=setsid -e 'setsid(); exec @ARGV or die $!' -- \
        "$qemu" -M "$machine" -cpu "$cpu" -m 256 -kernel "$kernel" \
        -initrd "$initrd" -nographic -no-reboot \
        -append "console=$console,115200 rdinit=/init" \
        >"$serial_log" 2>&1 &
fi
pid=$!

ticks=$((timeout * 10))
observed=boot-failed
while [ "$ticks" -gt 0 ]; do
    if grep -F 'FAT-FIXTURE:USERSPACE_REACHED' "$serial_log" >/dev/null 2>&1; then
        observed=userspace-reached
        break
    fi
    if ! kill -0 "$pid" 2>/dev/null; then
        break
    fi
    sleep 0.1
    ticks=$((ticks - 1))
done
if [ "$observed" != userspace-reached ] && grep -F 'Linux version' "$serial_log" >/dev/null 2>&1; then
    observed=kernel-booted
fi

kill -TERM -"$pid" 2>/dev/null || true
cleanup_ticks=30
while kill -0 "$pid" 2>/dev/null && [ "$cleanup_ticks" -gt 0 ]; do
    sleep 0.1
    cleanup_ticks=$((cleanup_ticks - 1))
done
if kill -0 "$pid" 2>/dev/null; then
    kill -KILL -"$pid" 2>/dev/null || true
fi
wait "$pid" 2>/dev/null || true
if kill -0 "$pid" 2>/dev/null; then cleanup=false; else cleanup=true; fi
serial_digest=$(sha256_file "$serial_log")

jq -n \
    --arg bundle_id "$bundle_id" --arg kernel_digest "$actual_kernel" \
    --arg machine_profile_id "$machine_profile" --arg qemu_digest "$qemu_digest" \
    --arg cpu "$cpu" --arg predicted "$predicted" --arg observed "$observed" \
    --arg serial_digest "$serial_digest" --argjson process_id "$pid" \
    --argjson cleanup "$cleanup" \
    '{schema_version:"1.0",id:"",bundle_id:$bundle_id,kernel_digest:$kernel_digest,
      machine_profile_id:$machine_profile_id,qemu_binary_digest:$qemu_digest,cpu:$cpu,
      process_id:$process_id,predicted_outcome:$predicted,observed_outcome:$observed,
      serial_log_digest:$serial_digest,cleanup_passed:$cleanup}' >"$result.tmp"
record_hash=$(jq -cS 'del(.id)' "$result.tmp" | tr -d '\n' | {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum; else shasum -a 256; fi
} | awk '{print substr($1,1,16)}')
jq --arg id "kfr-$record_hash" '.id=$id' "$result.tmp" >"$result"
rm "$result.tmp"

echo "fixture $class/$cpu: $observed cleanup=$cleanup"
