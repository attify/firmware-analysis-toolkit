#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/fat-qemu-contract.XXXXXX")
tmp=$(CDPATH= cd -- "$tmp" && pwd)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}';
    else shasum -a 256 "$1" | awk '{print $1}'; fi
}

mkdir -p "$tmp/bundle"
printf kernel >"$tmp/bundle/vmlinux"
printf initrd >"$tmp/bundle/initramfs.cpio"
kernel_digest=$(sha256_file "$tmp/bundle/vmlinux")
initrd_digest=$(sha256_file "$tmp/bundle/initramfs.cpio")
cat >"$tmp/bundle/manifest.json" <<EOF
{"id":"kab-test","class":"mips32-o32-le-r1-page4k","kernel_image":{"path":"vmlinux","digest":"sha256:$kernel_digest"},"declared_files":[{"path":"initramfs.cpio","digest":"sha256:$initrd_digest","role":"fixture-initramfs"}]}
EOF

cat >"$tmp/fake-qemu-success" <<'EOF'
#!/bin/sh
if [ "${1:-}" = "--version" ]; then echo 'QEMU emulator version 10.2.2'; exit 0; fi
echo 'Linux version 6.18.45-fat'
echo 'FAT-FIXTURE:USERSPACE_REACHED class=mips32-o32-le-r1-page4k pid=1'
trap 'exit 0' TERM INT
while :; do sleep 1; done
EOF
cat >"$tmp/fake-qemu-timeout" <<'EOF'
#!/bin/sh
if [ "${1:-}" = "--version" ]; then echo 'QEMU emulator version 10.2.2'; exit 0; fi
echo 'Linux version 6.18.45-fat'
trap 'exit 0' TERM INT
while :; do sleep 1; done
EOF
chmod +x "$tmp/fake-qemu-success" "$tmp/fake-qemu-timeout"
cat >"$tmp/machine.json" <<'EOF'
{"schema_version":"1.0","id":"mch-test","qemu_version":"10.2.2","machine":"malta","cpu":"4Kc","console":"ttyS0","classes":["mips32-o32-le-r1-page4k"],"capability_tier":"fixture-validated"}
EOF

"$repo_root/kernel/fixtures/run-qemu-fixture.sh" \
    --bundle "$tmp/bundle" --qemu "$tmp/fake-qemu-success" \
    --machine-profile "$tmp/machine.json" --timeout 3 \
    --result "$tmp/success.json"
jq -e '.observed_outcome == "userspace-reached" and .cleanup_passed == true' "$tmp/success.json" >/dev/null
success_pid=$(jq -r '.process_id' "$tmp/success.json")
if kill -0 "$success_pid" 2>/dev/null; then
    echo "successful fixture leaked process $success_pid" >&2
    exit 1
fi

"$repo_root/kernel/fixtures/run-qemu-fixture.sh" \
    --bundle "$tmp/bundle" --qemu "$tmp/fake-qemu-timeout" \
    --machine-profile "$tmp/machine.json" --timeout 1 \
    --result "$tmp/timeout.json"
jq -e '.observed_outcome == "kernel-booted" and .cleanup_passed == true' "$tmp/timeout.json" >/dev/null
timeout_pid=$(jq -r '.process_id' "$tmp/timeout.json")
if kill -0 "$timeout_pid" 2>/dev/null; then
    echo "timed-out fixture leaked process $timeout_pid" >&2
    exit 1
fi

echo "qemu fixture contract: passed"
