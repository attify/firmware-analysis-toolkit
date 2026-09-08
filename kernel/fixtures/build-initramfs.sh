#!/bin/sh
set -eu

recipe=${1:?recipe JSON required}
destination=${2:?destination required}
class=$(jq -er '.class' "$recipe")
cross_compile=$(jq -er '.cross_compile' "$recipe")
root="$destination/root"
rm -rf "$root"
mkdir -p "$root"

extra_flags=
case "$class" in
    mips32-o32-le-r1-page4k) extra_flags='-march=mips32 -mabi=32 -EL -mno-abicalls -G 0' ;;
    mips32-o32-be-r1-page4k) extra_flags='-march=mips32 -mabi=32 -EB -mno-abicalls -G 0' ;;
    arm32-eabi-le-v7-page4k) extra_flags='-march=armv7-a -marm -mfloat-abi=soft' ;;
    *) echo "unsupported fixture class: $class" >&2; exit 1 ;;
esac

# shellcheck disable=SC2086
"${cross_compile}gcc" -Os -static -nostdlib -ffreestanding -fno-builtin \
    -fno-stack-protector -fno-pic -Wl,-e,_start $extra_flags \
    -DFAT_KERNEL_CLASS=\"$class\" /opt/fat/init.c -o "$root/init"
cat >"$destination/initramfs.list" <<EOF
dir /dev 0755 0 0
nod /dev/console 0600 0 0 c 5 1
dir /proc 0555 0 0
dir /sys 0555 0 0
file /init $root/init 0755 0 0
EOF
