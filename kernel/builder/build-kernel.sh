#!/bin/bash
set -euo pipefail

archive=/input/linux.tar.xz
source_lock=/input/source-lock.json
builder=/input/builder.json
recipe=/input/recipe.json
profiles=/profiles
output=/output

expected=$(jq -er '.archive_digest | ltrimstr("sha256:")' "$source_lock")
actual=$(sha256sum "$archive" | awk '{print $1}')
[[ "$actual" == "$expected" ]] || { echo "source digest mismatch" >&2; exit 1; }

rm -rf /tmp/fat-kernel-source /tmp/fat-kernel-build /tmp/fat-initramfs
mkdir -p /tmp/fat-kernel-source /tmp/fat-kernel-build /tmp/fat-initramfs
tar -xJf "$archive" -C /tmp/fat-kernel-source --strip-components=1

class=$(jq -er '.class' "$recipe")
cross_compile=$(jq -er '.cross_compile' "$recipe")
base_defconfig=$(jq -er '.base_defconfig' "$recipe")
output_image=$(jq -er '.output_image' "$recipe")
build_target=$(basename "$output_image")
case "$class" in
    mips32-*) arch=mips ;;
    arm32-*) arch=arm ;;
    *) echo "unsupported kernel class: $class" >&2; exit 1 ;;
esac

/opt/fat/build-initramfs.sh "$recipe" /tmp/fat-initramfs

build_log=/tmp/fat-kernel-build.log
exec > >(tee "$build_log") 2>&1
echo "FAT kernel build class=$class source=sha256:$actual"
"${cross_compile}gcc" --version | head -1
make -C /tmp/fat-kernel-source O=/tmp/fat-kernel-build \
    ARCH="$arch" CROSS_COMPILE="$cross_compile" "$base_defconfig"

fragments=()
while IFS= read -r fragment; do
    fragments+=("$profiles/$fragment")
done < <(jq -er '.ordered_fragments[]' "$recipe")
cd /tmp
/tmp/fat-kernel-source/scripts/kconfig/merge_config.sh -m -O /tmp/fat-kernel-build \
    /tmp/fat-kernel-build/.config "${fragments[@]}"
/tmp/fat-kernel-source/scripts/config --file /tmp/fat-kernel-build/.config \
    --enable BLK_DEV_INITRD \
    --set-str INITRAMFS_SOURCE "" \
    --enable INITRAMFS_COMPRESSION_NONE
make -C /tmp/fat-kernel-source O=/tmp/fat-kernel-build \
    ARCH="$arch" CROSS_COMPILE="$cross_compile" olddefconfig
make -C /tmp/fat-kernel-source O=/tmp/fat-kernel-build \
    ARCH="$arch" CROSS_COMPILE="$cross_compile" -j"$(nproc)" "$build_target"
test -x /tmp/fat-kernel-build/usr/gen_init_cpio || {
    echo "kernel build did not produce usr/gen_init_cpio" >&2
    exit 1
}
/tmp/fat-kernel-build/usr/gen_init_cpio -t "$SOURCE_DATE_EPOCH" \
    /tmp/fat-initramfs/initramfs.list \
    > /tmp/fat-initramfs/initramfs.cpio

rm -rf "$output"/*
cp "/tmp/fat-kernel-build/$output_image" "$output/$(basename "$output_image")"
cp /tmp/fat-kernel-build/.config "$output/config.final"
cp "$build_log" "$output/build.log"
cp /tmp/fat-initramfs/initramfs.cpio "$output/initramfs.cpio"
cp /tmp/fat-initramfs/initramfs.list "$output/initramfs.list"
cp /tmp/fat-initramfs/root/init "$output/fixture-init"
cp "$recipe" "$output/recipe.json"
cp "$source_lock" "$output/source-lock.json"
cp "$builder" "$output/builder.json"
"${cross_compile}gcc" --version >"$output/compiler-version.txt"

sha() { sha256sum "$1" | awk '{print "sha256:"$1}'; }
kernel_name=$(basename "$output_image")
recipe_id=$(jq -er '.id' "$recipe")
source_lock_id=$(jq -er '.source_lock_id' "$recipe")
builder_id=$(jq -er '.builder_id' "$recipe")
source_url=$(jq -er '.archive_url' "$source_lock")

jq -n \
    --arg recipe_id "$recipe_id" \
    --arg class "$class" \
    --arg source_lock_id "$source_lock_id" \
    --arg builder_id "$builder_id" \
    --arg kernel_path "$kernel_name" --arg kernel_digest "$(sha "$output/$kernel_name")" \
    --arg config_digest "$(sha "$output/config.final")" \
    --arg log_digest "$(sha "$output/build.log")" \
    --arg initramfs_cpio_digest "$(sha "$output/initramfs.cpio")" \
    --arg initramfs_digest "$(sha "$output/initramfs.list")" \
    --arg fixture_init_digest "$(sha "$output/fixture-init")" \
    --arg recipe_digest "$(sha "$output/recipe.json")" \
    --arg source_lock_digest "$(sha "$output/source-lock.json")" \
    --arg builder_digest "$(sha "$output/builder.json")" \
    --arg compiler_digest "$(sha "$output/compiler-version.txt")" \
    --arg source_url "$source_url" \
    '{
      schema_version:"1.0", id:"", recipe_id:$recipe_id, class:$class,
      support_tier:"experimental", source_lock_id:$source_lock_id, builder_id:$builder_id,
      kernel_image:{path:$kernel_path,digest:$kernel_digest,role:"kernel-image"},
      final_config:{path:"config.final",digest:$config_digest,role:"kernel-config"},
      build_log:{path:"build.log",digest:$log_digest,role:"build-log"},
      declared_files:[
        {path:"initramfs.cpio",digest:$initramfs_cpio_digest,role:"fixture-initramfs"},
        {path:"initramfs.list",digest:$initramfs_digest,role:"fixture-initramfs-spec"},
        {path:"fixture-init",digest:$fixture_init_digest,role:"fixture-init-binary"},
        {path:"recipe.json",digest:$recipe_digest,role:"build-recipe"},
        {path:"source-lock.json",digest:$source_lock_digest,role:"source-provenance"},
        {path:"builder.json",digest:$builder_digest,role:"builder-provenance"},
        {path:"compiler-version.txt",digest:$compiler_digest,role:"toolchain-identity"}
      ],
      attribution:[
        {project:"Linux",source_url:$source_url,license:"GPL-2.0-only",role:"kernel-source",redistributed:true},
        {project:"Debian",source_url:"https://www.debian.org/",license:"aggregate-distribution",role:"builder",redistributed:false}
      ],
      recipe_reproducible:true, bit_reproducible:false
    }' >"$output/manifest.tmp.json"
bundle_hash=$(jq -cS 'del(.id)' "$output/manifest.tmp.json" | tr -d '\n' | sha256sum | cut -c1-16)
jq --arg id "kab-$bundle_hash" '.id=$id' "$output/manifest.tmp.json" >"$output/manifest.json"
rm "$output/manifest.tmp.json"
echo "FAT kernel bundle: kab-$bundle_hash"
