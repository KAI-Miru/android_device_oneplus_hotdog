#!/usr/bin/env bash

set -euo pipefail

if [[ "$#" -ne 7 ]]; then
  echo "usage: $0 SOURCE_ROOT RECOVERY_IMG KERNEL DTB RECOVERY_DTBO PARTITION_SIZE REPORT_DIR" >&2
  exit 2
fi

source_root="$1"
recovery_image="$2"
source_kernel="$3"
source_dtb="$4"
source_recovery_dtbo="$5"
partition_size="$6"
report_dir="$7"

for input in \
  "$recovery_image" \
  "$source_kernel" \
  "$source_dtb" \
  "$source_recovery_dtbo" \
  "$source_root/system/tools/mkbootimg/unpack_bootimg.py"
do
  if [[ ! -f "$input" ]]; then
    echo "required input is missing: $input" >&2
    exit 1
  fi
done

if [[ ! "$partition_size" =~ ^[0-9]+$ ]] || (( partition_size <= 0 )); then
  echo "invalid recovery partition size: $partition_size" >&2
  exit 1
fi

mkdir -p "$report_dir"
unpack_dir="$RUNNER_TEMP/hotdog-recovery-unpacked"
if [[ -e "$unpack_dir" ]]; then
  echo "refusing to reuse existing unpack directory: $unpack_dir" >&2
  exit 1
fi
mkdir -p "$unpack_dir"

python3 "$source_root/system/tools/mkbootimg/unpack_bootimg.py" \
  --boot_img "$recovery_image" \
  --out "$unpack_dir" \
  | tee "$report_dir/recovery-unpack-info.txt"

for component in kernel ramdisk dtb recovery_dtbo; do
  if [[ ! -s "$unpack_dir/$component" ]]; then
    echo "unpacked recovery component is missing or empty: $component" >&2
    exit 1
  fi
done
if [[ -e "$unpack_dir/second" ]]; then
  echo "unexpected second-stage payload in recovery image" >&2
  exit 1
fi

header_version="$(
  awk -F': ' '$1 == "boot image header version" { print $2 }' \
    "$report_dir/recovery-unpack-info.txt"
)"
page_size="$(
  awk -F': ' '$1 == "page size" { print $2 }' \
    "$report_dir/recovery-unpack-info.txt"
)"

if [[ ! "$header_version" =~ ^[0-9]+$ ]]; then
  echo "could not parse one numeric header version from unpack_bootimg info" >&2
  exit 1
fi
if [[ ! "$page_size" =~ ^[0-9]+$ ]]; then
  echo "could not parse one numeric page size from unpack_bootimg info" >&2
  exit 1
fi

# Cross-check the human-readable tool output against the fixed v0-v2 header
# fields. This avoids silently accepting a future output-format change.
read -r raw_header_version raw_page_size < <(
  python3 - "$recovery_image" <<'PY'
import struct
import sys

with open(sys.argv[1], "rb") as stream:
    header = stream.read(8 + (9 * 4))
if len(header) != 44 or header[:8] != b"ANDROID!":
    raise SystemExit("not a complete Android boot image header")
fields = struct.unpack_from("<9I", header, 8)
print(fields[8], fields[7])
PY
)
if [[ "$header_version" != "$raw_header_version" || \
      "$page_size" != "$raw_page_size" ]]; then
  echo "unpack_bootimg info disagrees with the raw boot header" >&2
  exit 1
fi

if [[ "$header_version" != "2" ]]; then
  echo "expected boot image header version 2, got $header_version" >&2
  exit 1
fi
if [[ "$page_size" != "4096" ]]; then
  echo "expected page size 4096, got $page_size" >&2
  exit 1
fi

source_kernel_hash="$(sha256sum "$source_kernel" | awk '{print $1}')"
source_dtb_hash="$(sha256sum "$source_dtb" | awk '{print $1}')"
source_dtbo_hash="$(sha256sum "$source_recovery_dtbo" | awk '{print $1}')"
image_kernel_hash="$(sha256sum "$unpack_dir/kernel" | awk '{print $1}')"
image_dtb_hash="$(sha256sum "$unpack_dir/dtb" | awk '{print $1}')"
image_dtbo_hash="$(sha256sum "$unpack_dir/recovery_dtbo" | awk '{print $1}')"

if [[ "$image_kernel_hash" != "$source_kernel_hash" ]]; then
  echo "packaged kernel does not match the pinned prebuilt" >&2
  exit 1
fi
if [[ "$image_dtb_hash" != "$source_dtb_hash" ]]; then
  echo "packaged DTB does not match the pinned prebuilt" >&2
  exit 1
fi
if [[ "$image_dtbo_hash" != "$source_dtbo_hash" ]]; then
  echo "packaged recovery-DTBO does not match the pinned prebuilt" >&2
  exit 1
fi

{
  printf 'source_kernel\t%s\t%s\n' "$source_kernel_hash" "$source_kernel"
  printf 'image_kernel\t%s\t%s\n' "$image_kernel_hash" "$unpack_dir/kernel"
  printf 'source_dtb\t%s\t%s\n' "$source_dtb_hash" "$source_dtb"
  printf 'image_dtb\t%s\t%s\n' "$image_dtb_hash" "$unpack_dir/dtb"
  printf 'source_recovery_dtbo\t%s\t%s\n' "$source_dtbo_hash" "$source_recovery_dtbo"
  printf 'image_recovery_dtbo\t%s\t%s\n' "$image_dtbo_hash" "$unpack_dir/recovery_dtbo"
  printf 'ramdisk\t%s\t%s\n' \
    "$(sha256sum "$unpack_dir/ramdisk" | awk '{print $1}')" \
    "$unpack_dir/ramdisk"
} | tee "$report_dir/recovery-component-sha256.txt"

image_size="$(stat --format='%s' "$recovery_image")"
kernel_size="$(stat --format='%s' "$unpack_dir/kernel")"
ramdisk_size="$(stat --format='%s' "$unpack_dir/ramdisk")"
dtb_size="$(stat --format='%s' "$unpack_dir/dtb")"
dtbo_size="$(stat --format='%s' "$unpack_dir/recovery_dtbo")"

pad_to_page() {
  local size="$1"
  local page="$2"
  printf '%s\n' "$(( (size + page - 1) / page * page ))"
}

kernel_padded="$(pad_to_page "$kernel_size" "$page_size")"
ramdisk_padded="$(pad_to_page "$ramdisk_size" "$page_size")"
dtb_padded="$(pad_to_page "$dtb_size" "$page_size")"
dtbo_padded="$(pad_to_page "$dtbo_size" "$page_size")"
expected_image_size="$((page_size + kernel_padded + ramdisk_padded + dtbo_padded + dtb_padded))"
fixed_region_size="$((page_size + kernel_padded + dtbo_padded + dtb_padded))"
maximum_ramdisk_region="$((partition_size - fixed_region_size))"
headroom="$((partition_size - image_size))"

if (( image_size != expected_image_size )); then
  echo "image size $image_size does not match the expected v2 layout $expected_image_size" >&2
  exit 1
fi
if (( image_size > partition_size )); then
  echo "recovery image is larger than its partition: $image_size > $partition_size" >&2
  exit 1
fi

{
  echo "header_version=$header_version"
  echo "page_size=$page_size"
  echo "kernel_size=$kernel_size"
  echo "kernel_padded=$kernel_padded"
  echo "ramdisk_size=$ramdisk_size"
  echo "ramdisk_padded=$ramdisk_padded"
  echo "recovery_dtbo_size=$dtbo_size"
  echo "recovery_dtbo_padded=$dtbo_padded"
  echo "dtb_size=$dtb_size"
  echo "dtb_padded=$dtb_padded"
  echo "fixed_non_ramdisk_region=$fixed_region_size"
  echo "maximum_padded_ramdisk_region=$maximum_ramdisk_region"
  echo "expected_image_size=$expected_image_size"
  echo "actual_image_size=$image_size"
  echo "recovery_partition_size=$partition_size"
  echo "partition_headroom=$headroom"
  if (( headroom < 4194304 )); then
    echo "warning=partition headroom is below 4 MiB"
  else
    echo "warning=none"
  fi
} | tee "$report_dir/recovery-image-layout.txt"

sha256sum "$recovery_image" \
  | tee "$report_dir/recovery-image.sha256"
