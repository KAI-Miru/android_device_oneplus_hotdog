#!/usr/bin/env python3
"""Independent structural audit for the Hotdog OOS12 stock-first TWRP image."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import struct
import sys
from pathlib import Path


def sha256(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def require_data(index, name: str) -> bytes:
    require(name in index, f"missing required ramdisk entry: {name}")
    require(bool(index[name].data), f"empty required ramdisk entry: {name}")
    return index[name].data


def require_marker(blob: bytes, marker: bytes, label: str) -> None:
    require(marker in blob, f"missing {label}: {marker!r}")


def verify_record(index, record: dict, label: str) -> None:
    target = record["target"]
    require(target in index, f"missing {label} target: {target}")
    data = index[target].data
    expected_bytes = record.get("target_bytes", record.get("bytes"))
    require(expected_bytes is not None, f"manifest has no byte count for {label} target: {target}")
    require(
        len(data) == expected_bytes,
        f"wrong byte count for {label} target: {target}",
    )
    require(
        sha256(data) == record["target_sha256"],
        f"wrong digest for {label} target: {target}",
    )


def entry_metadata(entry) -> tuple[int, ...]:
    return (
        entry.mode,
        entry.uid,
        entry.gid,
        entry.nlink,
        entry.mtime,
        entry.devmajor,
        entry.devminor,
        entry.rdevmajor,
        entry.rdevminor,
    )


def active_fstab_rows(text: str) -> list[list[str]]:
    rows = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        fields = stripped.split()
        if len(fields) >= 5:
            rows.append(fields)
    return rows


def verify_fstab(text: str, name: str) -> None:
    rows = active_fstab_rows(text)
    expected = {
        "system": ("/system", ["ext4", "erofs"]),
        "system_ext": ("/system_ext", ["ext4", "erofs"]),
        "product": ("/product", ["ext4", "erofs"]),
        "vendor": ("/vendor", ["ext4", "erofs"]),
        "odm": ("/odm", ["ext4", "erofs"]),
        "my_product": ("/my_product", ["erofs"]),
        "my_engineering": ("/my_engineering", ["ext4"]),
    }
    logical = [row for row in rows if "logical" in row[-1].split(",")]
    require(len(logical) == 12, f"{name} has the wrong logical-row count")
    for partition, (mount, filesystems) in expected.items():
        selected = [row for row in logical if row[0] == partition]
        require(
            [row[2] for row in selected] == filesystems,
            f"{name} has wrong filesystem alternatives for {partition}",
        )
        require(
            all(row[1] == mount for row in selected),
            f"{name} has wrong mount point for {partition}",
        )
        require(
            all("slotselect" in row[-1].split(",") for row in selected),
            f"{name} lost slotselect for {partition}",
        )
    require(
        any(row[:3] == ["/dev/block/bootdevice/by-name/recovery", "/recovery", "emmc"] for row in rows),
        f"{name} lost the OnePlus recovery-partition row",
    )
    require(
        any(row[:3] == ["/dev/block/bootdevice/by-name/userdata", "/data", "ext4"] for row in rows),
        f"{name} lost the OnePlus userdata row",
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--module-dir", type=Path, required=True)
    parser.add_argument("--stock-recovery", type=Path, required=True)
    parser.add_argument("--final-recovery", type=Path, required=True)
    parser.add_argument("--stock-cpio", type=Path, required=True)
    parser.add_argument("--raw-ramdisk", type=Path, required=True)
    parser.add_argument("--gzip-ramdisk", type=Path, required=True)
    parser.add_argument("--stock-patch-manifest", type=Path, required=True)
    parser.add_argument("--private-manifest", type=Path, required=True)
    parser.add_argument("--cryptoeng-manifest", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()

    sys.path.insert(0, str(args.module_dir.resolve()))
    import newc  # noqa: PLC0415
    from make_hotdog_stock_overlay import (  # noqa: PLC0415
        STOCK_CREDENTIAL_HELPER,
        STOCK_INTERPRETER,
        elf_interpreter,
    )
    from repack_boot_v2 import AVB_FOOTER_MAGIC, parse_boot_v2  # noqa: PLC0415

    stock = parse_boot_v2(args.stock_recovery)
    final = parse_boot_v2(args.final_recovery)
    require(len(final.image) == 100663296, "final partition size is not 96 MiB")
    require(
        len(stock.image) == stock.original_image_size == 77979648,
        "assembled OOS12 stock boot payload has the wrong size",
    )
    require(final.page_size == stock.page_size, "boot page size differs from stock")
    for component in ("kernel", "second", "recovery_dtbo", "dtb"):
        require(
            getattr(final, component) == getattr(stock, component),
            f"final {component} differs from OOS12 stock",
        )

    allowed_header_offsets = set(range(16, 20))
    allowed_header_offsets.update(range(576, 608))
    allowed_header_offsets.update(range(1636, 1644))
    changed_header_offsets = [
        offset
        for offset, (before, after) in enumerate(zip(stock.header_page, final.header_page, strict=True))
        if before != after
    ]
    require(
        all(offset in allowed_header_offsets for offset in changed_header_offsets),
        "boot header changed outside ramdisk size, image ID, or recovery-DTBO offset",
    )

    expected_gzip = args.gzip_ramdisk.read_bytes()
    expected_raw = args.raw_ramdisk.read_bytes()
    require(final.ramdisk == expected_gzip, "final ramdisk differs from the audited gzip payload")
    require(gzip.decompress(final.ramdisk) == expected_raw, "final ramdisk does not expand to audited CPIO")

    require(final.image[-64:-60] == AVB_FOOTER_MAGIC, "final image has no AVB footer")
    magic, major, minor, original_size, vbmeta_offset, vbmeta_size, reserved = struct.unpack(
        ">4sIIQQQ28s", final.image[-64:]
    )
    require(magic == AVB_FOOTER_MAGIC and (major, minor) == (1, 0), "bad AVB footer version")
    require(original_size == final.original_image_size, "AVB original-image size is wrong")
    require(vbmeta_offset == original_size, "VBMeta is not directly after the boot payload")
    require(vbmeta_offset + vbmeta_size <= len(final.image) - 64, "VBMeta exceeds image bounds")
    require(not any(reserved), "AVB footer reserved bytes are nonzero")
    require(final.image[vbmeta_offset : vbmeta_offset + 4] == b"AVB0", "VBMeta header is absent")
    algorithm_type = struct.unpack_from(">I", final.image, vbmeta_offset + 28)[0]
    require(algorithm_type == 0, "test image AVB algorithm is not NONE")

    final_entries = newc.read(args.raw_ramdisk)
    final_names = [entry.name for entry in final_entries]
    require(len(final_names) == len(set(final_names)), "final CPIO contains duplicate paths")
    final_index = newc.index(final_entries)
    stock_entries = newc.read(args.stock_cpio)
    stock_index = newc.index(stock_entries)
    require(len(stock_entries) == len(stock_index), "stock CPIO contains duplicate paths")

    stock_patch = load_json(args.stock_patch_manifest)
    private = load_json(args.private_manifest)
    cryptoeng = load_json(args.cryptoeng_manifest)
    require(stock_patch["stock_cpio_sha256"] == sha256(args.stock_cpio.read_bytes()), "stock manifest input digest mismatch")
    require(private["stock_cpio_sha256"] == sha256(args.stock_cpio.read_bytes()), "private manifest stock digest mismatch")

    replacement_targets = {
        record["target"] for record in stock_patch["records"] if record["kind"] == "replacement"
    }
    preserved_count = 0
    for name, source in stock_index.items():
        require(name in final_index, f"stock OnePlus entry was removed: {name}")
        target = final_index[name]
        if name in replacement_targets:
            require(entry_metadata(target) == entry_metadata(source), f"replacement changed metadata: {name}")
            continue
        require(target == source, f"stock OnePlus entry changed unexpectedly: {name}")
        preserved_count += 1

    for record in stock_patch["records"]:
        verify_record(final_index, record, "stock patch")
    for record in private["records"]:
        verify_record(final_index, record, "private TWRP")
    verify_record(
        final_index,
        {
            "target": cryptoeng["target"],
            "target_bytes": cryptoeng["source_bytes"],
            "target_sha256": cryptoeng["source_sha256"],
        },
        "CommonDCS",
    )
    require(cryptoeng["symbol_import_export_verified"] is True, "CommonDCS ABI link was not verified")
    require(
        "vendor.oplus.hardware.commondcs@1.0.so" in cryptoeng["service_dt_needed"],
        "cryptoeng service manifest lacks CommonDCS DT_NEEDED",
    )

    for name in (
        "system/bin/recovery",
        "system/etc/vintf/manifest.xml",
        "sbin/system/etc/vintf/manifest.xml",
        "sbin/vendor/etc/vintf/manifest.xml",
        "vendor/etc/vintf",
        "system/bin/hw/vendor.oplus.hardware.cryptoeng@1.0-service",
        "system/lib64/libdecrypt_recovery.so",
    ):
        require(name in stock_index, f"stock sentinel is absent from source CPIO: {name}")
        require(final_index[name] == stock_index[name], f"stock sentinel changed: {name}")

    required_private = (
        "system/tw/bin/recovery",
        "system/tw/bin/keystore2",
        "system/tw/bin/keystore_cli_v2",
        "system/tw/lib64/libbinder.so",
        "system/tw/lib64/libdecrypt_recovery.so",
        "system/tw/lib64/libcryptfs_hw.so",
        "system/tw/lib64/libfscrypt.so",
        "system/tw/lib64/vendor.oplus.hardware.cryptoeng@1.0.so",
        "system/tw/lib64/vendor.qti.hardware.cryptfshw@1.0.so",
    )
    for name in required_private:
        require_data(final_index, name)
    require(
        sha256(final_index["system/tw/lib64/libdecrypt_recovery.so"].data)
        == sha256(stock_index["system/lib64/libdecrypt_recovery.so"].data),
        "private libdecrypt_recovery is not the stock Oplus library",
    )

    dlopen = private.get("dlopen_root", {})
    expected_proprietary = {
        "system/tw/lib64/libdecrypt_recovery.so",
        "system/tw/lib64/libcryptfs_hw.so",
        "system/tw/lib64/libfscrypt.so",
        "system/tw/lib64/vendor.oplus.hardware.cryptoeng@1.0.so",
        "system/tw/lib64/vendor.qti.hardware.cryptfshw@1.0.so",
    }
    require(set(dlopen.get("proprietary_targets", [])) == expected_proprietary, "wrong Oplus decrypt load group")
    require(dlopen.get("unresolved_strong_symbol_groups") == 0, "decrypt load group has unresolved strong symbols")
    require(dlopen.get("dt_needed_closure_count") == len(dlopen.get("dependency_targets", [])), "decrypt closure count mismatch")

    require_marker(require_data(final_index, "system/tw/bin/recovery"), b"[H40 V51 PARENT]", "ColorOS adapter marker")
    credential_helper = require_data(final_index, STOCK_CREDENTIAL_HELPER)
    require(credential_helper[:4] == b"\x7fELF", "stock credential helper is not ELF")
    require(
        elf_interpreter(credential_helper) == STOCK_INTERPRETER,
        "credential helper was relocated out of the stock OOS12 linker namespace",
    )
    require(
        final_index[STOCK_CREDENTIAL_HELPER].mode & 0o111 != 0,
        "stock credential helper is not executable",
    )
    require(
        "system/tw/bin/oplus_h40_credential_helper" not in final_index,
        "credential helper was also copied into the private TWRP runtime",
    )
    require_marker(
        credential_helper,
        b"_Z21OplusCredentialVerifyNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEi",
        "Oplus credential ABI",
    )
    require_marker(
        require_data(final_index, "system/tw/bin/keystore2"),
        b"H40_RECOVERY_KEYSTORE2_PERMISSION_SHIM_V51",
        "Keystore2 recovery shim",
    )
    require_marker(
        require_data(final_index, "system/tw/lib64/libbinder.so"),
        b"H40_RECOVERY_BINDER_STABILITY_V0_V52",
        "Binder compatibility shim",
    )

    init = require_data(final_index, "system/etc/init/hw/init.rc")
    require_marker(init, b"service recovery /system/tw/bin/r", "private recovery route")
    require_marker(init, b"service fastbootd /system/tw/bin/fastbootd", "private fastbootd route")
    require_marker(init, b"mkdir /tmp/misc/keystore/", "Keystore working directory")
    linker_config = require_data(final_index, "system/etc/ld.config.txt")
    require_marker(linker_config, b"/system/tw/${LIB}:/system/${LIB}", "private linker search path")
    keystore_rc = require_data(final_index, "system/etc/init/keystore2.rc")
    require_marker(keystore_rc, b"service keystore2 /system/tw/bin/keystore2", "private Keystore2 route")
    require_marker(keystore_rc, b"    disabled", "disabled Keystore2 service")
    require(b"on late-init" not in keystore_rc and b"on boot" not in keystore_rc, "Keystore2 starts automatically")

    service_contexts = require_data(final_index, "system/etc/selinux/plat_service_contexts").decode("utf-8")
    for service in (
        "android.system.keystore2.IKeystoreService/default",
        "android.security.apc",
        "android.security.authorization",
        "android.security.compat",
        "android.security.metrics",
        "android.security.remoteprovisioning",
        "android.security.maintenance",
        "android.security.legacykeystore",
    ):
        selected = [
            line
            for line in service_contexts.splitlines()
            if line.split(maxsplit=1) and line.split(maxsplit=1)[0] == service
        ]
        require(len(selected) == 1 and "u:object_r:keystore_service:s0" in selected[0], f"bad service context: {service}")

    for name in ("etc/recovery.fstab", "system/etc/recovery.fstab"):
        verify_fstab(require_data(final_index, name).decode("utf-8"), name)
    twrp_flags = require_data(final_index, "etc/twrp.flags").decode("utf-8")
    require("/recovery" in twrp_flags and "flashimg=1" in twrp_flags, "TWRP flags lack recovery image support")
    props = require_data(final_index, "prop.default").decode("utf-8")
    for setting in ("ro.secure=0", "ro.adb.secure=0", "ro.debuggable=1", "persist.sys.usb.config=adb", "ro.boot.dynamic_partitions=true"):
        require(setting in props, f"missing recovery property: {setting}")

    report = {
        "format": 1,
        "result": "PASS",
        "final_image": {
            "bytes": len(final.image),
            "sha256": sha256(final.image),
            "boot_payload_bytes": final.original_image_size,
            "ramdisk_gzip_bytes": len(final.ramdisk),
            "ramdisk_gzip_sha256": sha256(final.ramdisk),
            "ramdisk_raw_bytes": len(expected_raw),
            "ramdisk_raw_sha256": sha256(expected_raw),
            "ramdisk_entries": len(final_entries),
        },
        "stock_oos12": {
            "image_sha256": sha256(stock.image),
            "cpio_entries": len(stock_entries),
            "entries_preserved_exactly": preserved_count,
            "entries_intentionally_patched": len(replacement_targets),
            "components": {
                name: {"bytes": len(getattr(final, name)), "sha256": sha256(getattr(final, name))}
                for name in ("kernel", "second", "recovery_dtbo", "dtb")
            },
        },
        "private_twrp": {
            "manifested_entries": len(private["records"]),
            "library_count": private["library_count"],
            "resource_entry_count": private["resource_entry_count"],
            "decrypt_dt_needed_closure_count": dlopen["dt_needed_closure_count"],
            "decrypt_unresolved_strong_symbol_groups": dlopen["unresolved_strong_symbol_groups"],
        },
        "oplus_crypto": {
            "private_proprietary_files": sorted(expected_proprietary),
            "commondcs_sha256": cryptoeng["source_sha256"],
            "commondcs_symbol_link_verified": cryptoeng["symbol_import_export_verified"],
        },
        "avb": {
            "footer_version": f"{major}.{minor}",
            "algorithm": "NONE",
            "rollback_index": 1,
            "original_image_bytes": original_size,
            "vbmeta_offset": vbmeta_offset,
            "vbmeta_bytes": vbmeta_size,
        },
        "changed_boot_header_offsets": changed_header_offsets,
        "checks": {
            "android_boot_header_v2_valid": True,
            "partition_size_exact_stock": True,
            "kernel_dtb_recovery_dtbo_exact_stock": True,
            "stock_ramdisk_preserved_except_audited_patch_set": True,
            "stock_recovery_vintf_and_crypto_sentinels_exact": True,
            "private_twrp_manifest_exact": True,
            "private_elf_dependency_closure_complete": True,
            "credential_helper_uses_stock_oos12_namespace": True,
            "oplus_decrypt_and_keystore_markers_present": True,
            "commondcs_dependency_present_and_abi_matched": True,
            "dynamic_ab_fstab_and_recovery_partition_present": True,
            "avb_footer_structurally_valid": True,
        },
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
