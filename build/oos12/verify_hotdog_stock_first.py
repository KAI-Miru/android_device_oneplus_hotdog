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


def require_symlink(index, name: str, target: bytes, label: str) -> None:
    entry = index.get(name)
    require(entry is not None, f"missing {label}: /{name}")
    require(entry.mode & 0o170000 == 0o120000, f"{label} is not a symlink: /{name}")
    require(entry.data == target, f"{label} has the wrong target: /{name}")


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
        "my_product": ("/my_product", ["ext4", "erofs"]),
        "my_engineering": ("/my_engineering", ["ext4", "erofs"]),
    }
    logical = [row for row in rows if "logical" in row[-1].split(",")]
    require(len(logical) == 14, f"{name} has the wrong logical-row count")
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
    physical = {
        ("/dev/block/bootdevice/by-name/metadata", "/metadata", "ext4"),
        ("/dev/block/bootdevice/by-name/op2", "/cache", "ext4"),
        ("/dev/block/bootdevice/by-name/userdata", "/data", "ext4"),
        ("/dev/block/bootdevice/by-name/misc", "/misc", "emmc"),
        ("/dev/block/bootdevice/by-name/boot", "/boot", "emmc"),
        ("/dev/block/bootdevice/by-name/recovery", "/recovery", "emmc"),
    }
    require(
        {(row[0], row[1], row[2]) for row in rows if row not in logical} == physical,
        f"{name} does not match the audited physical partition table",
    )
    forbidden_mounts = {
        "/special_preload",
        "/external_sd",
        "/usb_otg",
        "/opporeserve",
        "/persist",
        "/reserve4",
        "/apdp",
        "/devinfo",
    }
    require(
        forbidden_mounts.isdisjoint({row[1] for row in rows}),
        f"{name} exposes a phantom or duplicate mount",
    )
    require(
        all(
            flag not in row[-1].split(",")
            for row in rows
            for flag in ("first_stage_mount", "latemount")
        )
        and "reservedsize=" not in text,
        f"{name} retains Android first-stage-only recovery flags",
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
    parser.add_argument("--runtime-manifest", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()

    sys.path.insert(0, str(args.module_dir.resolve()))
    import newc  # noqa: PLC0415
    from make_hotdog_stock_overlay import (  # noqa: PLC0415
        APEX_POLICY_RULES,
        APEX_POLICY_TOOL,
        FIRMWARE_FILES,
        LEGACY_INSTALLER_SHELL,
        LEGACY_INSTALLER_SHELL_TARGET,
        MKE2FS_CONFIG_SOURCE,
        MKE2FS_CONFIG_TARGET,
        QSEE_RUNTIME_FILES,
        QSEE_RUNTIME_NEEDED,
        ROOT_BIN_LINK,
        ROOT_BIN_LINK_TARGET,
        STOCK_CREDENTIAL_HELPER,
        STOCK_INTERPRETER,
        TZDATA_BYTES,
        TZDATA_PATH,
        TZDATA_SHA256,
        elf_interpreter,
    )
    from make_hotdog_runtime_overlay import (  # noqa: PLC0415
        ATTESTATION_SHA256,
        ATTESTATION_TARGET,
        DISPLAYCONFIG_SHA256,
        DISPLAYCONFIG_TARGET,
        POLICY_SHA256,
        POLICY_TARGET,
        STOCK_SEPOLICY_SHA256,
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
    runtime = load_json(args.runtime_manifest)
    require(stock_patch["stock_cpio_sha256"] == sha256(args.stock_cpio.read_bytes()), "stock manifest input digest mismatch")
    require(private["stock_cpio_sha256"] == sha256(args.stock_cpio.read_bytes()), "private manifest stock digest mismatch")
    require(runtime["stock_cpio_sha256"] == sha256(args.stock_cpio.read_bytes()), "runtime manifest stock digest mismatch")

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

    sbin = final_index.get("sbin")
    require(
        sbin is not None and sbin.mode & 0o170000 == 0o040000,
        "legacy ZIP installer parent is not a directory",
    )
    installer_shell = final_index.get(LEGACY_INSTALLER_SHELL)
    require(installer_shell is not None, "legacy ZIP installer shell route is absent")
    require(
        installer_shell.mode & 0o170000 == 0o120000,
        "legacy ZIP installer shell route is not a symlink",
    )
    require(
        installer_shell.data == LEGACY_INSTALLER_SHELL_TARGET,
        "legacy ZIP installer shell route has the wrong target",
    )
    system_shell = final_index.get(LEGACY_INSTALLER_SHELL_TARGET.lstrip(b"/").decode("ascii"))
    require(system_shell is not None, "legacy ZIP installer shell target is absent")
    require(
        system_shell.mode & 0o170000 == 0o100000 and system_shell.mode & 0o111 != 0,
        "legacy ZIP installer shell target is not a regular executable",
    )
    installer_shell_records = [
        record
        for record in stock_patch["records"]
        if record.get("target") == LEGACY_INSTALLER_SHELL
    ]
    require(
        len(installer_shell_records) == 1
        and installer_shell_records[0].get("entry_type") == "symlink"
        and installer_shell_records[0].get("symlink_target")
        == LEGACY_INSTALLER_SHELL_TARGET.decode("ascii")
        and installer_shell_records[0].get("purpose") == "legacy_recovery_zip_installer",
        "legacy ZIP installer shell route is not audited in the stock overlay manifest",
    )
    require_symlink(final_index, ROOT_BIN_LINK, ROOT_BIN_LINK_TARGET, "root /bin compatibility link")
    root_bin_records = [
        record for record in stock_patch["records"] if record.get("target") == ROOT_BIN_LINK
    ]
    require(
        len(root_bin_records) == 1
        and root_bin_records[0].get("entry_type") == "symlink"
        and root_bin_records[0].get("symlink_target") == ROOT_BIN_LINK_TARGET.decode("ascii")
        and root_bin_records[0].get("purpose") == "root_bin_compatibility",
        "root /bin compatibility link is not audited in the stock overlay manifest",
    )
    require_data(final_index, MKE2FS_CONFIG_SOURCE)
    require_data(final_index, MKE2FS_CONFIG_TARGET)
    require(
        final_index[MKE2FS_CONFIG_TARGET].data == final_index[MKE2FS_CONFIG_SOURCE].data,
        "root mke2fs configuration differs from /system/etc/mke2fs.conf",
    )
    mke2fs_records = [
        record for record in stock_patch["records"] if record.get("target") == MKE2FS_CONFIG_TARGET
    ]
    require(
        len(mke2fs_records) == 1
        and mke2fs_records[0].get("source") == f"stock:{MKE2FS_CONFIG_SOURCE}"
        and mke2fs_records[0].get("purpose") == "mke2fs_fixed_path_config",
        "root mke2fs configuration is not audited in the stock overlay manifest",
    )

    for record in stock_patch["records"]:
        verify_record(final_index, record, "stock patch")
    for record in private["records"]:
        verify_record(final_index, record, "private TWRP")
    for record in runtime["records"]:
        verify_record(final_index, record, "stock runtime")
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
        "sepolicy",
    ):
        require(name in stock_index, f"stock sentinel is absent from source CPIO: {name}")
        require(final_index[name] == stock_index[name], f"stock sentinel changed: {name}")

    required_private = (
        "system/tw/bin/recovery",
        "system/tw/bin/keystore2",
        "system/tw/bin/keystore_cli_v2",
        "system/tw/bin/bash",
        "system/tw/bin/nano",
        "system/tw/bin/sgdisk",
        "system/tw/bin/zip",
        "system/tw/lib64/libbinder.so",
        "system/tw/lib64/libdecrypt_recovery.so",
        "system/tw/lib64/libcryptfs_hw.so",
        "system/tw/lib64/libfscrypt.so",
        "system/tw/lib64/vendor.oplus.hardware.cryptoeng@1.0.so",
        "system/tw/lib64/vendor.qti.hardware.cryptfshw@1.0.so",
    )
    for name in required_private:
        require_data(final_index, name)

    routes = {record["source"]: record for record in private["helper_routes"]}
    for helper in ("bash", "nano", "sgdisk", "zip"):
        public = f"system/bin/{helper}"
        private_target = f"system/tw/bin/{helper}"
        require(public in routes, f"required helper route is unmanifested: /{public}")
        require(routes[public]["private_target"] == private_target, f"wrong private route for /{public}")
        require(public in final_index, f"required public helper path is missing: /{public}")
        if routes[public]["routing"] == "stock_shell_exec_private":
            expected = ("#!/system/bin/sh\n" f'exec /system/tw/bin/{helper} "$@"\n').encode("ascii")
            require(final_index[public].data == expected, f"unsafe helper wrapper contents: /{public}")

    required_original_assets = {
        "file_contexts",
        "system/etc/mkshrc",
        "sbin/bash",
        "system/etc/bash/bashrc",
        "system/etc/init/nano.rc",
        "system/etc/nano/nanorc",
        "system/etc/terminfo/x/xterm-256color",
    }
    included_assets = set(private.get("original_assets_included", []))
    require(
        required_original_assets <= included_assets,
        f"TWRP compatibility assets are incomplete: {sorted(required_original_assets - included_assets)}",
    )
    for asset in required_original_assets:
        require(asset in final_index, f"required TWRP compatibility asset is absent: /{asset}")
    require_data(final_index, "file_contexts")
    require_data(final_index, "system/etc/mkshrc")
    require_symlink(final_index, "sbin/bash", b"/system/bin/bash", "legacy Bash route")
    require_symlink(final_index, "etc/bash", b"/system/etc/bash", "Bash configuration route")
    require_symlink(final_index, "etc/nano", b"/system/etc/nano", "Nano configuration route")
    require_symlink(final_index, "etc/terminfo", b"/system/etc/terminfo", "terminfo compatibility route")
    require(
        set(private.get("feature_bundles", {})) == {"bash", "nano"},
        "Bash/Nano feature bundles are not both manifested",
    )
    require_marker(
        require_data(final_index, "system/etc/init/nano.rc"),
        b"export TERMINFO /system/etc/terminfo",
        "Nano TERMINFO export",
    )
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
    recovery_data = require_data(final_index, "system/tw/bin/recovery")
    for marker, label in (
        (b"[OPLUS V58 PWDPROBE]", "recovery-owned password protector probe"),
        (b"guarded parent-process CE install", "guarded ColorOS CE installer"),
        (b"unsupported entry set in ", "fail-closed ColorOS CE layout allowlist"),
        (b"layout requires a non-wrapped data key", "direct-AES ColorOS CE layout"),
    ):
        require_marker(recovery_data, marker, label)
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

    for name in (
        "system/lib64/libkeystore-attestation-application-id.so",
        "system/lib64/libdisplayconfig.qti.so",
        "system/lib64/vendor.display.config@2.0.so",
        POLICY_TARGET,
    ):
        require_data(final_index, name)
    require(
        sha256(final_index[POLICY_TARGET].data) == POLICY_SHA256,
        "wrong APEX policy tool in final ramdisk",
    )
    require(
        sha256(final_index[DISPLAYCONFIG_TARGET].data) == DISPLAYCONFIG_SHA256,
        "wrong OOS12 F.22 displayconfig in final ramdisk",
    )
    require(
        sha256(final_index[ATTESTATION_TARGET].data) == ATTESTATION_SHA256,
        "wrong stock-compatible gatekeeper attestation library in final ramdisk",
    )
    require(
        sha256(final_index["sepolicy"].data) == STOCK_SEPOLICY_SHA256,
        "stock OOS12 sepolicy was replaced instead of patched live",
    )
    apex_policy = runtime.get("apex_policy", {})
    displayconfig = runtime.get("displayconfig", {})
    gatekeeper_attestation = runtime.get("gatekeeper_attestation", {})
    require(
        displayconfig.get("sha256") == DISPLAYCONFIG_SHA256
        and displayconfig.get("target") == DISPLAYCONFIG_TARGET,
        "runtime manifest has the wrong displayconfig identity",
    )
    require(
        apex_policy.get("rules") == list(APEX_POLICY_RULES),
        "runtime manifest has the wrong APEX rules",
    )
    require(apex_policy.get("target") == POLICY_TARGET, "runtime manifest has the wrong APEX tool path")
    require(apex_policy.get("stock_sepolicy_preserved") is True, "runtime manifest does not preserve stock policy")
    require(
        gatekeeper_attestation.get("sha256") == ATTESTATION_SHA256
        and gatekeeper_attestation.get("target") == ATTESTATION_TARGET
        and gatekeeper_attestation.get("incompatible_refbase_symbol_absent") is True,
        "runtime manifest has the wrong gatekeeper attestation identity",
    )
    closures = runtime.get("stock_namespace_closures", {})
    for label in ("gatekeeper", "secure_ui", "qsee_ops"):
        require(label in closures, f"runtime manifest lacks {label} closure")
        require(closures[label].get("unresolved") == [], f"runtime manifest has unresolved {label} libraries")
        require(
            closures[label].get("unresolved_strong_symbols") == [],
            f"runtime manifest has unresolved {label} symbols",
        )
    require(
        any(
            item.get("provider") == "injected:system/lib64/libkeystore-attestation-application-id.so"
            for item in closures["gatekeeper"].get("providers", [])
        ),
        "gatekeeper closure did not use the injected attestation library",
    )
    for expected in (
        "injected:system/lib64/libdisplayconfig.qti.so",
        "injected:system/lib64/vendor.display.config@2.0.so",
    ):
        require(
            any(item.get("provider") == expected for item in closures["secure_ui"].get("providers", [])),
            f"Secure UI closure did not use {expected}",
        )
    for expected in (
        "injected:system/lib64/libdrm.so",
        "injected:system/lib64/libdisplayconfig.qti.so",
    ):
        require(
            any(item.get("provider") == expected for item in closures["qsee_ops"].get("providers", [])),
            f"QSEE ops closure did not use {expected}",
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
    require(
        b"start phoenix_recovery" not in init and b"service phoenix_recovery " not in init,
        "impossible stock Phoenix recovery service remains",
    )
    require(b"mtk-msdc.0" not in init, "stock MediaTek e2fsck leftovers remain")
    require(
        b"wait /dev/block/bootdevice/by-name/modem" not in init,
        "stock five-second modem wait remains",
    )
    require(b"    start healthd\n" not in init, "premature stock healthd start remains")
    require(b"mount cgroup none /acct cpuacct" not in init, "legacy cpuacct mount remains")
    require(
        b"    writepid /dev/cpuset/system-background/tasks" not in init.splitlines(),
        "stock services still write to the missing recovery cpuset",
    )
    require(
        b"on property:sys.powerctl=*" not in init,
        "invalid stock powerctl action remains",
    )
    for service in (b"gatekeeperd", b"vndservicemanager", b"irsc_util", b"wpa_supplicant"):
        start = init.index(b"service " + service + b" ")
        end = init.find(b"\nservice ", start + 1)
        block = init[start : len(init) if end < 0 else end]
        require(b"\n    disabled\n" in block, f"stock service is not explicit-start only: {service!r}")
    require_marker(init, b"mkdir /config/usb_gadget/g1/functions/mtp.gs0", "MTP configfs function")
    require_marker(init, b"Configfs was mounted and initialized by the stock init action", "single configfs mount")
    require(
        b"on fs && property:sys.usb.configfs=1\n    mount configfs none /config" not in init,
        "stock init still mounts configfs twice",
    )
    require_marker(
        init,
        b"on property:sys.usb.config=mtp,adb && property:sys.usb.ffs.ready=1 && property:sys.usb.configfs=1",
        "MTP plus ADB configfs route",
    )
    require_marker(
        init,
        b'write /config/usb_gadget/g1/UDC "none"\n    rm /config/usb_gadget/g1/configs/b.1/f1\n    rm /config/usb_gadget/g1/configs/b.1/f2',
        "idempotent USB gadget teardown",
    )
    qcom_usb = require_data(final_index, "init.recovery.qcom.rc")
    require_marker(qcom_usb, b"Configfs binding is owned by the mode-specific routes", "single USB owner")
    require(
        b"on property:sys.usb.ffs.ready=1" not in qcom_usb,
        "Qualcomm init still owns an unconditional duplicate USB binding",
    )
    policy_commands = [
        f'exec u:r:recovery:s0 root root -- {APEX_POLICY_TOOL} --live "{rule}"'.encode()
        for rule in APEX_POLICY_RULES
    ]
    for policy_command in policy_commands:
        require_marker(init, policy_command, "synchronous APEX policy hook")
        require(
            init.count(policy_command) == 1
            and init.index(policy_command) < init.index(b"class_start default"),
            "APEX policy rule is not installed exactly once before recovery starts",
        )
    require(
        [init.index(command) for command in policy_commands]
        == sorted(init.index(command) for command in policy_commands),
        "APEX policy rules are installed in the wrong order",
    )
    for name in ("plat_file_contexts", "system/etc/selinux/plat_file_contexts"):
        require_marker(
            require_data(final_index, name),
            b"/system/bin/hotdog_apex_policy u:object_r:system_file:s0",
            f"APEX policy tool file context in {name}",
        )
    linker_config = require_data(final_index, "system/etc/ld.config.txt")
    require_marker(linker_config, b"/system/tw/${LIB}:/system/${LIB}", "private linker search path")
    keystore_rc = require_data(final_index, "system/etc/init/keystore2.rc")
    require_marker(keystore_rc, b"service keystore2 /system/tw/bin/keystore2", "private Keystore2 route")
    require_marker(keystore_rc, b"    disabled", "disabled Keystore2 service")
    require(b"on late-init" not in keystore_rc and b"on boot" not in keystore_rc, "Keystore2 starts automatically")
    require(
        b"writepid /dev/cpuset/foreground/tasks" not in keystore_rc,
        "Keystore2 still writes to a missing recovery cpuset",
    )

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
    flag_rows = [
        line.split()
        for line in twrp_flags.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    expected_flag_mounts = {
        "/recovery",
        "/boot",
        "/firmware",
        "/modem",
        "/bluetooth",
        "/dsp",
        "/dtbo",
        "/efs1",
        "/efs2",
        "/efsc",
        "/efsg",
        "/metadata",
        "/usbstorage",
    }
    require(
        {row[0] for row in flag_rows} == expected_flag_mounts,
        "TWRP flags do not match the audited Hotdog partition inventory",
    )
    require(
        sum(row[0] == "/usbstorage" for row in flag_rows) == 1,
        "TWRP flags have duplicate USB storage entries",
    )
    modem_row = next(row for row in flag_rows if row[0] == "/modem")
    for child in ("/bluetooth", "/dsp"):
        child_row = next(row for row in flag_rows if row[0] == child)
        require(
            "subpartitionof=/modem" in child_row[-1] and flag_rows.index(modem_row) < flag_rows.index(child_row),
            f"{child} lost its modem parent relationship",
        )
    props = require_data(final_index, "prop.default").decode("utf-8")
    for setting in ("ro.secure=0", "ro.adb.secure=0", "ro.debuggable=1", "persist.sys.usb.config=adb", "ro.boot.dynamic_partitions=true"):
        require(setting in props, f"missing recovery property: {setting}")

    cgroups = json.loads(require_data(final_index, "etc/cgroups.json"))
    controllers = {row["Controller"] for row in cgroups.get("Cgroups", [])}
    require(
        controllers == {"blkio", "cpu", "cpuacct", "cpuset", "memory", "schedtune"},
        "final root cgroups.json has the wrong controller set",
    )
    task_profiles = json.loads(require_data(final_index, "etc/task_profiles.json"))
    require(
        bool(task_profiles.get("Profiles")) and bool(task_profiles.get("AggregateProfiles")),
        "final root task_profiles.json is incomplete",
    )
    for filename, (expected_bytes, expected_sha256) in FIRMWARE_FILES.items():
        data = require_data(final_index, f"vendor/firmware/{filename}")
        require(len(data) == expected_bytes, f"wrong haptics firmware size: {filename}")
        require(sha256(data) == expected_sha256, f"wrong haptics firmware digest: {filename}")
    tzdata = require_data(final_index, TZDATA_PATH)
    require(len(tzdata) == TZDATA_BYTES, "wrong tzdata size")
    require(sha256(tzdata) == TZDATA_SHA256, "wrong tzdata digest")
    for filename, (expected_bytes, expected_sha256) in QSEE_RUNTIME_FILES.items():
        system_copy = require_data(final_index, f"system/lib64/{filename}")
        vendor_copy = require_data(final_index, f"vendor/lib64/{filename}")
        require(system_copy == vendor_copy, f"QSEE runtime copies differ: {filename}")
        require(len(system_copy) == expected_bytes, f"wrong QSEE runtime size: {filename}")
        require(sha256(system_copy) == expected_sha256, f"wrong QSEE runtime digest: {filename}")
        records = [
            record
            for record in stock_patch["records"]
            if record.get("target") in {
                f"system/lib64/{filename}",
                f"vendor/lib64/{filename}",
            }
        ]
        require(len(records) == 2, f"QSEE runtime manifest copies are incomplete: {filename}")
        require(
            all(
                record.get("soname") == filename
                and record.get("dt_needed") == QSEE_RUNTIME_NEEDED[filename]
                for record in records
            ),
            f"QSEE runtime ELF audit is missing or changed: {filename}",
        )

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
        "stock_runtime": {
            "manifested_entries": len(runtime["records"]),
            "gatekeeper_closure_sonames": len(closures["gatekeeper"]["resolved_sonames"]),
            "secure_ui_closure_sonames": len(closures["secure_ui"]["resolved_sonames"]),
            "qsee_ops_closure_sonames": len(closures["qsee_ops"]["resolved_sonames"]),
            "stock_sepolicy_sha256": STOCK_SEPOLICY_SHA256,
            "apex_policy_rules": list(APEX_POLICY_RULES),
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
            "legacy_zip_installer_shell_route_present": True,
            "oplus_decrypt_and_keystore_markers_present": True,
            "commondcs_dependency_present_and_abi_matched": True,
            "gatekeeper_stock_namespace_closure_complete": True,
            "secure_ui_stock_namespace_closure_complete": True,
            "stock_sepolicy_exact_and_apex_rules_synchronous": True,
            "usb_configfs_routes_idempotent_with_mtp": True,
            "root_cgroup_configuration_present": True,
            "hotdog_haptics_firmware_complete": True,
            "timezone_database_present": True,
            "qsee_optional_runtime_closure_complete": True,
            "irrelevant_stock_init_noise_removed": True,
            "inventory_audited_dynamic_ab_mount_tables": True,
            "avb_footer_structurally_valid": True,
        },
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
