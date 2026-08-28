#!/usr/bin/env python3
"""Build the minimal stock-side overlay for the Hotdog OOS 12 hybrid ramdisk."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import sys
from dataclasses import replace
from pathlib import Path


PRIVATE_CONTEXTS = (
    "/system/bin/hotdog_apex_policy u:object_r:system_file:s0",
    "/system/tw/linker64          u:object_r:system_linker_exec:s0",
    "/system/tw/bin(/.*)?         u:object_r:system_file:s0",
    "/system/tw/lib64(/.*)?       u:object_r:system_lib_file:s0",
)

KEYSTORE_SERVICE_CONTEXTS = (
    "android.system.keystore2.IKeystoreService/default                    u:object_r:keystore_service:s0",
    "android.security.apc                                                 u:object_r:keystore_service:s0",
    "android.security.authorization                                       u:object_r:keystore_service:s0",
    "android.security.compat                                              u:object_r:keystore_service:s0",
    "android.security.metrics                                             u:object_r:keystore_service:s0",
    "android.security.remoteprovisioning                                  u:object_r:keystore_service:s0",
    "android.security.maintenance                                         u:object_r:keystore_service:s0",
    "android.security.legacykeystore                                      u:object_r:keystore_service:s0",
)

LOGICAL_ROWS = (
    ("system", "/system", ("ext4", "erofs")),
    ("system_ext", "/system_ext", ("ext4", "erofs")),
    ("product", "/product", ("ext4", "erofs")),
    ("vendor", "/vendor", ("ext4", "erofs")),
    ("odm", "/odm", ("ext4", "erofs")),
    ("my_product", "/my_product", ("erofs",)),
    ("my_engineering", "/my_engineering", ("ext4",)),
)

STOCK_CREDENTIAL_HELPER = "system/bin/oplus_h40_credential_helper"
STOCK_INTERPRETER = "/system/bin/linker64"
APEX_POLICY_TOOL = "/system/bin/hotdog_apex_policy"
APEX_POLICY_RULE = "allow kernel tmpfs file read"

FIRMWARE_FILES = {
    "aw8697_haptic_170.bin": (
        5_852,
        "c77f9450350bd0036674c67cea62fd12784fe00aba5bc9e01f3411782fac57db",
    ),
    "40ms_RTP_170Hz.bin": (
        985,
        "f1de14505c59a0d91db1f1b2cf7e58a276f949f61946273cefb001d59f780527",
    ),
    "80ms_RTP_170Hz.bin": (
        1_979,
        "98fb90d52ddf8ce2e5825d057c67be0237d78e6c6df439c2d8fbceff136ab4ff",
    ),
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def decode(relative: str, data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SystemExit(f"expected UTF-8 text in {relative}") from exc


def elf_interpreter(blob: bytes) -> str:
    """Return the sole PT_INTERP path from an ELF executable."""

    if blob[:4] != b"\x7fELF":
        raise ValueError("entry is not ELF")
    elf_class, encoding = blob[4], blob[5]
    if elf_class not in (1, 2) or encoding not in (1, 2):
        raise ValueError("unsupported ELF class or byte order")
    endian = "<" if encoding == 1 else ">"
    if elf_class == 2:
        header = struct.unpack_from(endian + "HHIQQQIHHHHHH", blob, 16)
        phoff, phentsize, phnum = header[4], header[8], header[9]
        ph_format = endian + "IIQQQQQQ"
    else:
        header = struct.unpack_from(endian + "HHIIIIIHHHHHH", blob, 16)
        phoff, phentsize, phnum = header[4], header[8], header[9]
        ph_format = endian + "IIIIIIII"

    matches = []
    for number in range(phnum):
        values = struct.unpack_from(ph_format, blob, phoff + number * phentsize)
        if values[0] != 3:  # PT_INTERP
            continue
        if elf_class == 2:
            offset, size = values[2], values[5]
        else:
            offset, size = values[1], values[4]
        segment = blob[offset : offset + size]
        if len(segment) != size:
            raise ValueError("truncated PT_INTERP segment")
        matches.append(segment.split(b"\0", 1)[0].decode("ascii"))
    if len(matches) != 1:
        raise ValueError(f"expected exactly one PT_INTERP segment, found {len(matches)}")
    return matches[0]


def patch_init(text: str) -> str:
    recovery = re.compile(r"^service recovery /system/bin/recovery\s*$", re.MULTILINE)
    fastbootd = re.compile(r"^service fastbootd /system/bin/fastbootd\s*$", re.MULTILINE)
    if len(recovery.findall(text)) != 1 or len(fastbootd.findall(text)) != 1:
        raise SystemExit("unexpected Hotdog stock recovery/fastbootd service declarations")
    text = recovery.sub("service recovery /system/tw/bin/r", text)
    text = fastbootd.sub("service fastbootd /system/tw/bin/fastbootd", text)

    anchor = "    chown root shell /tmp\n    chmod 0775 /tmp\n\n"
    additions = "    mkdir /tmp/misc\n    mkdir /tmp/misc/keystore/\n"
    if text.count(anchor) != 1:
        raise SystemExit("Hotdog stock /tmp init anchor is absent or duplicated")
    if "mkdir /tmp/misc" in text or "mkdir /tmp/misc/keystore" in text:
        raise SystemExit("Hotdog stock init already contains TWRP Keystore2 directories")
    text = text.replace(anchor, anchor + additions, 1)

    mtk_checks = (
        "    exec /sbin/e2fsck -y /dev/block/platform/mtk-msdc.0/by-name/cache\n"
        "    exec /sbin/e2fsck -y /dev/block/platform/mtk-msdc.0/by-name/userdata\n"
    )
    if text.count(mtk_checks) != 1:
        raise SystemExit("unexpected stock MediaTek e2fsck leftovers")
    text = text.replace(
        mtk_checks,
        "    # Removed irrelevant MediaTek recovery filesystem checks.\n",
        1,
    )
    modem_wait = "    wait /dev/block/bootdevice/by-name/modem\n"
    if text.count(modem_wait) != 1:
        raise SystemExit("unexpected stock modem wait")
    text = text.replace(
        modem_wait,
        "    # The logical modem node is not required before recovery QSEE starts.\n",
        1,
    )

    # Stock init owns configfs in the stock-first ramdisk.  Make every route
    # tear down the prior binding before replacing its function links, and add
    # the MTP combinations TWRP requests.  This also makes repeated ffs.ready
    # notifications harmless instead of producing EEXIST/EBUSY.
    mtp_anchor = "    mkdir /config/usb_gadget/g1/functions/ffs.adb\n"
    if text.count(mtp_anchor) != 3 or "functions/mtp.gs0" in text:
        raise SystemExit("unexpected Hotdog stock configfs function setup")
    text = text.replace(
        mtp_anchor,
        mtp_anchor + "    mkdir /config/usb_gadget/g1/functions/mtp.gs0\n",
    )
    duplicate_mount = (
        "on fs && property:sys.usb.configfs=1\n"
        "    mount configfs none /config\n"
    )
    if text.count(duplicate_mount) != 1:
        raise SystemExit("unexpected Hotdog duplicate configfs mount")
    text = text.replace(
        duplicate_mount,
        "on fs && property:sys.usb.configfs=1\n"
        "    # Configfs was mounted and initialized by the stock init action.\n",
        1,
    )
    config_dir_anchor = (
        "    mkdir /config/usb_gadget/g1/configs/b.1/strings/0x409 0770 shell shell\n"
        "\n"
        "on fs && property:sys.usb.configfs=0"
    )
    if text.count(config_dir_anchor) != 1:
        raise SystemExit("unexpected Hotdog stock configfs descriptor setup")
    text = text.replace(
        config_dir_anchor,
        "    mkdir /config/usb_gadget/g1/configs/b.1/strings/0x409 0770 shell shell\n"
        "    rm /config/usb_gadget/g1/os_desc/b.1\n"
        "    symlink /config/usb_gadget/g1/configs/b.1 /config/usb_gadget/g1/os_desc/b.1\n"
        "\n"
        "on fs && property:sys.usb.configfs=0",
        1,
    )

    configfs_start = text.find("# Configfs triggers\n")
    configfs_end_anchor = "\n#Fangfang.Hui@PSW.AD.Storage.DiskEncryption.1122242"
    configfs_end = text.find(configfs_end_anchor, configfs_start)
    if configfs_start < 0 or configfs_end < 0:
        raise SystemExit("Hotdog stock configfs trigger block was not found")
    configfs = """# Configfs triggers; routes are idempotent across TWRP mode changes.
on property:sys.usb.config=none && property:sys.usb.configfs=1
    write /config/usb_gadget/g1/UDC "none"
    stop adbd
    stop fastbootd
    setprop sys.usb.ffs.ready 0
    rm /config/usb_gadget/g1/configs/b.1/f1
    rm /config/usb_gadget/g1/configs/b.1/f2
    setprop sys.usb.state ${sys.usb.config}

on property:sys.usb.config=sideload && property:sys.usb.ffs.ready=1 && property:sys.usb.configfs=1
    write /config/usb_gadget/g1/UDC "none"
    rm /config/usb_gadget/g1/configs/b.1/f1
    rm /config/usb_gadget/g1/configs/b.1/f2
    write /config/usb_gadget/g1/idVendor 0x18D1
    write /config/usb_gadget/g1/idProduct 0xD001
    write /config/usb_gadget/g1/configs/b.1/strings/0x409/configuration "adb"
    symlink /config/usb_gadget/g1/functions/ffs.adb /config/usb_gadget/g1/configs/b.1/f1
    write /config/usb_gadget/g1/UDC ${sys.usb.controller}
    setprop sys.usb.state ${sys.usb.config}

on property:sys.usb.config=adb && property:sys.usb.ffs.ready=1 && property:sys.usb.configfs=1
    write /config/usb_gadget/g1/UDC "none"
    rm /config/usb_gadget/g1/configs/b.1/f1
    rm /config/usb_gadget/g1/configs/b.1/f2
    write /config/usb_gadget/g1/idVendor 0x18D1
    write /config/usb_gadget/g1/idProduct 0xD001
    write /config/usb_gadget/g1/configs/b.1/strings/0x409/configuration "adb"
    symlink /config/usb_gadget/g1/functions/ffs.adb /config/usb_gadget/g1/configs/b.1/f1
    write /config/usb_gadget/g1/UDC ${sys.usb.controller}
    setprop sys.usb.state ${sys.usb.config}

on property:sys.usb.config=fastboot && property:sys.usb.ffs.ready=1 && property:sys.usb.configfs=1
    write /config/usb_gadget/g1/UDC "none"
    rm /config/usb_gadget/g1/configs/b.1/f1
    rm /config/usb_gadget/g1/configs/b.1/f2
    write /config/usb_gadget/g1/idVendor 0x18D1
    write /config/usb_gadget/g1/idProduct 0x4EE0
    write /config/usb_gadget/g1/configs/b.1/strings/0x409/configuration "fastboot"
    symlink /config/usb_gadget/g1/functions/ffs.fastboot /config/usb_gadget/g1/configs/b.1/f1
    write /config/usb_gadget/g1/UDC ${sys.usb.controller}
    setprop sys.usb.state ${sys.usb.config}

on property:sys.usb.config=mtp && property:sys.usb.configfs=1
    write /config/usb_gadget/g1/UDC "none"
    rm /config/usb_gadget/g1/configs/b.1/f1
    rm /config/usb_gadget/g1/configs/b.1/f2
    write /config/usb_gadget/g1/idVendor 0x2A70
    write /config/usb_gadget/g1/idProduct 0xF003
    write /config/usb_gadget/g1/configs/b.1/strings/0x409/configuration "mtp"
    symlink /config/usb_gadget/g1/functions/mtp.gs0 /config/usb_gadget/g1/configs/b.1/f1
    write /config/usb_gadget/g1/UDC ${sys.usb.controller}
    setprop sys.usb.state ${sys.usb.config}

on property:sys.usb.config=mtp,adb && property:sys.usb.configfs=1
    start adbd

on property:sys.usb.config=mtp,adb && property:sys.usb.ffs.ready=1 && property:sys.usb.configfs=1
    write /config/usb_gadget/g1/UDC "none"
    rm /config/usb_gadget/g1/configs/b.1/f1
    rm /config/usb_gadget/g1/configs/b.1/f2
    write /config/usb_gadget/g1/idVendor 0x2A70
    write /config/usb_gadget/g1/idProduct 0x9012
    write /config/usb_gadget/g1/configs/b.1/strings/0x409/configuration "mtp_adb"
    symlink /config/usb_gadget/g1/functions/mtp.gs0 /config/usb_gadget/g1/configs/b.1/f1
    symlink /config/usb_gadget/g1/functions/ffs.adb /config/usb_gadget/g1/configs/b.1/f2
    write /config/usb_gadget/g1/UDC ${sys.usb.controller}
    setprop sys.usb.state ${sys.usb.config}
"""
    text = text[:configfs_start] + configfs + text[configfs_end:]

    # The stock recovery policy blocks the kernel domain from reading the APEX
    # image staged on recovery tmpfs. Apply only that live rule synchronously
    # before class_start default; the OEM policy file stays byte-exact.
    class_anchor = "    class_start default\n"
    policy_command = (
        f'    exec u:r:recovery:s0 root root -- {APEX_POLICY_TOOL} --live "{APEX_POLICY_RULE}"\n'
    )
    if text.count(class_anchor) != 1:
        raise SystemExit("Hotdog stock default-class anchor is absent or duplicated")
    if APEX_POLICY_TOOL in text or APEX_POLICY_RULE in text:
        raise SystemExit("Hotdog stock init already contains the APEX policy hook")
    return text.replace(class_anchor, policy_command + class_anchor, 1)


def patch_qcom_usb(text: str) -> str:
    """Remove the second, unconditional owner of the configfs ADB binding."""

    trigger = """on property:sys.usb.ffs.ready=1
    mkdir /config/usb_gadget/g1/configs/b.1 0777 shell shell
    symlink /config/usb_gadget/g1/configs/b.1 /config/usb_gadget/g1/os_desc/b.1
    mkdir /config/usb_gadget/g1/configs/b.1/strings/0x409 0770 shell shell
    write /config/usb_gadget/g1/configs/b.1/strings/0x409/configuration "adb"
    symlink /config/usb_gadget/g1/functions/ffs.adb /config/usb_gadget/g1/configs/b.1/f1
    write /config/usb_gadget/g1/UDC ${sys.usb.controller}
"""
    if text.count(trigger) != 1:
        raise SystemExit("unexpected Qualcomm unconditional USB-ready trigger")
    return text.replace(
        trigger,
        "# Configfs binding is owned by the mode-specific routes in "
        "/system/etc/init/hw/init.rc.\n",
        1,
    )


def patch_linker_config(text: str) -> str:
    if "dir.twrp" in text or re.search(r"^\[twrp\]\s*$", text, re.MULTILINE):
        raise SystemExit("Hotdog stock linker config is already patched")
    recovery_dir = re.compile(r"^(dir\.recovery\s*=\s*/system/bin\s*)$", re.MULTILINE)
    if len(recovery_dir.findall(text)) != 1:
        raise SystemExit("Hotdog stock linker config lacks its unique recovery mapping")
    text = recovery_dir.sub(r"\1\ndir.twrp = /system/tw/bin", text)
    if not text.endswith("\n"):
        text += "\n"
    return text + (
        "\n[twrp]\n"
        "namespace.default.isolated = false\n"
        "namespace.default.search.paths = /system/tw/${LIB}:/system/${LIB}\n"
    )


def patch_dynamic_fstab(text: str, relative: str) -> str:
    lines = text.splitlines(keepends=True)
    newline = "\r\n" if "\r\n" in text else "\n"
    logical_positions: list[int] = []
    seen = set()
    for number, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        fields = stripped.split()
        if len(fields) < 5:
            continue
        flags = set(fields[-1].split(","))
        if "logical" in flags:
            logical_positions.append(number)
            seen.add(fields[0])
    required_stock = {"system", "vendor", "product", "my_product", "my_engineering"}
    if seen != required_stock:
        raise SystemExit(
            f"unexpected stock logical row set in {relative}: {sorted(seen)}"
        )

    insert_at = min(logical_positions)
    removed = set(logical_positions)
    generated = ["# TWRP logical partitions; OnePlus physical/recovery rows below are preserved." + newline]
    for partition, mount, filesystems in LOGICAL_ROWS:
        for filesystem in filesystems:
            options = "ro,barrier=1,discard" if filesystem == "ext4" else "ro"
            generated.append(
                f"{partition:<24} {mount:<16} {filesystem:<7} {options:<25} "
                f"wait,slotselect,logical{newline}"
            )

    output: list[str] = []
    for number, line in enumerate(lines):
        if number == insert_at:
            output.extend(generated)
        if number not in removed:
            output.append(line)
    result = "".join(output)

    active = []
    for line in result.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        fields = stripped.split()
        if len(fields) >= 5 and "logical" in fields[-1].split(","):
            active.append(fields)
    expected_count = sum(len(filesystems) for _, _, filesystems in LOGICAL_ROWS)
    if len(active) != expected_count:
        raise SystemExit(f"wrong logical-row count after patching {relative}")
    for partition, mount, filesystems in LOGICAL_ROWS:
        rows = [row for row in active if row[0] == partition and row[1] == mount]
        if [row[2] for row in rows] != list(filesystems):
            raise SystemExit(f"wrong filesystem alternatives for {partition} in {relative}")
        if any("slotselect" not in row[-1].split(",") for row in rows):
            raise SystemExit(f"{partition} lost slotselect in {relative}")
    return result


def append_unique_lines(text: str, lines: tuple[str, ...], heading: str) -> str:
    for line in lines:
        if line in text:
            raise SystemExit(f"entry is already patched: {line}")
    if not text.endswith("\n"):
        text += "\n"
    return text + f"\n# {heading}\n" + "\n".join(lines) + "\n"


def patch_adb_properties(text: str) -> str:
    replacements = {
        "ro.secure": "0",
        "ro.adb.secure": "0",
        "ro.debuggable": "1",
        "persist.sys.usb.config": "adb",
    }
    counts = {name: 0 for name in replacements}
    lines = text.splitlines(keepends=True)
    for number, line in enumerate(lines):
        stripped = line.rstrip("\r\n")
        if stripped.startswith("#") or "=" not in stripped:
            continue
        name, _value = stripped.split("=", 1)
        if name not in replacements:
            continue
        ending = line[len(stripped) :]
        lines[number] = f"{name}={replacements[name]}{ending}"
        counts[name] += 1
    if any(counts[name] < 1 for name in replacements):
        raise SystemExit(f"missing expected Hotdog stock ADB properties: {counts}")
    result = "".join(lines)
    if "ro.boot.dynamic_partitions=true" not in result:
        raise SystemExit("Hotdog dynamic-partition property was not preserved")
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--newc-dir", type=Path, required=True)
    parser.add_argument("--stock-cpio", type=Path, required=True)
    parser.add_argument("--twrp-cpio", type=Path, required=True)
    parser.add_argument("--firmware-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()

    sys.path.insert(0, str(args.newc_dir.resolve()))
    import newc  # noqa: PLC0415

    stock_entries = newc.read(args.stock_cpio)
    stock = newc.index(stock_entries)
    twrp = newc.index(newc.read(args.twrp_cpio))
    if len(stock_entries) != len(stock):
        raise SystemExit("stock CPIO contains duplicate paths")

    transforms = {
        "system/etc/init/hw/init.rc": patch_init,
        "init.recovery.qcom.rc": patch_qcom_usb,
        "system/etc/ld.config.txt": patch_linker_config,
        "etc/recovery.fstab": lambda text: patch_dynamic_fstab(text, "etc/recovery.fstab"),
        "system/etc/recovery.fstab": lambda text: patch_dynamic_fstab(
            text, "system/etc/recovery.fstab"
        ),
        "plat_file_contexts": lambda text: append_unique_lines(
            text, PRIVATE_CONTEXTS, "Private TWRP runtime"
        ),
        "system/etc/selinux/plat_file_contexts": lambda text: append_unique_lines(
            text, PRIVATE_CONTEXTS, "Private TWRP runtime"
        ),
        "system/etc/selinux/plat_service_contexts": lambda text: append_unique_lines(
            text, KEYSTORE_SERVICE_CONTEXTS, "Recovery Keystore2 compatibility services"
        ),
        "prop.default": patch_adb_properties,
    }

    overlay = []
    records = []
    for relative, transform in transforms.items():
        source = stock.get(relative)
        if source is None:
            raise SystemExit(f"missing required Hotdog stock entry: {relative}")
        target_data = transform(decode(relative, source.data)).encode("utf-8")
        if target_data == source.data:
            raise SystemExit(f"patch produced no change for {relative}")
        target = replace(source, data=target_data)
        overlay.append(target)
        records.append(
            {
                "kind": "replacement",
                "target": relative,
                "source_sha256": sha256(source.data),
                "target_sha256": sha256(target_data),
                "source_bytes": len(source.data),
                "target_bytes": len(target_data),
            }
        )

    additions = {
        "etc/twrp.flags": "system/etc/twrp.flags",
        # Stock init cannot replace its real /etc directory with /system/etc.
        # Put the A12 process-group configuration at the paths init reads.
        "etc/cgroups.json": "system/etc/cgroups.json",
        "etc/task_profiles.json": "system/etc/task_profiles.json",
        "system/etc/twrp.flags": "system/etc/twrp.flags",
        "system/etc/vintf/manifest/android.system.keystore2-service.xml": (
            "system/etc/vintf/manifest/android.system.keystore2-service.xml"
        ),
        "system/etc/selinux/plat_keystore2_key_contexts": (
            "system/etc/selinux/plat_keystore2_key_contexts"
        ),
        # This helper deliberately belongs to the preserved stock namespace.
        # The parent adapter proves its mappings before sending a credential;
        # relocating it under /system/tw makes that fail closed.
        STOCK_CREDENTIAL_HELPER: STOCK_CREDENTIAL_HELPER,
    }
    next_ino = max(entry.ino for entry in stock_entries) + 1
    for target_name, source_name in additions.items():
        if target_name in stock:
            raise SystemExit(f"Hotdog stock unexpectedly contains planned addition: {target_name}")
        source = twrp.get(source_name)
        if source is None:
            raise SystemExit(f"TWRP source is missing planned asset: {source_name}")
        if target_name == "etc/cgroups.json":
            config = json.loads(decode(source_name, source.data))
            controllers = {row["Controller"] for row in config.get("Cgroups", [])}
            required = {"blkio", "cpu", "cpuacct", "cpuset", "memory", "schedtune"}
            if controllers != required or config.get("Cgroups2", {}).get("Path") != "/dev/cg2_bpf":
                raise SystemExit("unexpected TWRP cgroups.json controller set")
        if target_name == "etc/task_profiles.json":
            profiles = json.loads(decode(source_name, source.data))
            if not profiles.get("Profiles") or not profiles.get("AggregateProfiles"):
                raise SystemExit("unexpected TWRP task_profiles.json")
        if target_name == STOCK_CREDENTIAL_HELPER:
            if source.mode & 0o170000 != 0o100000 or source.mode & 0o111 == 0:
                raise SystemExit("credential helper is not a regular executable")
            try:
                interpreter = elf_interpreter(source.data)
            except (UnicodeDecodeError, ValueError, struct.error) as exc:
                raise SystemExit(f"cannot validate credential-helper PT_INTERP: {exc}") from exc
            if interpreter != STOCK_INTERPRETER:
                raise SystemExit(
                    f"credential helper uses {interpreter!r}, expected {STOCK_INTERPRETER!r}"
                )
        added = replace(source, name=target_name, ino=next_ino)
        next_ino += 1
        overlay.append(added)
        record = {
            "kind": "addition",
            "source": source_name,
            "target": target_name,
            "target_sha256": sha256(added.data),
            "target_bytes": len(added.data),
        }
        if target_name == STOCK_CREDENTIAL_HELPER:
            record.update(
                {
                    "runtime": "stock_oos12",
                    "interpreter": STOCK_INTERPRETER,
                }
            )
        records.append(record)

    firmware_dir_name = "vendor/firmware"
    vendor_dir = stock.get("vendor")
    file_template = stock.get("system/etc/cgroups.json")
    if vendor_dir is None or vendor_dir.mode & 0o170000 != 0o040000:
        raise SystemExit("Hotdog stock lacks a vendor directory metadata template")
    if file_template is None or file_template.mode & 0o170000 != 0o100000:
        raise SystemExit("Hotdog stock lacks a regular-file metadata template")
    firmware_directory = stock.get(firmware_dir_name)
    if firmware_directory is not None:
        if firmware_directory.mode & 0o170000 != 0o040000:
            raise SystemExit("Hotdog stock vendor/firmware is not a directory")
    else:
        firmware_directory = replace(vendor_dir, name=firmware_dir_name, ino=next_ino)
        next_ino += 1
        overlay.append(firmware_directory)
        records.append(
            {
                "kind": "addition",
                "source": "stock:vendor metadata",
                "target": firmware_dir_name,
                "target_sha256": sha256(firmware_directory.data),
                "target_bytes": len(firmware_directory.data),
            }
        )
    for filename, (expected_bytes, expected_sha256) in FIRMWARE_FILES.items():
        source_path = args.firmware_dir / filename
        source_data = source_path.read_bytes()
        if len(source_data) != expected_bytes or sha256(source_data) != expected_sha256:
            raise SystemExit(f"Hotdog haptics firmware identity mismatch: {filename}")
        target_name = f"{firmware_dir_name}/{filename}"
        if target_name in stock:
            raise SystemExit(f"Hotdog stock unexpectedly contains {target_name}")
        firmware = replace(
            file_template,
            name=target_name,
            ino=next_ino,
            nlink=1,
            data=source_data,
        )
        next_ino += 1
        overlay.append(firmware)
        records.append(
            {
                "kind": "addition",
                "source": str(source_path.resolve()),
                "source_kind": "pinned_hotdog_a12_firmware",
                "target": target_name,
                "target_sha256": expected_sha256,
                "target_bytes": expected_bytes,
            }
        )

    keystore_rc_name = "system/etc/init/keystore2.rc"
    if keystore_rc_name in stock:
        raise SystemExit("Hotdog stock unexpectedly contains Keystore2 init")
    keystore_rc_source = twrp.get(keystore_rc_name)
    if keystore_rc_source is None:
        raise SystemExit("TWRP source is missing Keystore2 init")
    keystore_rc = decode(keystore_rc_name, keystore_rc_source.data)
    source_service = "service keystore2 /system/bin/keystore2 /tmp/misc/keystore"
    target_service = "service keystore2 /system/tw/bin/keystore2 /tmp/misc/keystore"
    if keystore_rc.count(source_service) != 1 or "    disabled" not in keystore_rc:
        raise SystemExit("unexpected TWRP Keystore2 service declaration")
    if re.search(r"^on\s+(?:late-init|boot)", keystore_rc, re.MULTILINE):
        raise SystemExit("Keystore2 init contains an unsafe automatic-start trigger")
    keystore_data = keystore_rc.replace(source_service, target_service, 1).encode("utf-8")
    keystore_entry = replace(
        keystore_rc_source, name=keystore_rc_name, ino=next_ino, data=keystore_data
    )
    overlay.append(keystore_entry)
    records.append(
        {
            "kind": "addition",
            "source": keystore_rc_name,
            "target": keystore_rc_name,
            "target_sha256": sha256(keystore_data),
            "target_bytes": len(keystore_data),
            "service_path": "/system/tw/bin/keystore2",
            "disabled": True,
        }
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    newc.write(args.output, overlay)
    roundtrip = newc.index(newc.read(args.output))
    if set(roundtrip) != {entry.name for entry in overlay}:
        raise SystemExit("Hotdog stock overlay path set changed on round-trip")
    for entry in overlay:
        if roundtrip[entry.name] != entry:
            raise SystemExit(f"Hotdog stock overlay mismatch after round-trip: {entry.name}")

    manifest = {
        "format": 1,
        "device": "hotdog",
        "partition_layout": "dynamic_ab_with_recovery_partition",
        "stock_cpio_sha256": sha256(args.stock_cpio.read_bytes()),
        "twrp_cpio_sha256": sha256(args.twrp_cpio.read_bytes()),
        "overlay_entry_count": len(overlay),
        "overlay_bytes": args.output.stat().st_size,
        "overlay_sha256": sha256(args.output.read_bytes()),
        "records": records,
    }
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(manifest, sort_keys=True))


if __name__ == "__main__":
    main()
