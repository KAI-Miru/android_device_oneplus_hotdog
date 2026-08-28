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
APEX_POLICY_RULE = "allow kernel recovery fd use"


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

    # The stock recovery policy lacks the one cross-domain fd permission that
    # qti's loop worker needs. Apply only that live rule synchronously before
    # class_start default launches recovery; the OEM policy file stays exact.
    class_anchor = "    class_start default\n"
    policy_command = (
        f'    exec u:r:recovery:s0 root root -- {APEX_POLICY_TOOL} --live "{APEX_POLICY_RULE}"\n'
    )
    if text.count(class_anchor) != 1:
        raise SystemExit("Hotdog stock default-class anchor is absent or duplicated")
    if APEX_POLICY_TOOL in text or APEX_POLICY_RULE in text:
        raise SystemExit("Hotdog stock init already contains the APEX policy hook")
    return text.replace(class_anchor, policy_command + class_anchor, 1)


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
