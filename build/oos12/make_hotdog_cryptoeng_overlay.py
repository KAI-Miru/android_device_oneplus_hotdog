#!/usr/bin/env python3
"""Package the one missing stock cryptoeng dependency for Hotdog recovery."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import replace
from pathlib import Path


TARGET = "system/lib64/vendor.oplus.hardware.commondcs@1.0.so"
SERVICE = "system/bin/hw/vendor.oplus.hardware.cryptoeng@1.0-service"
SERVICE_SHA256 = "18f4eacc1a4fcd3fe125abb544c7742041f89de2802f041ee1b88da6c93fe79e"
SOURCE_SHA256 = "b626c790281f66279136437ca7065b5c0318462407c11c2a6ec2af04dc35e5a6"
SOURCE_BYTES = 76160
SOURCE_SYMBOL = (
    "_ZN6vendor5oplus8hardware9commondcs4V1_020ICommonDcsHalService10getService"
    "ERKNSt3__112basic_stringIcNS5_11char_traitsIcEENS5_9allocatorIcEEEEb"
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--newc-dir", type=Path, required=True)
    parser.add_argument("--elf-audit-dir", type=Path, required=True)
    parser.add_argument("--stock-cpio", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()

    sys.path.insert(0, str(args.newc_dir.resolve()))
    sys.path.insert(0, str(args.elf_audit_dir.resolve()))
    import newc  # noqa: PLC0415
    import elf_audit  # noqa: PLC0415

    stock_entries = newc.read(args.stock_cpio)
    stock = newc.index(stock_entries)
    if TARGET in stock:
        raise SystemExit(f"stock recovery already contains {TARGET}")
    service = stock.get(SERVICE)
    if service is None or sha256(service.data) != SERVICE_SHA256:
        raise SystemExit("Hotdog stock cryptoeng service identity mismatch")
    linker = stock.get("system/etc/ld.config.txt")
    if linker is None or b"namespace.default.search.paths = /system/${LIB}" not in linker.data:
        raise SystemExit("Hotdog stock cryptoeng service cannot search /system/lib64")

    source = args.source.read_bytes()
    if len(source) != SOURCE_BYTES or sha256(source) != SOURCE_SHA256:
        raise SystemExit("OnePlus ODM CommonDCS dependency identity mismatch")
    if source[:4] != b"\x7fELF" or service.data[:4] != b"\x7fELF":
        raise SystemExit("cryptoeng service or CommonDCS dependency is not ELF")

    source_elf = elf_audit.Elf(args.source)
    if source_elf.soname != "vendor.oplus.hardware.commondcs@1.0.so":
        raise SystemExit(f"unexpected CommonDCS SONAME: {source_elf.soname}")
    if SOURCE_SYMBOL not in source_elf.defined:
        raise SystemExit("CommonDCS does not export the cryptoeng service entry point")

    service_temp = args.output.with_suffix(".cryptoeng-service.elf")
    service_temp.parent.mkdir(parents=True, exist_ok=True)
    service_temp.write_bytes(service.data)
    try:
        service_elf = elf_audit.Elf(service_temp)
    finally:
        service_temp.unlink(missing_ok=True)
    if source_elf.soname not in service_elf.needed:
        raise SystemExit("stock cryptoeng service does not declare CommonDCS as DT_NEEDED")
    if SOURCE_SYMBOL not in service_elf.undefined:
        raise SystemExit("stock cryptoeng service does not import the CommonDCS entry point")

    template = stock.get("system/lib64/vendor.oplus.hardware.cryptoeng@1.0.so")
    if template is None:
        raise SystemExit("stock recovery lacks a suitable OEM library metadata template")
    entry = replace(
        template,
        name=TARGET,
        ino=max(item.ino for item in stock_entries) + 100,
        nlink=1,
        data=source,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    newc.write(args.output, [entry])
    if newc.index(newc.read(args.output)).get(TARGET) != entry:
        raise SystemExit("CommonDCS overlay changed on round-trip")

    manifest = {
        "format": 1,
        "device": "hotdog",
        "source": str(args.source.resolve()),
        "source_bytes": len(source),
        "source_sha256": sha256(source),
        "source_soname": source_elf.soname,
        "target": TARGET,
        "service": SERVICE,
        "service_sha256": sha256(service.data),
        "service_dt_needed": service_elf.needed,
        "required_symbol": SOURCE_SYMBOL,
        "symbol_import_export_verified": True,
        "overlay_sha256": sha256(args.output.read_bytes()),
    }
    args.manifest.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(manifest, sort_keys=True))


if __name__ == "__main__":
    main()
