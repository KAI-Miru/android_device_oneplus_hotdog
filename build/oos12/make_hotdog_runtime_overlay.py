#!/usr/bin/env python3
"""Package the stock-namespace and APEX-policy runtime fixes for Hotdog."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import replace
from pathlib import Path


STOCK_GATEKEEPER = "system/bin/gatekeeperd"
STOCK_GATEKEEPER_SHA256 = "72168b54f3e6320ac63dd76cca8b2d0b683395059c44324e55407d0ac5a1f69f"
STOCK_KEYSTORE_PARCELABLES = "system/lib64/libkeystore_parcelables.so"
STOCK_SECURE_UI = "system/lib64/libsecureui.so"
STOCK_SECURE_UI_SHA256 = "252659d0ddb364fd5948d26003696d757391635d4388523e1e439d5233eecb68"
STOCK_SEPOLICY = "sepolicy"
STOCK_SEPOLICY_BYTES = 1_231_343
STOCK_SEPOLICY_SHA256 = "7f710aaf27c6e855c4b33ec57349c18d527d485589b4b323c902222d127702b7"

POLICY_TARGET = "system/bin/hotdog_apex_policy"
POLICY_BYTES = 356_584
POLICY_SHA256 = "9837db9db475eb74b6715f081768cb6a1f2fb5a2b2ac15755686062501bace27"
POLICY_INTERPRETER = "/system/bin/linker64"
POLICY_RULE = "allow kernel tmpfs file read"
POLICY_SOURCE_APK_SHA256 = "e0d32d2123532860f97123d927b1bb86c4e08e6fd8a48bfc6b5bee0afae9ebd5"
POLICY_SOURCE_URL = "https://github.com/topjohnwu/Magisk/releases/tag/v30.7"

DISPLAYCONFIG_TARGET = "system/lib64/libdisplayconfig.qti.so"
DISPLAYCONFIG_BYTES = 105_768
DISPLAYCONFIG_SHA256 = "18b95c53abeb03ab67e8eadd2a2009730109a8f04302d37663176d906b806327"
DISPLAYCONFIG_SOURCE = (
    "arminask/android_device_oneplus_hotdog@"
    "6ab060ecd35d89511fb6cd9e1d33e0486bd017b0:"
    "recovery/root/vendor/lib64/libdisplayconfig.qti.so"
)

ATTESTATION_TARGET = "system/lib64/libkeystore-attestation-application-id.so"
ATTESTATION_BYTES = 76_904
ATTESTATION_SHA256 = "af002511be00e9400c4aab876a74a73b3c02f7246d2f0ba42de59d7a8ffab00b"
ATTESTATION_SOURCE = "OnePlus 7 Pro H.40 stock recovery ramdisk"
INCOMPATIBLE_REFBASE_SYMBOL = "_ZNK7android7RefBase22incStrongRequireStrongEPKv"

LIBRARIES = (
    {
        "role": "gatekeeper_closure",
        "source": ATTESTATION_SOURCE,
        "target": ATTESTATION_TARGET,
        "soname": "libkeystore-attestation-application-id.so",
        "pinned_prebuilt": "stock_attestation",
    },
    {
        "role": "secure_ui_closure",
        "source": DISPLAYCONFIG_SOURCE,
        "target": DISPLAYCONFIG_TARGET,
        "soname": "libdisplayconfig.qti.so",
        "pinned_prebuilt": "displayconfig",
    },
    {
        "role": "secure_ui_closure",
        "source": "system/lib64/vendor.display.config@2.0.so",
        "target": "system/lib64/vendor.display.config@2.0.so",
        "soname": "vendor.display.config@2.0.so",
    },
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def elf(path: Path, elf_audit):
    try:
        parsed = elf_audit.Elf(path)
    except (OSError, elf_audit.ElfError) as exc:
        raise SystemExit(f"cannot audit ELF {path}: {exc}") from exc
    require(parsed.bits == 64 and parsed.e_machine == 183, f"not AArch64 ELF64: {path}")
    return parsed


def build_namespace(stock_tree: Path, injected: dict[str, tuple[Path, object]], elf_audit):
    providers: dict[str, tuple[str, object]] = {}
    for path in sorted((stock_tree / "system/lib64").glob("*.so")):
        try:
            parsed = elf_audit.Elf(path)
        except (OSError, elf_audit.ElfError):
            continue
        providers[path.name] = (f"stock:{path.name}", parsed)
        if parsed.soname:
            providers[parsed.soname] = (f"stock:{path.name}", parsed)
    for target, (path, parsed) in injected.items():
        label = f"injected:{target}"
        providers[Path(target).name] = (label, parsed)
        if parsed.soname:
            providers[parsed.soname] = (label, parsed)
    return providers


def resolve_closure(root: Path, providers: dict[str, tuple[str, object]], elf_audit) -> dict:
    root_elf = elf(root, elf_audit)
    members = [root_elf]
    pending = list(root_elf.needed)
    visited: set[str] = set()
    chain: list[dict] = []
    unresolved: set[str] = set()
    while pending:
        soname = pending.pop(0)
        if soname in visited:
            continue
        visited.add(soname)
        provider = providers.get(soname)
        if provider is None:
            unresolved.add(soname)
            continue
        label, parsed = provider
        members.append(parsed)
        chain.append({"soname": soname, "provider": label, "needed": parsed.needed})
        pending.extend(parsed.needed)
    require(not unresolved, f"unresolved stock namespace closure for {root}: {sorted(unresolved)}")
    exports: set[str] = set()
    imports: set[str] = set()
    for parsed in members:
        exports.update(parsed.defined)
        imports.update(parsed.undefined_strong)
    unresolved_symbols = sorted(imports - exports)
    require(
        not unresolved_symbols,
        f"unresolved strong symbols in stock namespace closure for {root}: {unresolved_symbols}",
    )
    return {
        "root": str(root),
        "root_needed": root_elf.needed,
        "resolved_sonames": sorted(visited),
        "providers": chain,
        "unresolved": [],
        "strong_import_count": len(imports),
        "unresolved_strong_symbols": [],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--newc-dir", type=Path, required=True)
    parser.add_argument("--elf-audit-dir", type=Path, required=True)
    parser.add_argument("--stock-cpio", type=Path, required=True)
    parser.add_argument("--twrp-cpio", type=Path, required=True)
    parser.add_argument("--stock-tree", type=Path, required=True)
    parser.add_argument("--twrp-tree", type=Path, required=True)
    parser.add_argument("--gatekeeper-attestation", type=Path, required=True)
    parser.add_argument("--displayconfig", type=Path, required=True)
    parser.add_argument("--policy-tool", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()

    sys.path.insert(0, str(args.newc_dir.resolve()))
    sys.path.insert(0, str(args.elf_audit_dir.resolve()))
    import newc  # noqa: PLC0415
    import elf_audit  # noqa: PLC0415

    stock_entries = newc.read(args.stock_cpio)
    stock = newc.index(stock_entries)
    twrp = newc.index(newc.read(args.twrp_cpio))
    require(len(stock_entries) == len(stock), "stock CPIO contains duplicate paths")

    for name, digest in (
        (STOCK_GATEKEEPER, STOCK_GATEKEEPER_SHA256),
        (STOCK_SECURE_UI, STOCK_SECURE_UI_SHA256),
        (STOCK_SEPOLICY, STOCK_SEPOLICY_SHA256),
    ):
        require(name in stock, f"stock recovery is missing {name}")
        require(sha256(stock[name].data) == digest, f"stock identity mismatch: {name}")
    require(len(stock[STOCK_SEPOLICY].data) == STOCK_SEPOLICY_BYTES, "stock sepolicy size mismatch")
    require(STOCK_KEYSTORE_PARCELABLES in stock, "stock recovery lacks Keystore parcelables")

    policy = args.policy_tool.read_bytes()
    require(len(policy) == POLICY_BYTES and sha256(policy) == POLICY_SHA256, "APEX policy tool identity mismatch")
    policy_elf = elf(args.policy_tool, elf_audit)
    require(policy_elf.interpreter == POLICY_INTERPRETER, "APEX policy tool uses the wrong interpreter")
    require(set(policy_elf.needed) == {"libc.so", "libm.so", "libdl.so"}, "unexpected APEX policy tool closure")
    require(b"--live" in policy and b"--load FILE" in policy, "APEX policy tool lacks required command support")

    overlay = []
    records = []
    injected: dict[str, tuple[Path, object]] = {}
    next_ino = max(item.ino for item in stock_entries) + 100
    for spec in LIBRARIES:
        source_name = spec["source"]
        target_name = spec["target"]
        require(target_name not in stock, f"stock recovery already contains {target_name}")
        prebuilt_kind = spec.get("pinned_prebuilt")
        if prebuilt_kind == "stock_attestation":
            source_path = args.gatekeeper_attestation
            source_data = source_path.read_bytes()
            require(
                len(source_data) == ATTESTATION_BYTES
                and sha256(source_data) == ATTESTATION_SHA256,
                "stock-compatible gatekeeper attestation library identity mismatch",
            )
            source = stock[STOCK_KEYSTORE_PARCELABLES]
            source_kind = "pinned_oneplus_h40_stock"
        elif prebuilt_kind == "displayconfig":
            source_path = args.displayconfig
            source_data = source_path.read_bytes()
            require(
                len(source_data) == DISPLAYCONFIG_BYTES
                and sha256(source_data) == DISPLAYCONFIG_SHA256,
                "OOS12 F.22 displayconfig identity mismatch",
            )
            source = stock[STOCK_SECURE_UI]
            source_kind = "pinned_oos12_f22"
        else:
            source = twrp.get(source_name)
            require(source is not None, f"TWRP build is missing {source_name}")
            source_path = args.twrp_tree / source_name
            source_data = source.data
            source_kind = "twrp_build"
        parsed = elf(source_path, elf_audit)
        require(parsed.soname == spec["soname"], f"unexpected SONAME for {source_name}: {parsed.soname}")
        if not prebuilt_kind:
            require(source_path.read_bytes() == source.data, f"TWRP tree/CPIO mismatch: {source_name}")
        if prebuilt_kind == "stock_attestation":
            require(
                INCOMPATIBLE_REFBASE_SYMBOL not in parsed.undefined_strong,
                "attestation library still requires the incompatible Android 12 RefBase ABI",
            )
        target = replace(source, name=target_name, ino=next_ino, nlink=1, data=source_data)
        next_ino += 1
        overlay.append(target)
        injected[target_name] = (source_path, parsed)
        records.append(
            {
                "kind": "addition",
                "role": spec["role"],
                "source": source_name,
                "source_kind": source_kind,
                "target": target_name,
                "target_bytes": len(target.data),
                "target_sha256": sha256(target.data),
                "soname": parsed.soname,
                "dt_needed": parsed.needed,
            }
        )

    parcelables = elf(args.stock_tree / STOCK_KEYSTORE_PARCELABLES, elf_audit)
    require(
        "libkeystore-attestation-application-id.so" in parcelables.needed,
        "stock Keystore parcelables no longer require the injected library",
    )
    secure_ui = elf(args.stock_tree / STOCK_SECURE_UI, elf_audit)
    require("libdisplayconfig.qti.so" in secure_ui.needed, "stock Secure UI no longer requires displayconfig")
    display = injected["system/lib64/libdisplayconfig.qti.so"][1]
    require("vendor.display.config@2.0.so" in display.needed, "displayconfig no longer requires HIDL 2.0")

    providers = build_namespace(args.stock_tree, injected, elf_audit)
    closures = {
        "gatekeeper": resolve_closure(args.stock_tree / STOCK_GATEKEEPER, providers, elf_audit),
        "secure_ui": resolve_closure(args.stock_tree / STOCK_SECURE_UI, providers, elf_audit),
    }

    template = stock.get("system/bin/toybox")
    require(template is not None and template.mode & 0o111, "stock recovery lacks an executable metadata template")
    policy_entry = replace(
        template,
        name=POLICY_TARGET,
        ino=next_ino,
        nlink=1,
        mode=(template.mode | 0o755),
        data=policy,
    )
    overlay.append(policy_entry)
    records.append(
        {
            "kind": "addition",
            "role": "apex_loop_policy",
            "source": str(args.policy_tool.resolve()),
            "target": POLICY_TARGET,
            "target_bytes": len(policy),
            "target_sha256": sha256(policy),
            "interpreter": policy_elf.interpreter,
            "dt_needed": policy_elf.needed,
        }
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    newc.write(args.output, overlay)
    roundtrip = newc.index(newc.read(args.output))
    require(set(roundtrip) == {item.name for item in overlay}, "runtime overlay path set changed on round-trip")
    for entry in overlay:
        require(roundtrip[entry.name] == entry, f"runtime overlay mismatch after round-trip: {entry.name}")

    manifest = {
        "format": 1,
        "device": "hotdog",
        "stock_cpio_sha256": sha256(args.stock_cpio.read_bytes()),
        "twrp_cpio_sha256": sha256(args.twrp_cpio.read_bytes()),
        "records": records,
        "stock_namespace_closures": closures,
        "displayconfig": {
            "source": DISPLAYCONFIG_SOURCE,
            "bytes": DISPLAYCONFIG_BYTES,
            "sha256": DISPLAYCONFIG_SHA256,
            "target": DISPLAYCONFIG_TARGET,
        },
        "gatekeeper_attestation": {
            "source": ATTESTATION_SOURCE,
            "bytes": ATTESTATION_BYTES,
            "sha256": ATTESTATION_SHA256,
            "target": ATTESTATION_TARGET,
            "incompatible_refbase_symbol_absent": True,
        },
        "apex_policy": {
            "mode": "synchronous_live_additive_before_default_class",
            "rule": POLICY_RULE,
            "target": POLICY_TARGET,
            "tool_sha256": POLICY_SHA256,
            "tool_source_release": POLICY_SOURCE_URL,
            "tool_source_apk_sha256": POLICY_SOURCE_APK_SHA256,
            "stock_sepolicy_preserved": True,
            "stock_sepolicy_bytes": STOCK_SEPOLICY_BYTES,
            "stock_sepolicy_sha256": STOCK_SEPOLICY_SHA256,
        },
        "overlay_entry_count": len(overlay),
        "overlay_bytes": args.output.stat().st_size,
        "overlay_sha256": sha256(args.output.read_bytes()),
    }
    args.manifest.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(manifest, sort_keys=True))


if __name__ == "__main__":
    main()
