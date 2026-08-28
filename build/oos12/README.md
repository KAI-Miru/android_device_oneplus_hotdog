# OOS12 stock-first image tooling

These dependency-free Python tools turn the normal compiled TWRP recovery
ramdisk into the final Hotdog image. The GitHub Actions workflow is the
canonical invocation and pins every source input.

- `assemble_stock_boot_v2.py` reconstructs and verifies the checked-in OOS12
  boot payload.
- `extract_boot_ramdisk.py`, `newc.py`, and `extract_newc_regulars.py` parse the
  boot/CPIO inputs without losing archive metadata.
- `make_hotdog_stock_overlay.py` makes the audited stock-side routing, fstab,
  context, property, USB, cgroup, haptics, and Keystore2 changes, and installs
  the credential helper unchanged in `/system/bin` so it uses the stock OOS12
  namespace.
- `make_private_twrp_overlay.py`, `h40_dlopen.py`, and `elf_audit.py` package
  the isolated TWRP runtime and prove its ELF/`dlopen` dependency closure.
- `make_hotdog_cryptoeng_overlay.py` verifies and installs the exact Hotdog
  ODM CommonDCS dependency.
- `make_hotdog_runtime_overlay.py` combines the pinned stock-compatible
  Gatekeeper attestation library and F.22 display implementation with the
  freshly built HIDL 2.0 interface, proves those strong-symbol closures plus
  the complete optional QSEE `libops.so` closure, and installs the live APEX
  policy tool.
- `merge_newc.py`, `gzip_deterministic.py`, and `repack_boot_v2.py` create the
  deterministic final boot payload.
- the pinned Android 12.1 `avbtool` adds/verifies the explicit test footer.
- `verify_hotdog_stock_first.py` independently checks stock preservation,
  manifests, decryption markers, fstab, boot components, partition size, and
  AVB structure.

The scripts fail closed on missing paths, hash drift, duplicate CPIO entries,
unexpected firmware layout, unresolved symbols, or component changes.
