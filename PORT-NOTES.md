# Hotdog OxygenOS 12 stock-first port notes

## Why the repository changed

The previous Android 12.1 source port still packaged a 2021 OxygenOS 11
kernel, DTB, recovery-DTBO, and device-root proprietary set. Replacing only
the TWRP recovery executable could not make that boot foundation compatible
with OxygenOS/ColorOS 12 and led to Qualcomm CrashDump on target firmware.

The obsolete components have been removed. The branch now checks in the exact
OOS12 boot-v2 components and stock ramdisk used by the locally verified
stock-first image. The final artifact is assembled in CI rather than requiring
a second local repack.

## Preserved Hotdog layout

- dynamic A/B logical partitions with `slotselect`;
- a dedicated, slotted `recovery` partition;
- Android boot header version 2 with 4096-byte pages;
- a 100,663,296-byte recovery partition;
- separate stock OOS12 kernel, recovery-DTBO, and DTB components;
- device identities for the 7T, 7T Pro, and 7T Pro 5G family.

This deliberately does not copy Guacamole's static-A/B recovery-as-boot
packaging. Only the reviewed ColorOS source adapter and generic private-runtime
builder are shared concepts.

## Stock-first construction

CI reconstructs the exact OOS12 recovery boot payload from the files described
by `prebuilt/oos12/manifest.json`. It decompresses the stock and compiled TWRP
ramdisks without a filesystem round trip, then builds four deterministic
newc overlays:

1. stock-side routing, dynamic fstab, USB, cgroup, haptics, SELinux context,
   Keystore2, and TWRP flag changes;
2. the private TWRP executables, resources, linker, recursive ELF closure, and
   the exact five-file Oplus decrypt load group;
3. the Hotdog ODM CommonDCS library required by the stock cryptoeng service;
4. the stock Gatekeeper/Secure UI closure and the narrowly scoped live APEX
   policy rule.

Every unpatched stock CPIO entry must remain byte-and-metadata identical.
The verifier rejects duplicate paths, missing closure members, unresolved
strong symbols, altered OnePlus VINTF/crypto sentinels, invalid dynamic fstab
rows, missing adapter markers, unexpected boot-header changes, component drift,
partition-size drift, and malformed AVB data.

## OxygenOS 12 fingerprints

| Component | Bytes | SHA-256 |
|---|---:|---|
| source stock recovery image | 100,663,296 | `3a776605346aca4e5e98f588e72a68cd38f8f01c782f573ff3efd26b93389916` |
| stock boot payload | 77,979,648 | `c4c38d24caebf0e7d64754b0f5ac58651496a85359dda0e4ba327385998d7790` |
| kernel | 40,142,864 | `4b435ff44ed87d45a334f071d0af59f8579e8d0ac70ddd1bc4cdbf8ac39b2d6a` |
| recovery-DTBO | 5,165,936 | `7187d1e64e79b1a9416b1fb332ef8d670cc59ad6dcacc6864db2ed2eec0fd5b7` |
| DTB | 12,168,729 | `558825c788f86b64927ca1c254db8876d4d54a27d067db3ba8b53f1543a28618` |
| stock gzip ramdisk | 20,489,437 | `97449f9d692985bd44305bd23fe59db34a3d26711d6aea25f4dc4b8398546aed` |
| stock raw CPIO | 58,282,496 | `7fe6263a5cc654b363ef010a3b140ea404393dbf992ca0580156357d6e7c46d0` |
| Hotdog ODM CommonDCS | 76,160 | `b626c790281f66279136437ca7065b5c0318462407c11c2a6ec2af04dc35e5a6` |

The source recovery reports Android 12, security patch `2022-12-05`, and
fingerprint
`qti/msmnile/msmnile:12/SKQ1.210216.001/1676623833591:user/release-keys`.

## Validation boundary

A green workflow proves deterministic construction, source markers, binary
dependency closure, OOS12 component identity, stock-file preservation, image
layout, and a structurally valid test AVB footer. It does not replace a real
device test of boot, display/touch, `/data` decryption, MTP, sideload,
fastbootd, slot handling, or safe flashing. The published image therefore
retains the `DEVICE-TEST` label until those checks are recorded on hardware.
