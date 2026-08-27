# ColorOS decryption adapter

This directory contains the reviewed ColorOS 12 decryption source adapter
ported from the working Guacamole H.40 recovery to Hotdog's pinned TWRP 12.1
snapshot.

Hotdog remains a dynamic A/B device with a dedicated, slotted recovery
partition. None of Guacamole's static-A/B, recovery-as-boot, kernel, DTB,
DTBO, fstab, partition-size, or hybrid boot-ramdisk packaging is used here.

## Patch set

The four adapter patches are byte-identical to the final Guacamole set proven
by Actions run `33031812198` and retained by Guacamole cleanup commit
`6935cbc2602ffeefebcd40f0a53cf14b346d12a0`:

| Patch | Pinned project | SHA-256 |
|---|---|---|
| `recovery.patch` | `bootable/recovery` `5c3d206a5eeb3d446bcda8248a405a4b278bab5c` | `bb813e0dc3cfb4f08894178c33d2c237a1636e5e81de93221acae27196c72087` |
| `vold.patch` | `system/vold` `a164ba05c5fef288059774a776b2e6e1119957cf` | `bf99fa1bcd3c9c73fd94d0a554898df9711332b2dea87e8566a01f6f740be394` |
| `security.patch` | `system/security` `14737db1429b8eebc15568bc748b2cd79ccad5c2` | `0cd8269b20fa83fcfff42eee02a6a0be8a0d8a74bb2ee9baba8449dc26441523` |
| `binder.patch` | `frameworks/native` `89c808424fbce9e40c0d4e0d1920b3c64a191b7f` | `bc1398b4901403a33d7ad80a171ba95974ba2c938558bc10b69ff350e8850895` |

`openaes.patch` (`be435c026ea0af8d979c71dde853f6920d68bab7a44a40a12b810e67da86a673`)
and `task-profiles.patch`
(`452deadb4638086f1487df59e853dbba2bf295ab63da983232f5e9477b70a364`)
preserve the two fixes already proven by Hotdog Actions run `32399278297`.
`keystore-service.patch`
(`29ef6a93de27f17dfb741cc3bf93eaf063cefacd739a8625e1c9b8e3f668156c`)
adapts the
Guacamole hybrid-runtime behavior to a complete Hotdog recovery image: the
TWRP-built keystore2 stays in the recovery namespace, is disabled during early
boot, and is started explicitly by the adapter only after `/data` is mapped.
The device init file creates `/tmp/misc/keystore` before that start can occur.

## Runtime boundary

This repository intentionally does not copy Guacamole's stock H.40 ramdisk or
its device-specific proprietary files. A successful Actions build proves the
source adapter, patched Keystore2/Binder path, and Hotdog recovery-image layout.
It does not prove ColorOS decryption.

The first runtime-capable image still needs a hash-pinned Hotdog ColorOS 12
closure containing the OEM decrypt library and its exact dependencies plus the
matching cryptoeng service/init/VINTF material. Import that closure only from
the target Hotdog/Hotdogb/Hotdogg firmware being tested; do not silently reuse
Guacamole blobs. Until then, artifacts are marked `UNTESTED` and the workflow
records the missing OEM runtime as a device-test gate rather than pretending
the compile proves decryption.

## Maintenance rules

1. Keep the upstream project commits and every patch checksum pinned.
2. Update patches as reviewed final-state diffs, never as chronological script
   stacks.
3. Preserve Hotdog's dedicated recovery image and dynamic-partition assertions.
4. Fail closed if an adapter safety marker or malformed-key rejection disappears.
5. Never call an image runtime-ready until the exact OEM closure and a device
   decryption log both pass review.
