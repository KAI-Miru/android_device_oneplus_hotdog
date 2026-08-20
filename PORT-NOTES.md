# hotdog Android 12.1 minimal port notes

## Scope

This working tree starts from `KAI-Miru/android_device_oneplus_hotdog` commit
`55d7d4e2eadcbb3cc712cca069c03876273582d5` (`android-11`). It is a conservative
source uplift for a current TWRP Android 12.1 build check. It is **not** a
ColorOS 12-ready recovery and it contains no new device binaries.

The port deliberately preserves hotdog's device-specific packaging:

- dynamic A/B logical partitions in `super`;
- boot image header version 2 and the existing offsets;
- prebuilt `Image.gz`, separate DTB, and separate recovery-DTBO;
- a dedicated, slotted recovery partition (`TARGET_NO_RECOVERY := false`,
  `BOARD_RECOVERYIMAGE_PARTITION_SIZE`, and `TW_HAS_RECOVERY_PARTITION`);
- the existing super size, dynamic group, partition list, fstab, and TWRP flags.

It does not copy guacamole's static-A/B, recovery-as-boot, kernel, DTB, DTBO,
fstab, or partition sizes.

## Source-safe Android 12.1 changes

- Both Qualcomm device dependencies now select `android-12.1`.
- Recovery compatibility defaults use `PLATFORM_VERSION := 99.87.36` and set
  `PLATFORM_VERSION_LAST_STABLE`. These are build/decrypt compatibility values,
  not a claim about the installed phone OS.
- `qcom_decrypt` and `qcom_decrypt_fbe` are packaged for every build variant,
  rather than only `eng`.
- Android 11 ashmem modules, relink requests, and `ashmemd.rc` are removed.
  The obsolete HIDL-base and `libpcrecpp` relink requests are also removed;
  `libcap`, `libion`, and `libxml2` remain.
- The old boot-HAL wrapper requests and manual `libandroidicu` output-tree copy
  are removed. The remaining boot 1.0 service/implementation set matches the
  service started by device init; current TWRP packages health 2.1, which init
  starts as `health-hal-2-1`.
- Fastbootd uses `android.hardware.fastboot@1.1-impl-mock`, and the product
  explicitly builds a recovery image with shipping API level 29 (hotdog
  launched on Android 10). It keeps dynamic-partition support but explicitly
  disables constructing a `super.img` from the unverified legacy geometry.
- The custom configfs USB file is reduced to recovery's supported ADB and MTP
  compositions, resets both ADB and MTP FunctionFS readiness, and removes the
  stale diagnostic/accessory/RNDIS compositions.
- Variant selection checks `ro.boot.project_codename` first and retains the two
  known numeric `ro.boot.project_name` fallbacks. `hotdogb`, `hotdog`, and
  `hotdogg` map to 7T, 7T Pro, and 7T Pro 5G respectively. An unknown device
  leaves the ROM/bootloader identity unchanged; no numeric 5G project ID is
  invented.
- The physical `system_a/b` and `vendor_a/b` recovery wipe list is removed. It
  is invalid and unsafe for logical partitions.
- The dormant `mount-dynamic-rw` service and script are removed; they disabled
  SELinux enforcement and attempted writable remounts despite never being
  started by the current tree.
- The A/B OTA list now includes the device-specific `odm`, `product`,
  `recovery`, and `vbmeta_system` partitions corroborated by the LineageOS 19
  hotdog tree. Actual ColorOS payload metadata remains the authority before
  any OTA or slot-write test.
- The boot-control service starts only after `/dev/block/bootdevice` exists.
- The known 5G modem/SPU partitions receive the same compatibility aliases as
  the Android 12 hotdog reference. Their source paths and OTA behavior remain
  part of the hotdogg device-test gate.
- Encrypted-backup exclusion is expressed as literal `true`. The pinned
  recovery snapshot has contradictory OpenAES conditionals, so CI applies a
  checksum-pinned three-hunk fix that makes `true` consistently exclude the
  library, command, and relink request.
- The pinned recovery also requires a `task_recovery_profiles.json` module that
  its pinned system/core tree does not define. CI adds that recovery-only module
  using system/core's own Android 12 `task_profiles.json`; the stale Android 11
  device-root copy is no longer treated as the module definition.
- The recovery image is capped at the conservative 96 MiB size corroborated by
  the newer hotdog tree until the physical ColorOS recovery partition is read
  from a device. Screen blanking uses the panel-safe brightness path (maximum
  1023, default 200) instead of a framebuffer blank that the Android 12
  reference reports can disable touch.
- Plain ADB gadget binding is left to current TWRP's core init rules. The
  device USB overlay retains only its MTP and compatibility compositions,
  avoiding a second action that unbound and rebound the same configfs link.
- Make lists have exact final entries without dangling continuations. Local
  `Android.bp`, `bootctrl/`, and `gpt-utils/` definitions remain because an
  exact duplicate replacement has not been proven in the resolved 12.1 tree.
- The obsolete debuggerd relink request was removed; current recovery no longer
  consumes its old variable name. All touched scripts are normalized to LF,
  and CI rejects carriage returns in the variant script before building.

## Deliberately unresolved runtime gates

These must be resolved from the exact target HD191x ColorOS 12 firmware or a
booted stock device before an image is treated as usable:

1. **Filesystem and encryption policy.** `recovery.fstab` is unchanged and
   remains ext4-only. Do not add EROFS/F2FS or alter metadata/FBE flags until
   `blkid` and the target vendor/odm fstab prove the filesystem types and every
   encryption option.
2. **Super metadata and OTA set.** The existing size `15032385536`, group
   `qti_dynamic_partitions`, group size `6441926656`, logical partition list,
   and expanded A/B OTA list are still target-firmware-unverified. Reconcile
   them with payload metadata or on-device `lpdump`; do not infer them from
   guacamole.
3. **Kernel and image components.** The unchanged 2021 recovery kernel is known
   not to provide EROFS support. Replace it only with a hotdog-valid,
   source-pinned kernel plus matching DTB/DTBO after checking EROFS, Unicode,
   fscrypt, inline encryption, dm-default-key, ext4, and F2FS support.
4. **Proprietary ABI and VINTF.** No Keymaster, Gatekeeper, QSEE, Oplus crypto,
   boot-control, display, or VINTF files were added or replaced. Import only a
   complete, hash-pinned closure from the exact target firmware. Existing
   VINTF enforcement remains a build/runtime gate, not proof of compatibility.
5. **5G numeric identity.** `hotdogg` codename handling is present, but the
   stock numeric 5G project ID remains unknown and intentionally unsupported.
6. **Boot-control definitions.** A full resolved-source build must check for
   duplicate `bootctrl.msmnile`/`libgptutils` definitions. Remove the local
   definitions only if the selected 12.1 common trees provide identical module
   names and behavior.

## Preserved file fingerprints

The port does not change these files:

| File | Bytes | SHA-256 |
|---|---:|---|
| `prebuilt/Image.gz` | 39,518,224 | `5cce136f5ebcede8ac03ae896dc64dc160c30c9ead981ae52d586e3598f578be` |
| `prebuilt/dtb.img` | 4,255,822 | `5fe452d09b59cf169662a0ec1f25a8d4ac9cd217852a28c8908a5b5c3860ad5a` |
| `prebuilt/dtbo.img` | 16,216,914 | `bd9640691f9d543204deb107e92de4f8ecf117e52d79b79cead8de031450d465` |
| `recovery.fstab` | 3,349 | `d932006aece65ed8a4445f64ee7d488232cb29f0b1ce2582fee501ce168e08dc` |
| `recovery/root/system/etc/twrp.flags` | 1,774 | `ce7bb5c2878af10e1881d87f2b93cae7d45b12577951372131e2a5087ef267e6` |

## Validation boundary

Local static validation completed successfully:

- `git diff --check`;
- Makefile continuation checks (no list continues into a blank/comment or EOF);
- JSON parsing of `twrp.dependencies`;
- `sh -n` for `unified-script.sh`;
- five-column parsing of all eight non-comment `recovery.fstab` rows, including
  `logical` on every OS logical-partition row;
- basic field parsing of every non-comment `twrp.flags` row;
- structural checks of both recovery init files and exact boot/health service
  name matching against the current TWRP 12.1 init definitions;
- assertions for dynamic A/B, header v2, dedicated recovery, and unchanged
  kernel/DTB/DTBO/fstab fingerprints;
- absence of the removed wipe list and Android 11 ashmem references.
- strict dependency resolution (CI does not set
  `ALLOW_MISSING_DEPENDENCIES`) plus checksum and path validation of the two
  pinned snapshot compatibility patches.

This local patch is intended for a GitHub Actions compile-only gate against a
pinned TWRP 12.1 snapshot. No recovery image was built or tested here. A
successful compile would prove source compatibility only; it would not prove
mounting, decryption, display/touch, slot switching, fastbootd, or safe flashing.

First device testing must be non-destructive. Prefer temporary boot only where
the bootloader supports it; otherwise back up both recovery slots first. Do not
format, wipe, change slots, run Fix Contexts, or write `/data` during the first
mount/decrypt investigation.
