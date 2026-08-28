# OxygenOS 12 recovery baseline

This directory is the byte-pinned HD191x OxygenOS 12 recovery baseline used
by both the normal TWRP compile and the stock-first final-image packager.
It replaces the repository's 2021 OxygenOS 11 kernel, DTB, recovery-DTBO,
and recovery-root vendor binaries.

`recovery-header-v2.bin`, `kernel`, `ramdisk-stock.cpio.gz`,
`recovery-dtbo.img`, and `dtb.img` reconstruct the exact 77,979,648-byte
signed-image payload region of the source recovery. The OEM signature is not
reused after changing the ramdisk; CI adds an explicitly unsigned test AVB
hash footer and verifies it before publishing the artifact.

The CommonDCS library is extracted from the matching Hotdog OxygenOS 12 ODM
image. It supplies the one DT_NEEDED dependency absent from the stock recovery
ramdisk's cryptoeng service. Its digest is identical to the already audited
H.40 copy, but the checked-in file now has Hotdog ODM provenance.

`system/lib64/libkeystore-attestation-application-id.so` comes from the
audited OnePlus 7 Pro H.40 stock recovery. Hotdog's stock `gatekeeperd` and
the rest of its system-library closure are byte-identical to that H.40
runtime. This stock-era library replaces the A12-built copy whose newer
`RefBase` ABI made Hotdog's preserved `gatekeeperd` fail at process start.

The four `vendor/firmware` haptics files are pinned from the Hotdog A12
device tree at commit `8189a039c1c402d1bb0b433935f5b1fb72a81a27`. They are
packaged directly into the final stock-first ramdisk so the kernel can load
them before TWRP starts.

`vendor/lib64/libspl.so`, `vendor/lib64/libops.so`, and the latter's
`vendor/lib64/libdrm.so` dependency come from that same pinned Hotdog A12
commit. The packager installs identical copies into the stock `system/lib64`
and `vendor/lib64` search paths so optional QSEE listeners remain resolvable
both before and after TWRP mounts the dynamic vendor image. CI proves the full
`libops.so` SONAME and strong-symbol closure against the preserved OOS12
namespace instead of checking only its direct dependency names.
The compiled TWRP timezone database is also retained in the final ramdisk;
this removes the early Bionic timezone lookup failures without substituting
host data.

`vendor/lib64/libdisplayconfig.qti.so` is the Hotdog OxygenOS F.22 blob from
the pinned `arminask/android_device_oneplus_hotdog` blob-refresh commit. The
preserved stock `libsecureui.so` requires this proprietary implementation,
while CI builds its open `vendor.display.config@2.0` HIDL dependency. The
packager verifies the prebuilt's byte count, SHA-256, ELF class, SONAME, and
dependency edge before placing it in the stock linker namespace.

`tools/hotdog-apex-policy` is the arm64 `magiskpolicy` executable from the
official Magisk v30.7 APK, renamed for its single recovery-only purpose. The
stock OOS12 `sepolicy` file is never replaced: init uses this tool twice,
synchronously before starting the default service class. It adds
`allow kernel recovery fd use` for the loop descriptor passed from recovery
and `allow kernel tmpfs file read` for the kernel's subsequent read of the
tmpfs-backed APEX image. The source release, APK digest, executable digest,
exact rules, and preserved stock-policy digest are pinned in the build
manifests.
Magisk is GPLv3 software; corresponding source is available from the v30.7
release at https://github.com/topjohnwu/Magisk/releases/tag/v30.7.

All sizes, hashes, firmware identity, stock raw-ramdisk identity, and source
image identities are recorded in `manifest.json`. These are proprietary
OnePlus firmware components and remain subject to their original terms.
