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

`vendor/lib64/libdisplayconfig.qti.so` is the Hotdog OxygenOS F.22 blob from
the pinned `arminask/android_device_oneplus_hotdog` blob-refresh commit. The
preserved stock `libsecureui.so` requires this proprietary implementation,
while CI builds its open `vendor.display.config@2.0` HIDL dependency. The
packager verifies the prebuilt's byte count, SHA-256, ELF class, SONAME, and
dependency edge before placing it in the stock linker namespace.

`tools/hotdog-apex-policy` is the arm64 `magiskpolicy` executable from the
official Magisk v30.7 APK, renamed for its single recovery-only purpose. The
stock OOS12 `sepolicy` file is never replaced: init uses this tool once, before
starting the default service class, to add `allow kernel recovery fd use` for
the qti loop worker. The source release, APK digest, executable digest, exact
rule, and preserved stock-policy digest are pinned in the build manifests.
Magisk is GPLv3 software; corresponding source is available from the v30.7
release at https://github.com/topjohnwu/Magisk/releases/tag/v30.7.

All sizes, hashes, firmware identity, stock raw-ramdisk identity, and source
image identities are recorded in `manifest.json`. These are proprietary
OnePlus firmware components and remain subject to their original terms.
