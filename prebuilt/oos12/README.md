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

All sizes, hashes, firmware identity, stock raw-ramdisk identity, and source
image identities are recorded in `manifest.json`. These are proprietary
OnePlus firmware components and remain subject to their original terms.
