# OnePlus Hotdog TWRP 12.1 — OxygenOS 12 stock-first ColorOS edition

This branch builds TWRP for the OnePlus 7T family (`hotdog`, `hotdogb`, and
`hotdogg`) as a dedicated recovery-partition image for dynamic A/B devices.
It is an unofficial test project; flashing remains at the tester's risk.

## Current build architecture

The repository no longer uses the 2021 OxygenOS 11 recovery foundation.
The kernel, DTB, recovery-DTBO, stock recovery ramdisk, and required ODM
CommonDCS dependency are exact, hash-pinned OxygenOS 12 components under
`prebuilt/oos12/`. The old device-root Qualcomm/OnePlus binary collection was
removed instead of being mixed with the newer firmware.

GitHub Actions performs two linked stages:

1. Build the pinned TWRP 12.1 source with the reviewed ColorOS decryption,
   parent-KeyStorage, Keystore2, and Binder compatibility patches.
2. Construct the final image from the OOS12 stock recovery ramdisk, preserve
   its OnePlus files, add only an audited private TWRP runtime and exact ELF
   dependency closure, repack it with the stock OOS12 boot components, add a
   test AVB footer, and independently verify the result.

The authoritative artifact is named
`hotdog-OOS12-stock-first-TWRP-ColorOS-DEVICE-TEST`. The earlier plain TWRP
build is retained only as a diagnostic/failsafe input to the stock-first stage.

## Partition and decryption model

Hotdog keeps its native layout: dynamic A/B logical partitions in `super`, a
dedicated slotted recovery partition, Android boot header v2, and a 96 MiB
recovery partition. System identity discovery supports both mounted dynamic
mapper devices and static by-name partitions, while failing closed when no
valid system identity is available.

The private runtime includes the exact recursive `DT_NEEDED` closure for TWRP
and the five stock Oplus decrypt libraries selected by the pinned manifest.
The stock cryptoeng service's missing CommonDCS dependency is taken from the
matching Hotdog OOS12 ODM image and checked at both the SONAME/symbol and hash
levels.

See [PORT-NOTES.md](PORT-NOTES.md),
[build/coloros/README.md](build/coloros/README.md), and
[prebuilt/oos12/README.md](prebuilt/oos12/README.md) for the validation and
provenance boundaries.

## Credits

TeamWin, CaptainThrowback, mauronofrio, the minimal-manifest maintainers, and
everyone whose OnePlus/Qualcomm recovery work this tree builds upon.
