# Device Tree for OnePlus 7T Pro aka Hotdog for TWRP (this should be unified with 7T, but I cannot test since I do not own that device)
## Disclaimer - Unofficial TWRP!
These are personal test builds of mine. In no way do I hold responsibility if it/you messes up your device.
Proceed at your own risk.

### Note
2021-04-27:
Initial build which boots on OOS11 for 7T / Pro.
Decryption on OOS11 does not work. Might work on custom that uses OOS11 blobs.

## Android 12.1 ColorOS branch

`android-12.1-latest-snapshot` is the maintained TWRP 12.1 branch. It preserves
Hotdog's dynamic A/B logical partitions and dedicated, slotted recovery image;
it does not use Guacamole's static-A/B recovery-as-boot packaging.

The branch ports the reviewed Guacamole ColorOS 12 decryption source adapter,
including the final parent-KeyStorage, malformed-`pKMblob`, Keystore2 recovery
permission, and Binder stability fixes. Hotdog uses its TWRP-built Keystore2
directly, with a disabled credential-time service and an init-created temporary
database directory. The Guacamole hybrid-ramdisk private-runtime packager is
not used.

GitHub Actions pins the manifest and critical source projects, verifies every
patch checksum and safety marker, builds `recoveryimage`, uploads a compiled
payload immediately after a successful link, and then audits the final image,
ELFs, prebuilt kernel/DTB/recovery-DTBO, custom MiruMira splash, and partition
size.

Any Actions image is **untested**. The exact Hotdog ColorOS OEM decrypt library,
cryptoeng service, dependency closure, and VINTF material have not been imported
from target firmware, so a green compile is not proof of working decryption.
The current kernel also lacks EROFS support. See [PORT-NOTES.md](PORT-NOTES.md)
and [build/coloros/README.md](build/coloros/README.md) for the precise boundary.

#### Legacy Android 11 status
- [X] Flashing ROMs (AOSP and OOS)
- [X] ADB (+ sideload)
- [X] all important partitions listed in mount/backup lists
- [X] MTP export
- [X] decrypt /data - Only working for Custom A10 and A11 ROMs using OOS10 blobs
- [X] Backup to internal/microSD - Not working
- [X] Restore from internal/microSD - Not working
- [X] F2FS/EXT4 Support, exFAT/NTFS where supported
- [X] backup/restore to/from external (USB-OTG) storage
- [X] update.zip sideload
- [X] backup/restore to/from adb (https://gerrit.omnirom.org/#/c/15943/)

#### Not working - OxygenOS specific
- Decryption and probably everything that requires it

##### Credits
- CaptainThrowback for original trees.
- mauronofrio for original trees.
- TWRP team and everyone involved for their amazing work.
