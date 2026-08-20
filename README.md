# Device Tree for OnePlus 7T Pro aka Hotdog for TWRP (this should be unified with 7T, but I cannot test since I do not own that device)
## Disclaimer - Unofficial TWRP!
These are personal test builds of mine. In no way do I hold responsibility if it/you messes up your device.
Proceed at your own risk.

### Note
2021-04-27:
Initial build which boots on OOS11 for 7T / Pro.
Decryption on OOS11 does not work. Might work on custom that uses OOS11 blobs.

## Android 12.1 test branch

The `codex/hotdog-a12-minimal` branch is a compile-only port to a guarded TWRP
12.1 source set. Its GitHub Actions workflow pins the manifest revision and the
critical source projects, records the complete resolved manifest, and builds
the dedicated `recoveryimage` target from the preserved prebuilt kernel, DTB,
and recovery-DTBO. It is only partially pinned, not a complete 253-project
lockfile. The minimal manifest omits CTS/VTS-only defaults, so the normal TWRP
missing-dependency mode is enabled while critical recovery files and image
components are checked explicitly.

Any Actions image is **untested**. Do not flash it based on a green build alone.
The current kernel lacks EROFS support, and ColorOS 12 encryption, proprietary
HAL compatibility, partition metadata, slot control, display, touch, and boot
remain device-test gates. See [PORT-NOTES.md](PORT-NOTES.md) for the exact scope
and fingerprints.

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
