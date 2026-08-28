# ColorOS 12 decryption source adapter

This directory carries the checksum-pinned source patches applied to the
pinned TWRP 12.1 recovery, vold, system/security, system/core, and Binder
snapshots. The final adapter includes parent-KeyStorage handling, malformed
`pKMblob` rejection, the recovery Keystore2 permission shim, the SDK-30 Binder
stability bridge, credential-time Keystore2 startup, and universal mounted
dynamic/static system-identity discovery.

Hotdog's current user-0 CE key uses the ColorOS direct-AES form with Android's
16 KiB `secdiscardable`. The current-only installer validates that exact
three-file layout before each read and still rejects Keymaster blobs, links,
extra files, and every key-directory mutation path.

The adapter is only one half of the result. `build/oos12/` packages its output
as a private runtime inside the exact Hotdog OxygenOS 12 stock recovery
ramdisk. This preserves OnePlus init, VINTF, crypto services, SELinux material,
and proprietary files while avoiding symbol collisions between the stock and
TWRP namespaces.

## Pinned patch set

| Patch | Target project | SHA-256 |
|---|---|---|
| `binder.patch` | `frameworks/native` | `bc1398b4901403a33d7ad80a171ba95974ba2c938558bc10b69ff350e8850895` |
| `keystore-service.patch` | `bootable/recovery` | `29ef6a93de27f17dfb741cc3bf93eaf063cefacd739a8625e1c9b8e3f668156c` |
| `openaes.patch` | `bootable/recovery` | `be435c026ea0af8d979c71dde853f6920d68bab7a44a40a12b810e67da86a673` |
| `recovery.patch` | `bootable/recovery` | `c196b8bd497039ae9ec7587212d47e0fe105867982b4ee06a02bbe30507b464e` |
| `security.patch` | `system/security` | `0cd8269b20fa83fcfff42eee02a6a0be8a0d8a74bb2ee9baba8449dc26441523` |
| `task-profiles.patch` | `system/core` | `452deadb4638086f1487df59e853dbba2bf295ab63da983232f5e9477b70a364` |
| `vold.patch` | `system/vold` | `5a0596b99fcef595695b42eb35ef84eb2d7b84784e5dceb473a6543d8d427a06` |

The workflow verifies each checksum before applying it, checks the expected
changed path set, rejects legacy unsafe fallbacks, audits the linked ELFs, and
then hands the compiled ramdisk to the OOS12 stock-first stage.
