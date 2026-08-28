# ColorOS 12 decryption source adapter

This directory carries the checksum-pinned source patches applied to the
pinned TWRP 12.1 recovery, vold, system/security, system/core, and Binder
snapshots. The final adapter includes parent-KeyStorage handling, malformed
`pKMblob` rejection, the recovery Keystore2 permission shim, the SDK-30 Binder
stability bridge, credential-time Keystore2 startup, and universal mounted
dynamic/static system-identity discovery.

The recovery and vold decryption patches, including the no-credential
supplements, are shared byte-for-byte with Guacamole. The credentialed
current-only installer detects either proven Oplus direct-AES
schema at runtime: the minimal `encrypted_key` plus `version` form, or the
legacy-`none` form with a nonzero 16 KiB `secdiscardable`. It revalidates the
same schema before key retrieval and rejects Keymaster blobs, links, malformed
or mixed layouts, extra files, and every key-directory mutation path.

The no-credential supplement never calls the crash-prone stock
`fscrypt_init_user0_ce()` export. It hands the default-password request to the
parent recovery process, validates the Keymaster-backed user-0 `current` key
schema twice, installs that key without changing the key directory, and then
requires filesystem policy/key-status proof before declaring CE decrypted.

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
| `recovery-no-credential.patch` | `bootable/recovery` | `a79e9a761ded5640f4413c48191fee3bc511e7eb15f316cbac8aa0f6b264298d` |
| `security.patch` | `system/security` | `0cd8269b20fa83fcfff42eee02a6a0be8a0d8a74bb2ee9baba8449dc26441523` |
| `task-profiles.patch` | `system/core` | `452deadb4638086f1487df59e853dbba2bf295ab63da983232f5e9477b70a364` |
| `vold.patch` | `system/vold` | `034b64defe6e7ff10b91e8948e0f2ac19da3a7f434bb03e9e6351fba283f2cda` |
| `vold-no-credential.patch` | `system/vold` | `ee2472e7bb81f320d2fd473cedadc3db2f475fd15551beb3c4948d73522e7199` |

The workflow verifies each checksum before applying it, checks the expected
changed path set, rejects legacy unsafe fallbacks, audits the linked ELFs, and
then hands the compiled ramdisk to the OOS12 stock-first stage.
