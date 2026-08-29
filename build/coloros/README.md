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

The no-credential supplements never call the crash-prone stock
`fscrypt_init_user0_ce()` export and avoid the stock password-type ABI when no
user-0 `.pwd` protector exists. They hand the default-password request to the
parent recovery process, validate the Keymaster-backed user-0 `current` key
schema twice, install that key without changing the key directory, and then
require filesystem policy/key-status proof before declaring CE decrypted.

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
| `recovery.patch` | `bootable/recovery` | `ccd7231d66b3599203c8fde236ec4f9ca90bab3118239d67f5547f3c0032dbe5` |
| `recovery-no-credential.patch` | `bootable/recovery` | `491f78e08921259749cc1333191ba12c0a73d86bf504822f1f445056870a24f5` |
| `recovery-password-probe.patch` | `bootable/recovery` | `91033f9fb2238c54bd88e0cb50f8d684e8ffcd3c3491ca9dba635d0688931b0f` |
| `recovery-setup-de-ce-guard.patch` | `bootable/recovery` | `214fb48a0372dfef489235ab693024a1a15dac7d676398883a51dfc781d53192` |
| `security.patch` | `system/security` | `0cd8269b20fa83fcfff42eee02a6a0be8a0d8a74bb2ee9baba8449dc26441523` |
| `task-profiles.patch` | `system/core` | `452deadb4638086f1487df59e853dbba2bf295ab63da983232f5e9477b70a364` |
| `vold.patch` | `system/vold` | `b1664fe7e29b500310e4e4fb6a3f108ddcbe399d50ce66497d58c3fc627b07dd` |
| `vold-no-credential.patch` | `system/vold` | `077d150773b512f110b202472e7a4558f4bc7171b5a992417523be0b6490e86b` |

The workflow verifies each checksum before applying it, checks the expected
changed path set, rejects legacy unsafe fallbacks, audits the linked ELFs, and
then hands the compiled ramdisk to the OOS12 stock-first stage.
