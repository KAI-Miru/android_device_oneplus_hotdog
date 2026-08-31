# ColorOS 12 decryption source adapter

This directory carries the checksum-pinned source patches applied to the
pinned TWRP 12.1 recovery, vold, system/security, system/core, and Binder
snapshots. The final adapter includes parent-KeyStorage handling, malformed
`pKMblob` rejection, the recovery Keystore2 permission shim, the SDK-30 Binder
stability bridge, credential-time Keystore2 startup, and universal mounted
dynamic/static system-identity discovery.

The shared recovery lifecycle patch also makes Format Data create ext4
userdata with the `encrypt`, `verity`, `quota`, and `project` features required
by Android. This does not depend on the host `mke2fs.conf` defaults.

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
| `apex-loop.patch` | `bootable/recovery` | `8cef6cf7c0c7ec6f9fe14d990c2fee488bfab78135efe40313723ab1c9c8e412` |
| `binder.patch` | `frameworks/native` | `bc1398b4901403a33d7ad80a171ba95974ba2c938558bc10b69ff350e8850895` |
| `keystore-service.patch` | `bootable/recovery` | `29ef6a93de27f17dfb741cc3bf93eaf063cefacd739a8625e1c9b8e3f668156c` |
| `openaes.patch` | `bootable/recovery` | `be435c026ea0af8d979c71dde853f6920d68bab7a44a40a12b810e67da86a673` |
| `recovery.patch` | `bootable/recovery` | `ccd7231d66b3599203c8fde236ec4f9ca90bab3118239d67f5547f3c0032dbe5` |
| `recovery-no-credential.patch` | `bootable/recovery` | `620c17e844a76c9257fba0c1f1df1f50f617381c6e79acec5c0ad2960e58cf72` |
| `recovery-password-probe.patch` | `bootable/recovery` | `91033f9fb2238c54bd88e0cb50f8d684e8ffcd3c3491ca9dba635d0688931b0f` |
| `recovery-setup-de-ce-guard.patch` | `bootable/recovery` | `214fb48a0372dfef489235ab693024a1a15dac7d676398883a51dfc781d53192` |
| `recovery-fast-startup.patch` | `bootable/recovery` | `f064ae92c4dfbea09b6864072f0668034f38220c0d47874621c45a923f5b8bbc` |
| `recovery-data-lifecycle.patch` | `bootable/recovery` | `7e1fd8e0caa646d7795e0149710daba703f30f4322e6c047ef02fd5107dad080` |
| `security.patch` | `system/security` | `0cd8269b20fa83fcfff42eee02a6a0be8a0d8a74bb2ee9baba8449dc26441523` |
| `task-profiles.patch` | `system/core` | `452deadb4638086f1487df59e853dbba2bf295ab63da983232f5e9477b70a364` |
| `vold.patch` | `system/vold` | `0e77fb79b487c3e3c37c39d433a2ed51b2c2748da2e92778bd81a15cb180cd9e` |
| `vold-no-credential.patch` | `system/vold` | `9d86b2154b43b04f74d9b52bd4d5ce214c8505153ee8061854f6d3199e324797` |

The workflow verifies each checksum before applying it, checks the expected
changed path set, rejects legacy unsafe fallbacks, audits the linked ELFs, and
then hands the compiled ramdisk to the OOS12 stock-first stage.
