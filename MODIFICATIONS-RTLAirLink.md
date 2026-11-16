# Modifications — 2026-11-15

This is the RTLAirLink distribution of the experimental Owly development work, derived from AirPort_RTW89 and the projects listed in CREDITS.md. Original notices are retained. The version names identify development snapshots, not stability guarantees.

## Inherited development changes

The source snapshot contains macOS compatibility work and guarded native AWDL interface/service lifecycle, peer admission, frame codec/queues, radio TX/RX handling, shared-channel scheduling and a Lilu Legacy event/client bridge. Earlier development added the native GET154 HT capability path. These are changes to the upstream port, not functionality claimed to exist unchanged upstream.

Changes dated 2026-11-15 affect these production files:

- `Source-Build/src/compat_rtw89/owly_awdl_peer.inc`: accept upstream success when static BlockAck CAM is exhausted on a dynamic-capable RTL8852B; retain real firmware errors and rollback. Use the reply gate for control responses; add peer MAC/response-delay diagnostics.
- `Source-Build/src/compat_rtw89/owly_native_link.c` and `.h`: add the confirmed-slot reply gate while retaining freshness/channel/pause/end-of-slot guards. The proactive Bonjour query gate retains its previous behavior.

The two regression cases failed on the preceding source and passed after the fixes. Host tests mock hardware/kernel boundaries; they are not RF or file-transfer evidence.

## Publication changes

- Rename the outer output directories: `AirPort_RTW89.kext` → `RTLAirLink.kext`, `OwlyAirLinkBridge.kext` → `RTLAirBridge.kext`.
- Retain internal executable names, identifiers, class names, the nested frontend name and boot-args.
- Add the standalone `build.py`/`build.sh` pipeline, documentation and release packaging. The build uses the same production flags and retains ABI/import checks and paired frontend UUID binding.
- Change `Bridge-Source/build_macos.sh` to call `tools/check_build_host.py`. This build-only platform/explicit-SDK gate allows source compilation without already having the developer's Owly cohort loaded. Production runtime guards are unchanged. The previous check_host.py remains as research tooling and is not the public entry point.
- Add dated comments to the three BlockAck-related production files without changing executable logic. Original research snapshot hashes, before these publication changes, are recorded in UPSTREAM_SNAPSHOT_SHA256.json.
- Exclude personal diagnostics, packet captures, EFI/configuration and Apple system binaries from the distribution. Dependency source, original notices and unchanged firmware remain included.

Requested display branding also updates CFBundleName/CFBundleDisplayName in all three Info.plists, newModelString in backend/frontend (retaining the detected chip), APPLE80211_IOC_DRIVER_VERSION text, and the bridge VersionInfo property. These display changes are dated inline. Hardware-version reporting, vendor, class and bundle identifiers remain unchanged. System Information display must still be checked after booting the published binaries.

## Version metadata correction — 2026-11-15

Rebuilt v0.1.0 at the owner's request to replace the initially published archives. The Wi-Fi System Information string, backend/frontend/bridge bundle versions, module descriptors and bridge status now all report 0.1.0. Shared version headers keep display and module strings aligned; the builder rejects inconsistent source metadata and compiled module descriptors. The bridge is rebound to the newly compiled frontend UUID. Network behavior and bundle identifiers are unchanged. Release and package digests change; use the current checksums and replace both kexts together.
