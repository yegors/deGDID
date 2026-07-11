# Open Questions

Last updated: 2026-07-11

Living backlog. Resolve with source-backed evidence; distinguish a public negative
result from something that still needs a controlled lab capture.

## Generation

- [x] Capture full anonymous (non-MSA) mint path on clean local-account VM (ETW + optional TLS metadata) -> **partial:** EXP-B shows SYSTEM/`.DEFAULT` `0018` LID without MSA after unblock; full ETW/SOAP capture still open
- [x] Confirm whether `.DEFAULT` / SYSTEM `LID` can differ from interactive user `LID` -> **YES they can:** after control mint, SYSTEM=`.DEFAULT` present, HKCU still empty (`EXP-B`)
- [ ] Exact XML fields returned today (`GlobalDeviceID` vs `DevicePUID` vs `HWPUIDFlipped`) on Win11 24H2/25H2 -> **narrowed:** build-26200 PDB RE parses the Device PUID from `/S:Envelope/S:Body/ps:DeviceUpdatePropertiesResponse/HWPUIDFlipped` `[STATIC]`; an Autopilot DeviceAdd capture shows `HWDeviceID` + `GlobalDeviceID` `[OBSERVED]`. A redacted raw response from each current consumer/anonymous flow is still needed before calling the complete schema stable.
- [ ] Whether DeviceAdd hardware components enable server-side link across reinstalls (and how strong) -> DeviceAdd includes EKPub, SMBIOS serial, and OfflineDeviceID `[OBSERVED]`; Autopilot proves a *separate* MS backend can match its hardware hash after receiving the device token `[OBSERVED]`. That establishes correlation capability, **not** that the GDID backend performs the join or how reliable it is.

## Emission / court channel

- [ ] Which component associates GDID with arbitrary HTTPS destinations (SmartScreen? DiagTrack? web threat? other?) -> the court result proves an association existed `[COURT]`, but the public filing/report names no client, endpoint, or telemetry pipeline. Do not assign it to Edge, SmartScreen, DiagTrack, CDP, or DO without a capture.
- [x] Public retention answer for GDID IP / URL records -> **no GDID-specific duration is published.** Microsoft says retention varies by data/purpose and can be extended by legal preservation; its law-enforcement material describes process, not a GDID/IP/URL schedule `[MSDOC]`. Exact duration remains non-public.
- [ ] Whether Edge vs Chrome vs curl differ for MS-side association
- [ ] Whether DO download requests themselves carry GDID or only compliance snapshots do -> `UCDOStatus` proves a reporting snapshot contains `GlobalDeviceId` `[MSDOC]`; the public schema/API exposes neither Windows' built-in download headers nor a wire trace. Packet capture is still required.

## Network

- [x] Current live DDS host routing (configured-resolver snapshot, 2026-07-11) -> bare `dds.microsoft.com` returned no address; `cs.dds.microsoft.com` and `aad.cs.dds.microsoft.com` chain through Traffic Manager to Azure Front Door; `ztd.dds.microsoft.com` chains through Traffic Manager to an Autopilot Azure host `[OBSERVED]`. See `architecture.md`; addresses are resolver/region dependent.
- [ ] Role of NXDOMAIN hosts still in `cdp.dll` (`fd.dds...`, `cdpcs.access...`) - both still return NXDOMAIN `[OBSERVED]`; public role remains unknown beyond the static strings.
- [ ] Full list of token scopes that embed or require device PUID -> only DDS, Activity, and adjacent Live SSL scopes are evidenced so far; opaque tickets have not been decoded into a complete claim map.

## Token clients

- [x] `{67082621-8D18-4333-9C64-10DE93676363}` -> WebView2-associated IdentityCRL ticket: multiple independent sandbox traces show `msedgewebview2.exe` reading its `DeviceId`/`DeviceTicket` `[OBSERVED]`. Exact Entra app-registration display name is not public.
- [x] `{C89E2069-AF13-46DB-9E39-216131494B87}` -> CloudApp (CloudPlus) MSA client association: the IdentityCRL negative-cache entry is scoped to `tip.cloudapp.net` `[ASSESSED]`; it is not evidence of a Windows-inbox client.
- [x] `{F0C62012-2CEF-4831-B1F7-930682874C86}` -> Windows Store licensing / `WinStoreAuth`: debug output names `WinStoreAuth::AuthenticationInternal::SetMsaClientId` with this GUID `[STATIC]`.

## Policy / product

- [x] Post-Stokes Microsoft public statement (checked 2026-07-11) -> no GDID-specific Microsoft News/Docs/CSR statement, opt-out, or LE-retention explanation found. Public material remains the court representative description plus generic privacy/legal-process policy `[ASSESSED]`.
- [x] Enterprise policy knobs for DDS/CDP -> `./Device/Vendor/MSFT/Policy/Config/Connectivity/AllowConnectedDevices=0` disables CDP after reboot `[MSDOC]`. It is **not** a no-breakage Entra guarantee: Microsoft warns it can remove the Entra sign-in path in Autopilot pre-provisioning; deploy only after enrollment and pilot the required workflow.
- [x] Interaction with Windows 11 Recall -> no public GDID/DDS linkage found. Microsoft documents Recall snapshots/AI as local-only, encrypted, opt-in, and not sent to Microsoft `[MSDOC]`; this does not prove unrelated Windows services stop emitting GDID.

## Countermeasure validation (lab - see `lab-playbook.md`)

- [x] **Prevent-at-install:** offline OOBE -> no LID until DeviceAdd? -> **YES** on Lab VM (`EXP-A1`, build 26200/25H2, NIC disconnected, all LID paths empty, TokenKeys=0)
- [x] **Pre-blocks before first online:** mint prevented while blocks hold? -> **YES short soak** (`EXP-A4`: Internet OK, `login.live.com` hosts-blocked, no LID; LiveId `0x800704CF`)
- [x] **Local-only rotate offline:** decoy/wipe sticks across reboot without net? -> **Wipe cleared offline** (`EXP-C`); **post-wipe + blocks survives full VM reboot** (still no LID)
- [x] **Local-only + registration blocks:** decoy not replaced by silent DeviceAdd? -> **Mixed then fixed:** machine-hive wipe OK (`EXP-C`); naive HKCU wipe resurrected (`EXP-C2`); **expanded wipe (Immersive Property + Token + LID) + continuous blocks stays empty** (`EXP-C3`)
- [x] Identify HKCU LID rehydrate source -> **`Immersive\production\Property\<LID hex>`**; wipe in root `degdid.ps1`
- [x] **Windows Update** under DeviceAdd/DDS blocks -> **YES** scan + Defender update; CU history under blocks; LID stayed empty (`EXP-D`, also C2 step 0)
- [ ] Feature update (enablement package) under blocks - **deferred** (long disposable snap; CU path already validated)
- [x] Breakage catalog -> desktop/WU OK; MSA/LiveId broken expected; Store/Xbox/Phone Link auth expected fail (`EXP-E`)
- [x] Unblock after decoy / wipe -> **nuanced** (`EXP-F`): decoy not instantly replaced; wipe+unblock not auto-remint without DeviceAdd client; **eager** remint proven in `EXP-B`
- [x] Online server rotate (control) -> same class as EXP-B (allow `login.live.com` DeviceAdd); no opaque changer binary required
- [ ] Firewall-only minimum (no hosts) - **deferred**; hosts+firewall v0 set already validated for mint starve
