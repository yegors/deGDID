# Open Questions

Last updated: 2026-07-11

Living backlog. Resolve with source-backed evidence; distinguish a public negative
result from something that still needs a controlled lab capture.

## Tool completion / release hardening

For the supported unmanaged, single-user Windows 11 scope, completion means:

1. continuously block the DeviceAdd mint path; and
2. remove known active real Device PUID state with the canonical wipe.

General telemetry suppression, complete mapping of adjacent Microsoft endpoints, and
the exact Stokes URL-association sensor are **not** release gates.

- [x] Integrate canonical dual-stack hosts entries, auto-resolving dynamic-keyword
  FQDN firewall rules, and a separate outbound `wlidsvc` service rule. The current
  script verifies these layers and the mint path before mutation. This is
  implementation status, not longitudinal lab proof.
- [ ] Hold `ProtectedNoRealGdid` for at least 24 hours across multiple reboots with
  the current integrated rules; verify the DeviceAdd gate remains healthy and no
  known active real PUID appears. `EXP-G` has passed immediate Protect plus two
  reboots; the duration and remaining transitions are still running/pending.
- [x] Run `-Protect` against the real contaminated state shape: target-user LID,
  Property, Token/Tickets, machine residual cache, and related files. Interim
  `EXP-G` cleared that state and held through two reboots plus service/task
  triggers. Actual MSA UI/sign-in behavior remains optional compatibility work.
- [x] Narrow the advertised mutation scope to Windows 11 25H2/build 26200.
- [ ] Run the full closure matrix on Windows 11 24H2 before adding that build to
  the supported mutation contract.

## Generation

- [x] Confirm anonymous/local-account machine-level mint: after unblock, EXP-B
  produced the same `0018…` PUID in SYSTEM and `.DEFAULT` without MSA while HKCU
  remained empty. `[LAB]`
- [ ] Capture the full anonymous DeviceAdd path with ETW and a redacted raw SOAP
  response. EXP-B proved the outcome, not the complete wire schema.
- [x] Confirm whether `.DEFAULT` / SYSTEM `LID` can differ from interactive-user
  `LID`: they can; SYSTEM and `.DEFAULT` were populated while HKCU remained empty
  in EXP-B. `[LAB]`
- [ ] Exact XML fields returned today (`GlobalDeviceID` vs `DevicePUID` vs
  `HWPUIDFlipped`) on Win11 24H2/25H2 -> **narrowed:** build-26200 public-PDB
  analysis identifies
  `/S:Envelope/S:Body/ps:DeviceUpdatePropertiesResponse/HWPUIDFlipped`
  `[STATIC]`; a cited Autopilot capture shows `HWDeviceID` + `GlobalDeviceID`
  `[CITED-RE]`. A redacted response from each current consumer/anonymous flow is
  still needed before calling the complete schema stable.
- [ ] Whether DeviceAdd hardware components enable a server-side link across
  reinstalls, and how strong that link is -> cited captures include EKPub, SMBIOS
  serial, OfflineDeviceID, and other hardware inputs `[CITED-RE]`. Autopilot shows
  that a *separate* backend can match its hardware hash after receiving a device
  token `[CITED-RE]`; that does not prove a GDID-backend join.

## Emission / court channel

- [ ] Which component associates GDID with arbitrary HTTPS destinations (SmartScreen? DiagTrack? web threat? other?) -> the court result proves an association existed `[COURT]`, but the public filing/report names no client, endpoint, or telemetry pipeline. Do not assign it to Edge, SmartScreen, DiagTrack, CDP, or DO without a capture.
- [x] Public retention answer for GDID IP / URL records -> **no GDID-specific duration is published.** Microsoft says retention varies by data/purpose and can be extended by legal preservation; its law-enforcement material describes process, not a GDID/IP/URL schedule `[MSDOC]`. Exact duration remains non-public.
- [ ] Whether Edge vs Chrome vs curl differ for MS-side association
- [ ] Whether DO download requests themselves carry GDID or only compliance snapshots do -> `UCDOStatus` proves a reporting snapshot contains `GlobalDeviceId` `[MSDOC]`; the public schema/API exposes neither Windows' built-in download headers nor a wire trace. Packet capture is still required.

## Network

- [x] Current live DDS host routing (configured-resolver snapshot, 2026-07-11) ->
  bare `dds.microsoft.com` returned no address; `cs.dds.microsoft.com` and
  `aad.cs.dds.microsoft.com` chain through Traffic Manager to Azure Front Door;
  `ztd.dds.microsoft.com` chains through Traffic Manager to an Autopilot Azure host
  `[LAB]`. Addresses are resolver/region dependent.
- [ ] Role of NXDOMAIN hosts still in `cdp.dll` (`fd.dds...`,
  `cdpcs.access...`) -> both returned NXDOMAIN in the current snapshot `[LAB]`;
  public role remains unknown beyond the static strings.
- [ ] Full list of token scopes that embed or require device PUID -> only DDS, Activity, and adjacent Live SSL scopes are evidenced so far; opaque tickets have not been decoded into a complete claim map.

## Token clients

- [x] `{67082621-8D18-4333-9C64-10DE93676363}` -> WebView2-associated IdentityCRL ticket: multiple independent cited sandbox traces show `msedgewebview2.exe` reading its `DeviceId`/`DeviceTicket` `[CITED-RE]`. Exact Entra app-registration display name is not public.
- [x] `{C89E2069-AF13-46DB-9E39-216131494B87}` -> CloudApp (CloudPlus) MSA client association: the IdentityCRL negative-cache entry is scoped to `tip.cloudapp.net` `[ASSESSED]`; it is not evidence of a Windows-inbox client.
- [x] `{F0C62012-2CEF-4831-B1F7-930682874C86}` -> Windows Store licensing / `WinStoreAuth`: debug output names `WinStoreAuth::AuthenticationInternal::SetMsaClientId` with this GUID `[STATIC]`.

## Policy / product

- [x] Post-Stokes Microsoft public statement (checked 2026-07-11) -> no GDID-specific Microsoft News/Docs/CSR statement, opt-out, or LE-retention explanation found. Public material remains the court representative description plus generic privacy/legal-process policy `[ASSESSED]`.
- [x] Enterprise policy knob for CDP ->
  `./Device/Vendor/MSFT/Policy/Config/Connectivity/AllowConnectedDevices=0`
  disables CDP after reboot `[MSDOC]`. The policy documentation does not attach
  the Autopilot Entra-sign-in warning to this setting.
- [x] Correct the Autopilot warning attribution -> Microsoft warns that
  **disabling the Microsoft Account Sign-in Assistant (`wlidsvc`)** during
  Autopilot pre-provisioning may hide the Entra sign-in option and lead to
  EULA/local-account setup `[MSDOC]`. The tool blocks `wlidsvc` outbound traffic,
  does not disable the service, makes no Autopilot-compatibility claim, and refuses
  managed-system mutation.
- [x] Interaction with Windows 11 Recall -> no public GDID/DDS linkage found. Microsoft documents Recall snapshots/AI as local-only, encrypted, opt-in, and not sent to Microsoft `[MSDOC]`; this does not prove unrelated Windows services stop emitting GDID.

## Countermeasure validation (lab - see `lab-playbook.md`)

- [x] **Prevent-at-install:** offline OOBE produced no LID on the lab VM
  (`EXP-A1`, build 26200/25H2, NIC disconnected, all LID paths empty,
  TokenKeys=0). `[LAB]`
- [x] **Pre-blocks before first online, short baseline:** Internet remained usable,
  `login.live.com` was hosts-blocked, no LID appeared, and LiveId logged
  `0x800704CF` (`EXP-A4`). `[LAB]` This does not close the 24-hour/reboot gate.
- [x] **Canonical wipe bundle under continuous blocks:** naive HKCU LID-only cleanup
  rehydrated in EXP-C2; the expanded Property + Token + LID + known-cache wipe stayed
  empty through the EXP-C3 reboot and short soak. `[LAB]`
- [ ] **C3 ablation:** run one-store-at-a-time snapshot experiments to determine
  whether `Immersive\production\Property\<LID>` is independently sufficient or
  necessary for rehydrate. Until then it is a required wipe-bundle member and
  high-confidence store, not a uniquely proven cause.
- [x] **Mutation direction:** wipe is canonical. Decoy remains experimental and
  carries no claim of server recognition or durable privacy.
- [x] **Windows Update** under registration blocks -> WU scan and Defender update
  worked; CU history showed blocked-period installs; LID stayed empty (`EXP-D`).
  `[LAB]`
- [ ] Controlled pending cumulative update and feature update under blocks ->
  optional compatibility coverage. EXP-D supports only a zero-pending scan,
  Defender update, and prior blocked-period history.
- [x] Breakage catalog -> desktop and WU were measured working; MSA network failure
  follows directly from blocking `login.live.com`. Store/Xbox/Phone Link auth
  failures remain expected, not fully exercised UI results (`EXP-E`).
- [x] Unblock after decoy / wipe -> nuanced (`EXP-F`): decoy was not instantly
  replaced and wipe+unblock did not auto-remint without a requesting client;
  eager remint remains demonstrated by `EXP-B`. `[LAB]`
- [x] First-mint control -> `EXP-B` covers the allow-DeviceAdd class from a
  never-minted image. Direct wipe-then-unblock remint remains separate and open.
- [x] Replace the stale IP-resolution/firewall-only draft with the current
  dual-stack hosts + dynamic FQDN + `wlidsvc` service-firewall integration.
  A no-hosts firewall-only mode is not the shipped contract and is not a release
  gate.
