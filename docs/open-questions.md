# Open Questions

Last updated: 2026-07-09

Living backlog. Resolve with lab evidence; then update `architecture.md` / `surfaces.md`.

## Generation

- [ ] Capture full anonymous (non-MSA) mint path on clean local-account VM (ETW + optional TLS metadata)
- [ ] Confirm whether `.DEFAULT` / SYSTEM `LID` can differ from interactive user `LID`
- [ ] Exact XML fields returned today (`GlobalDeviceID` vs `DevicePUID` vs `HWPUIDFlipped`) on Win11 24H2/25H2
- [ ] Whether DeviceAdd hardware components enable server-side link across reinstalls (and how strong)

## Emission / court channel

- [ ] Which component associates GDID with arbitrary HTTPS destinations (SmartScreen? DiagTrack? web threat? other?)
- [ ] Retention period for GDID IP / URL records
- [ ] Whether Edge vs Chrome vs curl differ for MS-side association
- [ ] Whether DO download requests themselves carry GDID or only compliance snapshots do

## Network

- [ ] Current live hosts behind `dds.microsoft.com` (CNAME/anycast) — bare A lookup was odd on lab
- [ ] Role of NXDOMAIN hosts still in `cdp.dll` (`fd.dds…`, `cdpcs.access…`) — legacy?
- [ ] Full list of token scopes that embed or require device PUID

## Token clients

- [ ] Identify `{67082621-…}`, `{C89E2069-…}`, `{F0C62012-…}`

## Policy / product

- [ ] Any post-Stokes Microsoft public statement on GDID, LE sharing, or opt-out
- [ ] Enterprise policy knobs that clear or suppress DDS registration without breaking Entra join
- [ ] Interaction with Windows 11 “recall” / other AI features (if any)

## Countermeasure validation (lab — see `lab-playbook.md`)

- [x] **Prevent-at-install:** offline OOBE → no LID until DeviceAdd? → **YES** on Lab VM (`EXP-A1`, build 26200/25H2, NIC disconnected, all LID paths empty, TokenKeys=0)
- [ ] **Pre-blocks before first online:** mint prevented while blocks hold?
- [ ] **Local-only rotate offline:** decoy/wipe sticks across reboot without net?
- [ ] **Local-only + registration blocks:** decoy not replaced by silent DeviceAdd?
- [ ] **Windows Update** under DeviceAdd/DDS blocks (WU allow-list intact)?
- [ ] Feature update keeps decoy if blocks hold?
- [ ] Breakage catalog: Store, MSA, CDP, activation
- [ ] Unblock after decoy → confirms forced server re-mint?
- [ ] Does GDID-Changer-style *online* rotate differ only by talking to MS? (control)
- [ ] Firewall-only minimum set with acceptable breakage
