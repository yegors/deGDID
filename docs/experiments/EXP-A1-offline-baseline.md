# EXP-A1 — Offline OOBE, never online (baseline)

Date: 2026-07-09  
VM: Hyper-V lab guest (Win11)  
Guest account: local-only (no MSA); hostname redacted for publish  
Status: **`[OBSERVED]` GDID-only offline baseline**

## Setup

- OOBE with `BYPASSNRO` → local account only
- NIC **always disabled** / disconnected through install
- Checkpoint taken after first desktop

## Inspect (redacted)

Raw inspect dump not committed. Summary: all LID paths empty; TokenKeys=0.

| Check | Result |
|-------|--------|
| Build | 26200 / Display **25H2** |
| NIC | Ethernet = **Disconnected** |
| HKCU IdentityCRL `LID` | **empty / absent** |
| `.DEFAULT` `LID` | **empty / absent** |
| SYSTEM (`S-1-5-18`) `LID` | **empty / absent** |
| Token dir keys | **0** |
| `wlidsvc` | Running / Manual |
| `CDPSvc` | Running / Automatic |
| `dosvc` | Running / Automatic |
| `DiagTrack` | Running / Automatic |

## Verdict

**`[OBSERVED]` H1 supported for this offline baseline:** Offline install with local account and no network → **no Device PUID / GDID was present in the inspected local stores**, even though CDP/wlidsvc/DiagTrack were running.

Services can be up without a server-assigned install id. Mint appears gated on successful DeviceAdd (or equivalent) once network + `login.live.com` are reachable.

The completion gate here is GDID-only: this run establishes the inspected offline state, not later online durability or general Windows compatibility.

## Next

- EXP-A4 style: apply registration blocks **before** first online, then connect NIC — does mint stay prevented?
- Or deeper offline inspect (full IdentityCRL tree, CDP folder) while still airgapped.
