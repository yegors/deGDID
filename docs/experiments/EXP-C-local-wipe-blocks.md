# EXP-C - Local-only wipe + registration blocks (contaminated install)

Date: 2026-07-11  
VM: lab guest after EXP-B mint  
Prior GDID: present in SYSTEM/`.DEFAULT` (`0018...`; hash recorded, value not committed)  
Checkpoints: `S3b-before-local-rotate-*` -> `S4-after-local-wipe-blocked-*`

## Procedure

1. Record pre-state hash of SYSTEM/`.DEFAULT` `LID` (same value both hives).
2. Disconnect Hyper-V NIC.
3. Stop `wlidsvc` / `CDPSvc`.
4. `degdid.ps1 -Wipe` (cleared `.DEFAULT` + SYSTEM `LID`, CDP folder).
5. Confirm offline: **no LID** anywhere.
6. Apply hosts registration blocks (firewall IP refresh hung offline on DNS - hosts still applied; later fixed online).
7. Reconnect NIC to Default Switch; start identity services; soak ~2 min.

## Results

| Check | Result |
|-------|--------|
| Wipe offline | **Cleared** SYSTEM + `.DEFAULT` |
| After online + blocks | **StillEmpty=True** - no `LID` in HKCU / `.DEFAULT` / SYSTEM |
| Same as old GDID? | **False** (nothing to compare - empty) |
| NIC / general net | Up (example/TCP to 1.1.1.1 worked earlier in run) |
| `login.live.com` | Hosts -> `0.0.0.0` |
| LiveId log | Errors again (`6113` / `2028`) - provision attempts failing |

Summary: hashes were recorded privately and are **not** committed.

## Verdict

**`[OBSERVED]` H3/H4 PASS (short soak + reboot):** On a previously minted install (machine-hive only; HKCU never had LID), **local-only wipe** of Device PUID + **registration hosts blocks** kept the image **without a local GDID** after returning online and after reboot. The old `g:...` did **not** reappear within the tested window.

### What this means

- Contaminated â‰  doomed locally: you can erase the install id offline (for this mint shape).
- Blocks stop silent DeviceAdd from immediately re-minting a **new** real GDID.
- Combined with EXP-A4/B: prevent mint, or wipe+starve after contamination.
- **Later:** HKCU-contaminated installs need expanded wipe - see EXP-C2 / EXP-C3.

### Caveats

- Does **not** erase Microsoft's server-side history of the old GDID.
- Store UI under blocks covered in EXP-E (expected auth failure).
- Offline firewall DNS refresh can hang - hosts-only apply is enough; script uses short DNS job timeouts.

## Next

Superseded by EXP-C2 / C3 for HKCU continuity; EXP-D for Update.
