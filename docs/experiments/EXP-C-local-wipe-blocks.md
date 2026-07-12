# EXP-C - Local-only wipe + registration blocks (contaminated install)

Date: 2026-07-11  
VM: lab guest after EXP-B mint  
Prior GDID: present in SYSTEM/`.DEFAULT` (`0018...`; hash recorded, value not committed)  
Checkpoints: `S3b-before-local-rotate-*` -> `S4-after-local-wipe-blocked-*`
Status: **`[OBSERVED]` GDID-only continuous-block, short-window result**

## Procedure

1. Record pre-state hash of SYSTEM/`.DEFAULT` `LID` (same value both hives).
2. Disconnect Hyper-V NIC.
3. Stop `wlidsvc` / `CDPSvc`.
4. `degdid.ps1 -Wipe` (cleared `.DEFAULT` + SYSTEM `LID`, CDP folder).
5. Confirm offline: **no LID** anywhere.
6. Apply hosts registration blocks (firewall IP refresh hung offline on DNS - hosts still applied; later fixed online).
7. Reconnect NIC to Default Switch; start identity services; soak ~2 min.

This records the historical pre-hardening procedure. The current script reverses the
unsafe public ordering: standalone Wipe refuses without an already verified gate, and
Protect establishes the gate before identity mutation.

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

**`[OBSERVED]` H3 supported; H4 supported only at the GDID-only gate for this short window:** On a previously minted install (machine-hive only; HKCU never had LID), a **local-only wipe** cleared the Device PUID. Registration hosts blocks were in place before reconnect and remained continuous while the image stayed **without a local GDID** after returning online and after reboot. The old `g:...` did **not** reappear within the tested window.

### What this means

- Contaminated ≠ doomed locally: the run erased the locally readable install id offline for this machine-hive-only mint shape.
- Under this tested window, continuous blocks coincided with no immediate **new** real GDID mint.
- Combined with EXP-A4/B: prevent mint, or wipe+starve after contamination.
- **Later:** HKCU-contaminated installs need expanded wipe - see EXP-C2 / EXP-C3.

### Caveats

- Does **not** erase Microsoft's server-side history of the old GDID.
- Store and other UI paths under blocks were not exercised; see the partial/inferred EXP-E catalog.
- The historical static-IP firewall refresh could hang while offline. The current rewrite removed that job-based static-IP mechanism.
- The result is a continuous-block short window, not a long-soak or bypass-resistance claim.

## Next

Superseded by EXP-C2 / C3 for HKCU continuity; EXP-D for Update.
