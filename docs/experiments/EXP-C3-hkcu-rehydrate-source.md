# EXP-C3 - HKCU LID rehydrate source + expanded wipe

Date: 2026-07-11  
Follows: [EXP-C2](./EXP-C2-continuity-drill.md)

## Question

What restores HKCU `IdentityCRL\ExtendedProperties\LID` across reboot after a naive wipe, while hosts still block `login.live.com`?

## Finding

**Primary local restore store (HKCU):**

| Store | Role |
|-------|------|
| `HKCU\...\IdentityCRL\Immersive\production\Property\<LID hex>` | Binary blob (~346 bytes) named as the LID; survives clearing `ExtendedProperties\LID` alone |
| `HKCU\...\Immersive\production\Token\{...}\DeviceId` + `DeviceTicket` | Parallel copies / tickets |
| TokenBroker cache, CDP folder, `cmdkey` `didlogical` | Cleared for hygiene; `didlogical` often recreates empty without restoring LID |

Plaintext file scan of common Microsoft AppData trees for the LID hex/decimal: **0 hits**. Restore is registry-side (Immersive Property), not a loose file.

## Protocol

1. Map IdentityCRL tree (see `tools/hunt-lid-source.ps1 -Phase Map`)
2. Expanded wipe via `degdid.ps1 -Wipe` / `-Protect` to clear Immersive Property values, Token DeviceId/Ticket, cmdkey, TokenBroker cache, CDP, plus all LID paths
3. Ensure hosts registration block **before** any online soak
4. Reboot + soak with wlidsvc/CDP forced

## Results

| Step | Result |
|------|--------|
| Map | Immersive Property value name == old LID; Token DeviceId == same; SYSTEM/`.DEFAULT` empty at map time |
| Expanded wipe | HKCU LID + Immersive Property + DeviceTicket cleared |
| Reboot + blocks | **HKCU stayed empty** - old GDID did **not** resurrect |
| Pitfall | Brief **hosts gap** after wipe allowed LiveId SOAP (~23:16) -> **new** SYSTEM/`.DEFAULT` `0018...` (â‰  old GDID). Not HKCU rehydrate. |
| Wipe again under blocks + reboot + ~4 min soak (wlidsvc forced) | **HKCU + `.DEFAULT` + SYSTEM all empty**; no DeviceAdd in LiveId log |

## Verdict

- EXP-C2 failure was **incomplete wipe**, not magic network remint of the same PUID under blocks.
- Kill Immersive `Property\<LID>` (and Token device fields) **with** LID wipe, and keep registration blocks continuous.
- Root `degdid.ps1` implements expanded wipe/decoy/block; `tools/hunt-lid-source.ps1` remains for map/audit/search.

## Still open

- Registry audit SACL on SYSTEM/`.DEFAULT` writers (optional; HKCU path solved)
- Whether Decoy mode should also seed/clear Immersive Property
- Longer multi-day soak / Update under this clean empty state
