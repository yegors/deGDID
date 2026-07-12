# EXP-C3 - HKCU LID rehydrate candidate + expanded wipe

Date: 2026-07-11  
Follows: [EXP-C2](./EXP-C2-continuity-drill.md)
Status: **`[OBSERVED]` successful expanded bundle under continuous blocks; short window; ablation pending**

## Question

What restores HKCU `IdentityCRL\ExtendedProperties\LID` across reboot after a naive wipe, while hosts still block `login.live.com`?

## High-confidence bundle member

IdentityCRL Immersive `Property\<LID>` is a **required/high-confidence member of the successful wipe bundle unless and until an ablation run shows otherwise**. It survived clearing `ExtendedProperties\LID` alone, was cleared with the expanded bundle, and the old LID then stayed absent. Because the run changed several stores together, it does **not** isolate Immersive Property as the sole causal restore source.

| Store | Role |
|-------|------|
| `HKCU\...\IdentityCRL\Immersive\production\Property\<LID hex>` | Binary blob (~346 bytes) named as the LID; survives clearing `ExtendedProperties\LID` alone |
| `HKCU\...\Immersive\production\Token\{...}\DeviceId` + `DeviceTicket` | Parallel copies / tickets |
| TokenBroker cache, CDP folder, `cmdkey` `didlogical` | Cleared for hygiene; `didlogical` often recreates empty without restoring LID |

Plaintext file scan of common Microsoft AppData trees for the LID hex/decimal: **0 hits**. The matching candidate state found in this search was registry-side, not a loose plaintext file; the expanded-bundle run did not isolate one registry member as the sole cause.

## Protocol

1. Map IdentityCRL tree (see `tools/hunt-lid-source.ps1 -Phase Map`)
2. Historical expanded-bundle wipe cleared Immersive Property values, Token DeviceId/Ticket, `cmdkey` didlogical, TokenBroker cache, CDP, and all LID paths. The current hardened script retains the proven Property/Token/LID and file-cache bundle but does not claim `cmdkey` deletion is required.
3. Ensure hosts registration block **before** any online soak
4. Reboot + soak with wlidsvc/CDP forced

## Results

| Step | Result |
|------|--------|
| Map | Immersive Property value name == old LID; Token DeviceId == same; SYSTEM/`.DEFAULT` empty at map time |
| Expanded wipe | HKCU LID + Immersive Property + DeviceTicket cleared |
| Reboot + blocks | **HKCU stayed empty** - old GDID did **not** resurrect |
| Pitfall | Brief **hosts gap** after wipe allowed LiveId SOAP (~23:16) -> **new** SYSTEM/`.DEFAULT` `0018...` (≠ old GDID). Not HKCU rehydrate. |
| Wipe again under blocks + reboot + ~4 min soak (wlidsvc forced) | **HKCU + `.DEFAULT` + SYSTEM all empty**; no DeviceAdd in LiveId log |

## Verdict

- EXP-C2 showed that the LID-only wipe was **incomplete**; C3's expanded multi-store bundle succeeded.
- Keep Immersive `Property\<LID>` (and Token device fields) in the wipe bundle and keep registration blocks continuous. Immersive Property remains a required/high-confidence member pending ablation.
- Root `degdid.ps1` implements expanded wipe/decoy/block; `tools/hunt-lid-source.ps1` remains for map/audit/search.
- The completion gate is GDID-only and covers the continuous-block short window actually observed (reboot + ~4-minute soak), not long-duration durability or component-level causality.

## Still open

- Registry audit SACL on SYSTEM/`.DEFAULT` writers (optional; HKCU high-confidence candidate mapped)
- C3 ablation: repeat from the same contaminated snapshot while omitting only Immersive Property from the otherwise identical wipe bundle
- Longer multi-day soak / Update under this clean empty state
