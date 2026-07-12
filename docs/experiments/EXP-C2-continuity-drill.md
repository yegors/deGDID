# EXP-C2 - Continuity drill (mint -> reboot -> wipe+block -> reboot)

Date: 2026-07-11  
Lab guest after Windows Update under prior blocks.
Status: **`[OBSERVED]` continuity drill; naïve wipe negative result**

## Protocol (as requested)

1. Confirm still no GDID after update  
2. Unblock -> mint GDID₁
3. Reboot -> same GDID₁
4. Wipe + reblock -> reboot -> expect gone  

## Results

| Step | Result |
|------|--------|
| **0** Post-update | **No GDID** (blocks still on). Update did not mint. |
| **1** Unblock + soak | Minted a server `g:...` / `0018...` PUID (value redacted; not committed) |
| **2** Reboot | **Same GDID₁** (`SameAfterReboot=True`) |
| **3-4** Wipe LID + hosts block + reboot | **FAIL vs hope:** GDID₁ **returned in HKCU only** |
| SYSTEM / `.DEFAULT` after 4 | Still **empty** |
| `login.live.com` / expanded MSA hosts | Still **0.0.0.0** / blocked |
| `cmdkey` `didlogical` | Deleted; after reboot often **absent**, yet HKCU LID still returns |

Summary: redacted; raw step dump not committed.

## What this run shows

1. **Update ≠ mint** in the observed post-update state while registration remained blocked.
2. **GDID persists across reboot** when legitimately minted (continuity of install id).  
3. **Simple registry wipe is not enough** once a **user-hive (HKCU)** copy has existed: something **locally restores the same PUID into HKCU** across reboot **without** needing `login.live.com` (hosts still blocking).  
4. Earlier EXP-C "wipe stays empty" still stands for the **machine-hive-only** mint case (EXP-B style: SYSTEM/`.DEFAULT` only, HKCU never had LID). Contaminated **HKCU** is a harder animal.

## Likely restore class (open)

- Not plaintext in searched AppData (binary scan of common Microsoft trees found **no** raw LID).  
- `WindowsLive:target=virtualapp/didlogical` is involved in the ecosystem but **deleting it alone did not stop** HKCU resurrection.  
- Later EXP-C3 mapped IdentityCRL Immersive Property as a high-confidence member of the successful expanded wipe bundle; a single-variable ablation was not run.

## Follow-ups

- [x] Map the high-confidence HKCU restore-store candidate -> **Immersive `Property\<LID>`** (+ Token DeviceId/Ticket); see [EXP-C3](./EXP-C3-hkcu-rehydrate-source.md)
- [x] Expand wipe into root `degdid.ps1`  
- [ ] Longer soak / Update under expanded-wipe empty state  
- [x] Decoy mode clears Immersive Property  
- [ ] Ablate Immersive Property from the expanded bundle to isolate causality

## Verdict

Continuity drill **partially succeeded**: mint and reboot-stability were confirmed; **naïve LID-only wipe failed** after HKCU contamination. EXP-C3's expanded bundle stayed empty in its tested continuous-block short window, but its individual components were not ablated.
