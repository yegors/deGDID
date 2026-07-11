# EXP-C2 - Continuity drill (mint -> reboot -> wipe+block -> reboot)

Date: 2026-07-11  
Lab guest after Windows Update under prior blocks.

## Protocol (as requested)

1. Confirm still no GDID after update  
2. Unblock -> mint GDIDâ‚  
3. Reboot -> same GDIDâ‚  
4. Wipe + reblock -> reboot -> expect gone  

## Results

| Step | Result |
|------|--------|
| **0** Post-update | **No GDID** (blocks still on). Update did not mint. |
| **1** Unblock + soak | Minted a server `g:...` / `0018...` PUID (value redacted; not committed) |
| **2** Reboot | **Same GDIDâ‚** (`SameAfterReboot=True`) |
| **3-4** Wipe LID + hosts block + reboot | **FAIL vs hope:** GDIDâ‚ **returned in HKCU only** |
| SYSTEM / `.DEFAULT` after 4 | Still **empty** |
| `login.live.com` / expanded MSA hosts | Still **0.0.0.0** / blocked |
| `cmdkey` `didlogical` | Deleted; after reboot often **absent**, yet HKCU LID still returns |

Summary: redacted; raw step dump not committed.

## What this proves

1. **Update â‰  mint** while registration is blocked.  
2. **GDID persists across reboot** when legitimately minted (continuity of install id).  
3. **Simple registry wipe is not enough** once a **user-hive (HKCU)** copy has existed: something **locally restores the same PUID into HKCU** across reboot **without** needing `login.live.com` (hosts still blocking).  
4. Earlier EXP-C "wipe stays empty" still stands for the **machine-hive-only** mint case (EXP-B style: SYSTEM/`.DEFAULT` only, HKCU never had LID). Contaminated **HKCU** is a harder animal.

## Likely restore class (open)

- Not plaintext in searched AppData (binary scan of common Microsoft trees found **no** raw LID).  
- `WindowsLive:target=virtualapp/didlogical` is involved in the ecosystem but **deleting it alone did not stop** HKCU resurrection.  
- Suspect: encrypted vault / IdentityCRL secondary store / device-key-bound local cache that rehydrates `ExtendedProperties\LID` at logon.

## Follow-ups

- [x] Identify HKCU restore source -> **Immersive `Property\<LID>`** (+ Token DeviceId/Ticket); see [EXP-C3](./EXP-C3-hkcu-rehydrate-source.md)  
- [x] Expand wipe into root `degdid.ps1`  
- [ ] Longer soak / Update under expanded-wipe empty state  
- [x] Decoy mode clears Immersive Property  

## Verdict

Continuity drill **partially succeeded**: mint and reboot-stability confirmed; **naÃ¯ve LID-only wipe fails** once HKCU Immersive Property is contaminated. **Resolved in EXP-C3** with expanded wipe.
