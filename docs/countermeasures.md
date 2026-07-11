# Countermeasures - Validated Matrix

Last updated: 2026-07-11  
Status: **lab-validated** for core P1/P2/P3/P4 paths on Win11 25H2; see `docs/experiments/`. End-user script: root `degdid.ps1`.

Focus strategies called out by project direction:

1. **Prevent mint at install**
2. **Starve / block registration servers**
3. **Local-only offline rotation** (no network re-register)
4. (Contrast) Server-side re-provision rotate - not preferred for "offline discontinuity"

---

## Strategy overview

| ID | Strategy | Talks to MS? | Continuity break | Main risk |
|----|----------|--------------|------------------|-----------|
| P1 | Offline OOBE / delay first DeviceAdd | No until online | N/A (never minted yet) | First unblocked online mints for real |
| P2 | Block DeviceAdd + DDS + activity hosts | Blocked | Prevents *new* server id | Breaks MSA/Store/CDP; WU must stay allowed |
| P3 | **Local-only** rewrite/delete Device PUID offline | No | Local fingerprint changes | OS may heal; fake id not in MS graph; unblock -> re-mint |
| P4 | P3 + P2 combined | No DeviceAdd | Best shot at stable decoy | Same breakage as P2 |
| P5 | Clear state online -> server new GDID | Yes | New *real* GDID (MS has it) | Old GDID history remains; MSA join |
| P6 | Starve CDP/Activity without hosts file | Partial | Reduces emit | May not stop mint |

**Project preference to validate:** **P1 + P4** (never mint if possible; if contaminated, local decoy + permanent registration block).

---

## P1 - Prevent generation on install

### Idea
Complete setup **without** reaching `login.live.com` DeviceAdd. Keep registration blocked before first route to Internet.

### Candidate tactics
- Airplane / no NIC through OOBE; local account only
- Pre-apply hosts/firewall blocks **before** enabling network (unattend / first-logon script / parent firewall)
- Avoid MSA sign-in forever on that image

### Lab results
- **`[OBSERVED]` H1:** Offline OOBE/local account -> no `LID` (`EXP-A1`).
- **`[OBSERVED]` H2 (short soak):** Hosts blocks applied before first online -> general Internet works; `login.live.com` starved; **no `LID`** after wlidsvc/CDP bounce (`EXP-A4`). LiveId logs `0x800704CF`.
- No local placeholder Device PUID observed without server mint in these runs.

### Still open
- Longer soak / reboot under blocks
- Windows Update under blocks (`EXP-D`)
- DoH / hardcoded-IP bypass of hosts (need real IP firewall rules via external DNS)

---

## P2 - Block registration servers "for good measure"

### Block set (v0)
See `lab-playbook.md` Â§3: `login.live.com`, DDS hosts, `activity.windows.com`, etc.

### Allow
Windows Update delivery endpoints (do not nuke `*.microsoft.com`).

### Expected breakage
- Microsoft account sign-in
- Store auth, Xbox, OneDrive MSA
- Phone Link / CDP graph
- Autopilot/ZTD (N/A on consumer lab)

### Expected keepers (to verify)
- Local apps, files, non-MSA browsing
- Windows Update (H5)

---

## P3 - Local-only rotation (contaminated install)

### Idea
While **offline**, change or wipe local Device PUID copies (`LID`, Token `DeviceId`, SYSTEM/`.DEFAULT`) and wipe device tickets / CDP state - **without** calling DeviceAdd.

### Why
- Server re-mint (P5) gives Microsoft a **fresh real** GDID immediately - bad if goal is "stop being a registered install."
- Local decoy aims for: nothing valid to send, or a non-graph id, until/unless blocks fail.

### Will Windows break? (predictions - lab must confirm)

| Area | Prediction |
|------|------------|
| Boot / local desktop | Likely OK |
| Windows Update | Likely OK if only identity keys change |
| MSA / Store / CDP | Likely broken or flaky until re-provision |
| Activation | Usually separate; watch for device-auth edge cases |
| After unblock | High chance of **silent DeviceAdd** -> real new GDID (P5) |

### Lab results (P3/P4)
- **`[OBSERVED]` EXP-C:** Wipe SYSTEM/`.DEFAULT` `LID` (HKCU never minted) + hosts blocks -> stayed empty across soak/reboot.
- **`[OBSERVED]` EXP-C2:** After mint into **HKCU**, reboot keeps same GDID; **LID-only** wipe+hosts+reboot -> **same GDID returns in HKCU** (local rehydrate).
- **`[OBSERVED]` EXP-C3:** Rehydrate source is `HKCU\...\Immersive\production\Property\<LID>` (+ Token DeviceId/Ticket). Expanded wipe + **continuous** hosts blocks -> HKCU/SYSTEM/`.DEFAULT` stay empty across reboot + multi-minute soak. Do not leave a hosts gap while online (gap allowed a *new* machine-hive mint).
- Server-side history of old GDID still untouched either way.
- **`[OBSERVED]` EXP-D:** WU COM search + Defender `Update-MpSignature` under blocks; CU history includes blocked-period installs; LID stayed empty.
- **`[OBSERVED]` EXP-E:** Desktop/WU OK; MSA/LiveId path broken (expected); Store/Xbox/Phone Link auth expected fail under blocks.
- **`[OBSERVED]` EXP-F:** Decoy in HKCU not instantly replaced after unblock (short soak); wipe+unblock not auto-remint without DeviceAdd client. Eager remint = **EXP-B**.

---

## P4 - Local-only + permanent blocks (preferred contaminated path)

1. Airplane / ensure registration blocks first  
2. Expanded local wipe or decoy (`degdid.ps1 -Protect` / `-Protect -UseDecoy`)  
3. Keep P2 blocks continuous (no hosts gap while online)  
4. Go online; verify LID empty or decoy stable  
5. Update + breakage: see EXP-D / EXP-E  

**Lab status:** validated on Win11 25H2 lab VM (`EXP-A`...`EXP-F`).

---

## P5 - Online server rotate (contrast only)

Clear registration -> allow `login.live.com` -> new server GDID when the stack actually DeviceAdds.  
**`[OBSERVED]` EXP-B:** first unblock after never-minted blocked state -> mint ~2 min.  
**`[OBSERVED]` EXP-F:** not an instant timer after decoy/wipe on a tired image.

---

## Verification checklist (any strategy)

- [x] `inspect` LID HKCU + SYSTEM + `.DEFAULT`
- [x] Token `DeviceId` / Immersive Property absence after expanded wipe
- [x] No DeviceAdd under blocks (LiveId errors / empty LID)
- [x] WU scan / Defender update under blocks (`EXP-D`)
- [x] Breakage table (`EXP-E`)
- [x] Snapshot chain on lab VM (S1...S5)

---

## Explicit non-claims

- Local decoy â‰  erased MS historical records for old GDID  
- Blocks â‰  hide all telemetry (DiagTrack and other planes remain)  
- Not a lawful-process evasion guide  
- Feature-update and firewall-only-minimum not labbed (deferred)

---

## Next

Phase 4 tooling polish / optional public summary. Core lab hypotheses closed.
