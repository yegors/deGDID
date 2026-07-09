# Countermeasures — Draft Matrix (Pre-Lab)

Last updated: 2026-07-09  
Status: **design only** until VM experiments in `lab-playbook.md` complete.

Focus strategies called out by project direction:

1. **Prevent mint at install**
2. **Starve / block registration servers**
3. **Local-only offline rotation** (no network re-register)
4. (Contrast) Server-side re-provision rotate — not preferred for “offline discontinuity”

---

## Strategy overview

| ID | Strategy | Talks to MS? | Continuity break | Main risk |
|----|----------|--------------|------------------|-----------|
| P1 | Offline OOBE / delay first DeviceAdd | No until online | N/A (never minted yet) | First unblocked online mints for real |
| P2 | Block DeviceAdd + DDS + activity hosts | Blocked | Prevents *new* server id | Breaks MSA/Store/CDP; WU must stay allowed |
| P3 | **Local-only** rewrite/delete Device PUID offline | No | Local fingerprint changes | OS may heal; fake id not in MS graph; unblock → re-mint |
| P4 | P3 + P2 combined | No DeviceAdd | Best shot at stable decoy | Same breakage as P2 |
| P5 | Clear state online → server new GDID | Yes | New *real* GDID (MS has it) | Old GDID history remains; MSA join |
| P6 | Starve CDP/Activity without hosts file | Partial | Reduces emit | May not stop mint |

**Project preference to validate:** **P1 + P4** (never mint if possible; if contaminated, local decoy + permanent registration block).

---

## P1 — Prevent generation on install

### Idea
Complete setup **without** reaching `login.live.com` DeviceAdd. Keep registration blocked before first route to Internet.

### Candidate tactics
- Airplane / no NIC through OOBE; local account only
- Pre-apply hosts/firewall blocks **before** enabling network (unattend / first-logon script / parent firewall)
- Avoid MSA sign-in forever on that image

### Expected
- Possible absence of `LID` until first successful DeviceAdd (`lab` H1/H2)
- Windows usable as local desktop; Store/MSA features limited once blocked

### Unknown until lab
- Does some component invent a local placeholder id without server?
- Does WU or other setup require DeviceAdd?

---

## P2 — Block registration servers “for good measure”

### Block set (v0)
See `lab-playbook.md` §3: `login.live.com`, DDS hosts, `activity.windows.com`, etc.

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

## P3 — Local-only rotation (contaminated install)

### Idea
While **offline**, change or wipe local Device PUID copies (`LID`, Token `DeviceId`, SYSTEM/`.DEFAULT`) and wipe device tickets / CDP state — **without** calling DeviceAdd.

### Why
- Server re-mint (P5) gives Microsoft a **fresh real** GDID immediately — bad if goal is “stop being a registered install.”
- Local decoy aims for: nothing valid to send, or a non-graph id, until/unless blocks fail.

### Will Windows break? (predictions — lab must confirm)

| Area | Prediction |
|------|------------|
| Boot / local desktop | Likely OK |
| Windows Update | Likely OK if only identity keys change |
| MSA / Store / CDP | Likely broken or flaky until re-provision |
| Activation | Usually separate; watch for device-auth edge cases |
| After unblock | High chance of **silent DeviceAdd** → real new GDID (P5) |

### Updates
- Feature/CU updates historically **keep** GDID (`[COURT]`). Under P4, expect local decoy to **persist across updates** if registration stays blocked (H8).
- If update path re-runs device provision, decoy may die — test in EXP-D.

---

## P4 — Local-only + permanent blocks (preferred contaminated path)

1. Airplane mode  
2. Local rotate / wipe (P3)  
3. Apply P2 blocks  
4. Go online  
5. Verify LID stable + no DeviceAdd  
6. Run Update + breakage catalog  

This is the headline procedure to validate in VM lab.

---

## P5 — Online server rotate (contrast only)

Clear registration → allow `login.live.com` → new server GDID.  
Useful as **control experiment**, not as privacy win vs Microsoft.

---

## Verification checklist (any strategy)

- [ ] `inspect` LID HKCU + SYSTEM + `.DEFAULT`
- [ ] Token `DeviceId` consistency / absence
- [ ] No DeviceAdd traffic under blocks
- [ ] WU scan/download result
- [ ] Store/MSA smoke
- [ ] Snapshot rollback documented

---

## Explicit non-claims

- Local decoy ≠ erased MS historical records for old GDID  
- Blocks ≠ hide all telemetry (DiagTrack and other planes remain)  
- Not a lawful-process evasion guide  

---

## Next

Execute `lab-playbook.md` agent phases L0–L6; promote surviving procedures here to **validated** with `[OBSERVED]` tags.
