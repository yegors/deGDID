# EXP-F - Unblock / revert after local decoy or wipe

Date: 2026-07-11  
Follows: EXP-C3 clean empty + decoy under blocks
Status: **`[OBSERVED]` original short-window negative; later wipe-remint control passed in EXP-G**

## Protocol

1. **Decoy under blocks:** `degdid.ps1 -Protect -UseDecoy` (or Decoy after Block)
2. Reboot with hosts blocks still on -> check decoy stickiness
3. **F1:** Remove registration blocks; soak ~6 min with wlidsvc/CDP up
4. **F2:** Expanded wipe while **unblocked**; soak ~5-6 min; optional Device Information / DDS scheduled tasks

Cross-check: **EXP-B** observed first-chance mint after unblocking the never-minted A4 image -> SYSTEM/`.DEFAULT` mint in ~2 min with LiveId `6115/6116/6117`.

## Results

| Step | Result |
|------|--------|
| Decoy + blocks + reboot | **HKCU decoy stuck** (prefix `0018...`); SYSTEM LID often empty after reboot |
| F1 unblock, decoy present | **No replacement** in ~6 min - same local decoy remained in HKCU; no LiveId DeviceAdd SOAP |
| F2 wipe while unblocked | Stayed **empty** ~5+ min despite `login.live.com` HTTPS **200** and TCP 443 OK |
| Device Info / DDS tasks | Started; **still no mint** in short soak; LiveId only start/stop (`2024`), no `6115` |
| EXP-B (prior) | Unblock from **blocked-never-minted** eager state -> **first-chance server mint** ~2 min |

## Verdict

1. **Local decoy is sticky** - unblock alone does **not** instantly force a server PUID over an existing HKCU LID (short soak).
2. **F2 did not observe or prove wipe-remint.** The wiped image stayed empty for ~5-6 minutes while unblocked; that bounds only this short window and trigger set.
3. **First-chance server mint is real** in EXP-B's eager, never-minted state. EXP-B is a mint control, not evidence that a previously minted-and-wiped image remints.
4. **Practical:** Keep **blocks** if the goal is "no new real GDID." Decoy/wipe without blocks is **not** a guarantee against eventual remint; it is also **not** an instant remint timer.

## 2026-07-15 follow-up

EXP-G later exercised the missing direct control on the same current-revision VM
timeline: Protect/wipe, reboot clean, Unblock, reboot unblocked, observe a real PUID
return, Protect again, and reboot clean again.

The unblocked reboot produced a real PUID after 22 seconds while identity services
and registration tasks were exercised. The state included two LID stores, two
machine DeviceIdentities roots, and two DeviceTickets. The subsequent Protect
captured two real PUIDs, completed all 37 operations without failure, and remained
`ProtectedNoRealGdid` after the final reboot.

This closes the direct wipe -> unblock -> remint observation gap. It does not
contradict the original F2 negative: remint is client/trigger dependent, and the
22-second triggered result is not a universal timer.

## Explicit non-claims

- The original EXP-F run did not prove multi-hour/day remint latency after decoy
  unblock.
- The original F2 window did not observe wipe -> remint; the later EXP-G follow-up
  did observe it under an unblocked reboot plus identity triggers.
- Did not run opaque GDID-Changer binaries; online rotate = clear state + allow DeviceAdd (EXP-B class).
- Feature-update under blocks and firewall-only minimum left deferred (low ROI vs hosts block set already validated).
