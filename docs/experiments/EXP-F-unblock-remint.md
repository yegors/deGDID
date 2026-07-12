# EXP-F - Unblock / revert after local decoy or wipe

Date: 2026-07-11  
Follows: EXP-C3 clean empty + decoy under blocks
Status: **`[OBSERVED]` short-window unblock behavior; wipe-remint not proven**

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

## Explicit non-claims

- Did not prove multi-hour/day remint latency after decoy unblock.
- Did not observe or prove wipe -> remint; the H7 wipe-remint hypothesis remains open.
- Did not run opaque GDID-Changer binaries; online rotate = clear state + allow DeviceAdd (EXP-B class).
- Feature-update under blocks and firewall-only minimum left deferred (low ROI vs hosts block set already validated).
