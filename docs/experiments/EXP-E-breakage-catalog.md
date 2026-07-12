# EXP-E — Breakage catalog (blocks + empty LID)

Date: 2026-07-11  
Config: registration hosts/firewall blocks + no GDID (`EXP-C3` clean). Local account only.
Status: **PARTIAL / INFERRED - named UI paths were not exercised**

## Matrix

| Feature | State | Note |
|---------|-------|------|
| Boot / login / desktop | partially observed | VM boot and PS Direct session OK; interactive UI path not separately exercised |
| Windows Update scan | observed, partial | COM search OK; pending=0 (`EXP-D`) |
| Defender sig update | observed | `Update-MpSignature=OK` (`EXP-D`) |
| Activation | observed degraded state | `LicenseStatus=5` (lab VM licensing / notification — not proven caused by blocks) |
| Microsoft Store package | present only | Appx present; **MSA download/sign-in not exercised in UI** |
| MSA / LiveId network | observed blocked | `login.live.com` blocked; UI behavior inferred |
| CDPSvc | observed running | DDS blocked; graph/Phone Link effect inferred |
| Edge binary | binary check only | Non-MSA browse and sync not tested |
| OneDrive package | absent | N/A on this image |
| Xbox package | present only | MSA auth not exercised; failure inferred |
| Phone Link package | present only | Pairing not exercised; failure inferred from CDP/DDS blocks |
| LID after probes | empty | No accidental mint |

## UI paths not exercised

Store free-app download, Settings MSA sign-in wizard, Xbox login, Phone Link pairing, Edge browse/sync, and an interactive desktop workflow were **not run**. Their behavior under blocks remains inferred; package presence is recorded only where noted.

## Verdict

**PARTIAL / INFERRED:** The run observed VM boot/PS Direct access, the limited EXP-D servicing checks, blocked identity endpoints, package presence, and an empty LID. It did **not** exercise the named UI paths, so it proves neither their breakage nor their compatibility. The completion gate here is limited to the observed GDID state; the breakage catalog remains open.
