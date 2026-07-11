# EXP-E — Breakage catalog (blocks + empty LID)

Date: 2026-07-11  
Config: registration hosts/firewall blocks + no GDID (`EXP-C3` clean). Local account only.

## Matrix

| Feature | State | Note |
|---------|-------|------|
| Boot / login / desktop | works | PS Direct session OK |
| Windows Update scan | works | COM search OK; pending=0 |
| Defender sig update | works | `Update-MpSignature=OK` (`EXP-D`) |
| Activation | degraded | `LicenseStatus=5` (lab VM licensing / notification — not proven caused by blocks) |
| Microsoft Store package | present | Appx present; **MSA download/sign-in not exercised in UI** — expect auth fail |
| MSA / LiveId network | broken (expected) | `login.live.com` blocked |
| CDPSvc | running | DDS blocked → graph/Phone Link sync expected fail |
| Edge binary | works | Non-MSA browse assumed OK; sync not tested |
| OneDrive package | absent | N/A on this image |
| Xbox package | present | MSA auth expected broken |
| Phone Link package | present | CDP/DDS blocked — pairing expected fail |
| LID after probes | empty | No accidental mint |

## Configs not fully UI-tested

Store free-app download, Settings MSA sign-in wizard, Xbox login, Phone Link pairing, Edge sync — marked **expected broken** under blocks; package presence only where noted.

## Verdict

Core desktop + Update OK. MSA/Store-auth/CDP-graph features are the intentional sacrifice of P2/P4.
