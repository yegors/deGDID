# Glossary

Last updated: 2026-07-11

| Term | Meaning |
|------|---------|
| **GDID** | Global Device Identifier — `g:` + decimal form of Device PUID; install-scoped id named in Stokes complaint |
| **Device PUID** | 64-bit Passport Unique ID for a *device/install*; often hex `0018…`; stored as `LID` / `DeviceId` |
| **User PUID** | MSA *account* id; often `0003…`; not the same as GDID |
| **DeviceAdd** | Passport SOAP registration to `login.live.com/ppsecure/deviceaddcredential.srf` |
| **DDS** | Device Directory Service — MS graph of user↔device associations (`cs.dds.microsoft.com`, etc.) |
| **CDP** | Connected Devices Platform — Windows client (`cdp.dll`, `CDPSvc`) for cross-device + DDS registration |
| **MSA** | Microsoft Account |
| **wlidsvc** | Windows Live ID / Microsoft Account Sign-in Assistant service; participates in DeviceAdd and device identity, while the PUID itself is server-assigned |
| **DO** | Delivery Optimization — reports `UCDOStatus.GlobalDeviceId` |
| **IdentityCRL** | Registry identity store under `Software\Microsoft\IdentityCRL` |
| **x-device-token** | MSA device ticket used e.g. for Autopilot ZTD calls |
| **ZTD** | Zero Touch Deployment / Autopilot path via `ztd.dds.microsoft.com` |
| **Wipe** | Canonical tool mutation: remove known active real Device PUID state and related known local copies only after the DeviceAdd block gate verifies |
| **Decoy** | Experimental mutation: install a local `0018…`-shaped value with no claim that Microsoft issued or recognizes it |
| **Protection gate** | Required canonical dual-stack hosts plus actual mint-path verification; managed FQDN/service firewall rules are reported defense in depth, not a mandatory topology |

## Confidence tags

| Tag | Meaning |
|-----|---------|
| `[COURT]` | Stated in legal filings / MS rep via affidavit |
| `[MSDOC]` | Microsoft Learn / official endpoint docs |
| `[STATIC]` | From binaries / public PDBs / strings |
| `[LAB]` | Reproduced directly in this project's lab or local workstation inspection |
| `[CITED-RE]` | Behavioral observation or traffic capture reported by a cited external reverse-engineering source; not necessarily reproduced locally |
| `[OBSERVED]` | Direct observation where the narrower provenance tag is unavailable; nearby text should name the source |
| `[ASSESSED]` | Strong inference; needs more proof |
