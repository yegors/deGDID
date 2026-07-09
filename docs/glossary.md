# Glossary

| Term | Meaning |
|------|---------|
| **GDID** | Global Device Identifier — `g:` + decimal form of Device PUID; install-scoped id named in Stokes complaint |
| **Device PUID** | 64-bit Passport Unique ID for a *device/install*; often hex `0018…`; stored as `LID` / `DeviceId` |
| **User PUID** | MSA *account* id; often `0003…`; not the same as GDID |
| **DeviceAdd** | Passport SOAP registration to `login.live.com/ppsecure/deviceaddcredential.srf` |
| **DDS** | Device Directory Service — MS graph of user↔device associations (`cs.dds.microsoft.com`, etc.) |
| **CDP** | Connected Devices Platform — Windows client (`cdp.dll`, `CDPSvc`) for cross-device + DDS registration |
| **MSA** | Microsoft Account |
| **wlidsvc** | Windows Live ID / Microsoft Account service — mints device identity |
| **DO** | Delivery Optimization — reports `UCDOStatus.GlobalDeviceId` |
| **IdentityCRL** | Registry identity store under `Software\Microsoft\IdentityCRL` |
| **x-device-token** | MSA device ticket used e.g. for Autopilot ZTD calls |
| **ZTD** | Zero Touch Deployment / Autopilot path via `ztd.dds.microsoft.com` |

## Confidence tags

| Tag | Meaning |
|-----|---------|
| `[COURT]` | Stated in legal filings / MS rep via affidavit |
| `[MSDOC]` | Microsoft Learn / official endpoint docs |
| `[STATIC]` | From binaries / public PDBs / strings |
| `[OBSERVED]` | Reproduced on a real machine (ours or cited RE) |
| `[ASSESSED]` | Strong inference; needs more proof |
