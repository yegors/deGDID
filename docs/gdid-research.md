# Microsoft GDID Research Notes

Last updated: 2026-07-11

## Status

- **Repo purpose:** deep research of GDID-class Microsoft device tracking + practical countermeasures. See [`plan.md`](./plan.md).
- This file is news + quick findings. Deep map lives in:
  - [`architecture.md`](./architecture.md) - when/how IDs are generated, network I/O
  - [`surfaces.md`](./surfaces.md) - threat/storage/endpoint inventory
  - [`threat-model.md`](./threat-model.md) - adversaries & limits
  - [`glossary.md`](./glossary.md) / [`open-questions.md`](./open-questions.md)
- Project tooling: root [`degdid.ps1`](../degdid.ps1) (public); lab helpers under `tools/`.

---

## Latest news (July 2026)

**Trigger event:** DOJ unsealed a superseding criminal complaint against **Peter Stokes** (19, dual US-Estonian), alleged Scattered Spider / Octo Tempest member. Arrested in Helsinki ~2026-04-10 boarding a flight to Japan; charged in N.D. Illinois (Chicago).

**Why it blew up:** Affidavit cites Microsoft **Global Device Identifier (GDID)** telemetry as a key attribution link - even when the suspect used VPN (Tzulo) and tunneling (ngrok).

### Timeline (from reporting + court summary)

| When | What |
|------|------|
| ~2015 | GDID / related infra present since Windows 10 era |
| Oct 2024 | Microsoft criminal referral to DOJ implicating Stokes |
| May 12, 2025 19:21 UTC | GDID `g:6755467234350028` hits ngrok signup at same second as account creation |
| Apr 10, 2026 | Arrest in Finland |
| ~Jul 1, 2026 | Complaint unsealed; GDID goes viral in security press |
| Jul 7, 2026 | Broad coverage (Register, Digital Trends, Cybernews, etc.) |

### What investigators did with GDID

1. Got IP / account records from ngrok + VPN provider.
2. Asked Microsoft for records tied to a specific GDID.
3. Matched exact timestamps (e.g. ngrok signup page visit).
4. Correlated GDID IP history with Snapchat / Facebook / Apple account IPs and travel records (Estonia, NYC, Thailand, etc.).

**Microsoft's own definition (court, via MS representative):** persistent, device-level ID that uniquely identifies a **Windows installation** (physical or VM) across certain Microsoft services. Survives OS updates; **reinstall -> new GDID**.

### Press / community reaction

- Surprise that MS can correlate install ID with third-party site visits / IP history under lawful process.
- No consumer opt-out toggle; no dedicated GDID transparency report called out in coverage.
- Viral myths (128-bit hardware-serial hash) are **wrong** per court text + reverse engineering.

### Key sources

- [The Register - Windows GDID / Stokes](https://www.theregister.com/cyber-crime/2026/07/07/windows-is-watching-anti-piracy-tool-fingers-scattered-spider-suspect/5267953)
- [Digital Trends - GDID tracking](https://www.digitaltrends.com/computing/your-windows-pc-has-been-quietly-tracking-you-and-a-hackers-arrest-just-made-it-public/)
- [CyberScoop - Stokes extradition](https://cyberscoop.com/scattered-spider-peter-stokes-cybercrime-extradition/)
- [Cybernews - telemetry backlash](https://cybernews.com/security/windows-telemetry-gdid-helps-arrest-hacker/)

---

## Official Microsoft documentation (thin)

Microsoft barely documents GDID publicly. The main named surface is Delivery Optimization / Update Compliance reporting:

### `UCDOStatus.GlobalDeviceId`

- **Docs:**
  - [WUfB reports schema - UCDOStatus](https://learn.microsoft.com/en-us/windows/deployment/update/wufb-reports-schema-ucdostatus)
  - [Azure Monitor - UCDOStatus](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/ucdostatus)
- **Type:** string
- **Example:** `g:9832741921341`
- **Description (verbatim MS):** "Microsoft global device identifier. This identifier is used by Microsoft internally."
- Sits beside geo/IP-ish fields: `City`, `Country`, `ISP`, `LastCensusSeenTime`.
- Used in KQL examples as `count_distinct(GlobalDeviceId)` for DO bandwidth reporting.
- **Important:** DO **reports** the ID; it does **not** own/mint it.

There is **no** consumer-facing Learn page titled "Global Device Identifier" explaining purpose, retention, LE sharing, or opt-out.

## Research delta - 2026-07-11

### Response fields and hardware correlation

- Build-26200 public-PDB RE identifies the `wlidsvc.dll` response parse target as
  `ps:DeviceUpdatePropertiesResponse/HWPUIDFlipped`; `<ps:DevicePUID>` is also
  present in its schema/string material. `[STATIC]`
- A separate Autopilot DeviceAdd capture observes `HWDeviceID` and
  `GlobalDeviceID` in its SOAP response. Treat that as a flow-specific capture,
  not proof of one immutable response schema across consumer, anonymous, 24H2, and
  25H2 paths. `[OBSERVED]`
- DeviceAdd supplies durable hardware inputs (EKPub, SMBIOS serial, OfflineDeviceID,
  TPM material). Autopilot demonstrates that a separate Microsoft backend can match
  an uploaded hardware hash after it receives the device token; it does **not**
  prove the GDID service joins reinstalls or quantify that join's confidence.
  `[OBSERVED]` `[ASSESSED]`

### Public policy / product boundary

- A targeted 2026-07-11 review of Microsoft Docs, News, and CSR found no
  GDID-specific post-Stokes statement, opt-out, or retention schedule. The
  [Privacy Statement](https://www.microsoft.com/en-us/privacy/privacystatement)
  says periods vary by data/purpose and can be extended for legal preservation; the
  [government-request report](https://www.microsoft.com/en-us/corporate-responsibility/reports/government-requests/customer-data)
  describes process, not a
  GDID/IP/URL duration. `[MSDOC]` `[ASSESSED]`
- The supported managed control is
  [`Connectivity/AllowConnectedDevices=0`](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-connectivity),
  which disables CDP after reboot.
  Microsoft explicitly warns that related blocks can disrupt the Entra sign-in
  option during Autopilot pre-provisioning. This is a post-enrollment pilot
  candidate, not a claim of Entra-safe suppression. `[MSDOC]`
- [Recall](https://learn.microsoft.com/en-us/windows/client-management/manage-recall)
  is a separate, opt-in local snapshot system in Microsoft's documentation:
  processing and storage are local, encrypted, and snapshots are not sent to
  Microsoft. No public Recall material found names GDID, DDS, or CDP. That limits
  the claimed link; it does not prove every unrelated Windows service stops
  reporting GDID while Recall is enabled. `[MSDOC]`

### What remains deliberately unclaimed

The court reporting establishes GDID â†” URL/time/IP association, but does not name the
Windows component, telemetry endpoint, browser, or retention period. It therefore
does not resolve SmartScreen vs DiagTrack vs another channel, Edge vs Chrome vs curl,
or whether a DO *content* request carries GDID. Those need controlled, consented lab
captures; the public [DO schema](https://learn.microsoft.com/en-us/windows/deployment/update/wufb-reports-schema-ucdostatus)
only proves a `GlobalDeviceId` reporting snapshot.
`[COURT]` `[MSDOC]` `[ASSESSED]`

---

## Technical model (summary)

Full pipeline, timing, and network I/O: **[`architecture.md`](./architecture.md)**.  
Surface inventory: **[`surfaces.md`](./surfaces.md)**.

One-liner: server-assigned 64-bit Device PUID (`g:<decimal>`), minted via `login.live.com` DeviceAdd (hardware sent as ceremony input), stored in IdentityCRL, announced by CDP into DDS, reported by DO as `GlobalDeviceId`. Local account still gets one (anonymous CDP path). VPN does not hide installâ†”Microsoft correlation.

Primary RE: [gdid-reversal](https://github.com/SmtimesIWndr/gdid-reversal). DeviceAdd traffic notes: [Windows-GDID-Changer](https://github.com/gd03gd031/Windows-GDID-Changer). Autopilot sibling: [Call4Cloud](https://call4cloud.nl/autopilot-profile-x-device-token-autopilot-marker/).

### Read your own

```powershell
$hex = (Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\IdentityCRL\ExtendedProperties').LID
"g:$([Convert]::ToUInt64($hex,16))"
```

**Do not publish your value.**

---

## Myths vs facts

| Claim | Verdict |
|-------|---------|
| 128-bit ID from hardware serials | **False** - 64-bit server PUID; reinstall changes it |
| VPN hides you from GDID correlation | **False** for MS-side records under lawful process |
| Only Microsoft sites are linked | **False in practice** - complaint tied GDID to ngrok signup / VPN IPs / browsing timestamps |
| Official opt-out toggle | **None known** |
| Public MS docs explain LE use | **No** - only internal DO reporting field |
| Exists since Win10 | **Likely** (infra ~2015; public naming sparse until ~2021+) |

---

## Open questions / next research

See **[`open-questions.md`](./open-questions.md)** for the living backlog.

Top gaps: exact raw response schema on current consumer/anonymous paths; exact
URLâ†”GDID sensor from Stokes; browser/client differential lab; full device-token
scope/claim map; and evidence of (or a bound on) server-side cross-reinstall joins.

---

## Project notes

- North star: [`plan.md`](./plan.md) - research -> measure -> countermeasures -> tooling.
- Use this file as findings memory; update when local/lab evidence changes.
- Do not commit real GDIDs, hostnames, usernames, or credentials - see `.gitignore` / redact experiment dumps.
