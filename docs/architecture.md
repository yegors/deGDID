# GDID Architecture — Generation, Lifecycle, Correlation

Last updated: 2026-07-11  
Confidence tags: `[COURT]` `[OBSERVED]` `[STATIC]` `[ASSESSED]` `[MSDOC]`

## Executive model

GDID is **not** a local hash of your GPU serial. It is a **server-assigned 64-bit Device PUID**, formatted as `g:<decimal>`, that Microsoft uses as a stable key for a Windows *installation* across identity, device-graph, and reporting systems.

```
┌─────────────┐   DeviceAdd / provision    ┌──────────────────┐
│  Windows    │ ─────────────────────────► │ login.live.com   │
│  install    │   (+ hardware DeviceInfo)  │ (Passport/MSA)   │
└─────────────┘                            └────────┬─────────┘
                                                    │ assigns Device PUID
                                                    ▼
                                           store locally (IdentityCRL)
                                                    │
                                                    ▼
┌─────────────┐   RegisterUserDevice       ┌──────────────────┐
│ CDPSvc /    │ ─────────────────────────► │ DDS graph        │
│ cdp.dll     │   auth: device tokens      │ dds / cs.dds …   │
└─────────────┘                            └────────┬─────────┘
                                                    │ keys as g:<PUID>
                    ┌───────────────────────────────┼────────────────┐
                    ▼                               ▼                ▼
            activity.windows.com            UCDOStatus DO        other MS
            (activity / timeline)           GlobalDeviceId       services
```

---

## 1. What the identifier is

| Property | Value | Tag |
|----------|-------|-----|
| Public name | Global Device Identifier (GDID) | `[COURT]` |
| Wire/server form | `g:` + decimal integer | `[COURT]` `[OBSERVED]` |
| Local form | 16 hex digits Device PUID (often `0018…`) | `[OBSERVED]` `[STATIC]` |
| Width | 64-bit | `[COURT]` (value fits) `[STATIC]` |
| Scope | One Windows **installation** (physical or VM) | `[COURT]` |
| Survives | Normal OS updates | `[COURT]` |
| Changes on | Full Windows reinstall (new install → new GDID) | `[COURT]` |
| User multiplicity | One MSA user can have many GDIDs | `[COURT]` footnote |
| Official consumer docs | Essentially none; DO schema one-liner | `[MSDOC]` |

Court example: `g:6755467234350028` → hex `0x0018000FC8CB93CC`.

**Namespace hint:** device PUIDs commonly sit in `0018…` class; user MSA PUIDs often `0003…`. `[OBSERVED]` `[STATIC]`

---

## 2. When it is generated

### 2.1 First mint (post-install / OOBE)

`[ASSESSED]` from Autopilot + GDID-Changer traffic analysis + RE:

1. After install (OOBE or first boot), Windows performs **device registration** with MSA Passport infrastructure — **even without signing into a Microsoft Account**. `[ASSESSED]` / community `[OBSERVED]` on local-account VMs.
2. Client POSTs a Passport SOAP **`DeviceAddRequest`** to:
   ```
   https://login.live.com/ppsecure/deviceaddcredential.srf
   ```
3. Request body includes **`DeviceInfo` components** (EKPub, SMBIOS serial, OfflineDeviceID, disk, TPM material, etc.) — hardware is *input to the registration ceremony*, not the GDID itself. `[OBSERVED]` (Autopilot capture) `[ASSESSED]` (component decoding)
4. The response field name is **flow-specific**:
   - Public-PDB RE of Win11 build 26200 `wlidsvc.dll` shows the Device-PUID parser targeting `/S:Envelope/S:Body/ps:DeviceUpdatePropertiesResponse/HWPUIDFlipped`. `[STATIC]`
   - An Autopilot DeviceAdd capture shows `HWDeviceID` and `GlobalDeviceID` in its response. `[OBSERVED]`
   - `<ps:DevicePUID>` is a code/schema string; it is not, by itself, proof that every current response exposes a separate `DevicePUID` element. `[STATIC]`
5. Client persists the PUID into IdentityCRL / identity store. `[OBSERVED]` `[STATIC]`

Autopilot-adjacent sibling flow (same mint family, enterprise path):

```
DeviceAddRequest → login.live.com
  → HWDeviceID + GlobalDeviceID
  → RST2.srf security token (x-device-token)
  → ztd.dds.microsoft.com Autopilot bootstrap (uses token, not raw hash)
```

`[OBSERVED]` source: Call4Cloud Autopilot traffic capture. Same `login.live.com` DeviceAdd surface; DDS-family host `ztd.dds.microsoft.com`.

### 2.2 Triggers for (re)registration / use

| Trigger | What happens | Tag |
|---------|--------------|-----|
| Fresh install / OOBE | First DeviceAdd → new GDID | `[COURT]` `[ASSESSED]` |
| CDP service start / state clear | `RegisterUserDeviceAsync` (reason: Startup) to DDS | `[OBSERVED]` (RE ETW) |
| MSA sign-in / account link | MSA path; tokens for DDS + activity | `[STATIC]` `[OBSERVED]` |
| Forced re-provision (clear sessions) | New server PUID possible on same hardware | `[ASSESSED]` (GDID-Changer) |
| OS feature update | GDID **kept** | `[COURT]` |
| Full wipe + reinstall | New GDID | `[COURT]` |

### 2.3 MSA vs anonymous / local account

- Early RE focused on MSA Device PUID via `wlidsvc`. `[STATIC]`
- Later correction: **CDP has an anonymous device path** if no MSA is connected; local account does **not** mean “no GDID.” `[ASSESSED]`
- **`[OBSERVED]` EXP-B (lab):** On a local-account Win11 25H2 image, after registration blocks were removed, a shared `0018…` Device PUID appeared in **SYSTEM and `.DEFAULT`** within ~2 minutes **without** MSA and **without** HKCU `ExtendedProperties\LID`. Inspect tools must read machine hives, not only HKCU.

---

## 3. How it is minted (MSA path — best documented)

### 3.1 Binary: `wlidsvc.dll` (Microsoft Account / Passport)

`[STATIC]` symbols / behavior:

- `CDeviceIdentityBase::CreateNewDeviceIdentity` / `Provision` / `BindDeviceToHardware`
- `DeviceAssociateRequest` → Passport PPCRL SOAP → `login.live.com`
- Has `<ps:DevicePUID>` schema/string material; `CAssociateDeviceRequest::ParseResponseBody` targets `.../ps:DeviceUpdatePropertiesResponse/HWPUIDFlipped`
- `DeviceIdStore::LogToRegistry`
- `BCryptGenRandom` generates a **device authentication key** bound via `BindDeviceToHardware` — **not** the PUID/GDID

**Critical distinction:**

| Artifact | Origin | Role |
|----------|--------|------|
| Device PUID / GDID | **Server-assigned** | Public-ish install fingerprint (`g:…`) |
| Device key / cert material | Local random + hardware bind | Authenticates as *this* device to MSA |

DeviceAdd sends durable hardware material, and the separate Autopilot service can match an
uploaded hardware hash after receiving a device token. This proves that Microsoft has
the *capability* to correlate hardware-backed registrations; it does **not** show that
the GDID backend joins old/new installations, or how strong such a join would be.
`[OBSERVED]` `[ASSESSED]` GDID is still not `hash(serials)` — reinstall proves that (`[COURT]`).

### 3.2 Consumer: CDP does not compute the ID

`[STATIC]` `cdp.dll`:

- `GetStableDeviceIdFromProvider` → identity provider COM
- `OnGetStableDeviceIdCompleted` stores opaque string
- Formats graph id as `"g:%s"`
- `DdsRegistrationClient` / `RegisterUserDeviceAsync` → DDS

ETW observation on forced re-register (`[OBSERVED]` RE):

```
DdsClient::RegisterUserDeviceAsync()  RegistrationReason: Startup  Account Type: MSA
DDSClient: Registration response received. HTTP status code: 200
GetDeviceIdAndTicketActivity -> deviceid: 0018…
```

---

## 4. Where it lives locally

Primary user-readable copy (`[OBSERVED]` on an online Win11 workstation + RE):

```
HKCU\SOFTWARE\Microsoft\IdentityCRL\ExtendedProperties
  LID = <16 hex Device PUID>

HKCU\SOFTWARE\Microsoft\IdentityCRL\Immersive\production\Token\<client>\
  DeviceId = same PUID
  DeviceTicket = per-client auth blob  (do not casually dump)
```

Also observed on a typical online install (`[OBSERVED]`):

| Location | Notes |
|----------|-------|
| `HKEY_USERS\.DEFAULT\…\IdentityCRL\ExtendedProperties\LID` | Machine/default hive; `0018` prefix |
| `HKEY_USERS\S-1-5-18\…\IdentityCRL\ExtendedProperties\LID` | SYSTEM; `0018` prefix |
| `HKLM\SOFTWARE\Microsoft\IdentityCRL\NegativeCache\<PUID>_…\` | Token/throttle caches keyed by device PUID |
| `%LOCALAPPDATA%\ConnectedDevicesPlatform\` | CDP state (`.cdp` files); wiping alone does **not** clear PUID |
| Feedback Hub → Settings → Device Information | UI display of global device id (community) |
| IrisService registry JSON | May embed `GLOBALDEVICEID` / `g:` in cached payloads |

**Token dir roles (online sample):** mix of AppContainer SIDs (Store, Client.CBS, ContentDeliveryManager) and MSA client GUIDs (CDP/Live SSL, Settings, Outlook, built-in OnlineId clients). Same `DeviceId` stamped on each ticket. See `surfaces.md`.

---

## 5. Network I/O — what talks, when

### 5.1 Mint / identity

| When | Host / URL | Purpose | Tag |
|------|------------|---------|-----|
| First provision / re-provision | `login.live.com` especially `/ppsecure/deviceaddcredential.srf` | DeviceAdd; provisions PUID (response field varies by flow; see §2.1) | `[ASSESSED]` `[MSDOC]` device auth |
| Token / STS | `login.live.com` `/RST2.srf` (and related) | Device security tokens | `[ASSESSED]` |
| Ongoing MSA | `*.login.live.com` | Account + device auth | `[MSDOC]` |

### 5.2 Device graph (DDS) / CDP

| Host | Role | Tag |
|------|------|-----|
| `cs.dds.microsoft.com` | DDS associations; currently chains through Traffic Manager to Azure Front Door | `[MSDOC]` `[OBSERVED]` |
| `dds.microsoft.com` | Referenced in `cdp.dll`; bare name currently returns DNS NODATA (no A/AAAA) | `[STATIC]` `[OBSERVED]` |
| `fd.dds.microsoft.com` | In `cdp.dll`; current NXDOMAIN, role not publicly documented | `[STATIC]` `[OBSERVED]` |
| `aad.cs.dds.microsoft.com` | AAD-flavored DDS; currently chains through Traffic Manager to Azure Front Door | `[STATIC]` `[OBSERVED]` |
| `cdpcs.access.microsoft.com` | In `cdp.dll`; current NXDOMAIN, role not publicly documented | `[STATIC]` `[OBSERVED]` |
| `ztd.dds.microsoft.com` | Autopilot / ZTD bootstrap; currently chains through Traffic Manager to a regional Autopilot Azure host | `[OBSERVED]` |

**When:** CDP registration on startup / after state loss; ongoing graph sync for Phone Link, nearby share, continue-on-PC style features. `[OBSERVED]` ETW Startup registration; `[MSDOC]` DDS purpose.

**Configured-resolver DNS snapshot (2026-07-11):** `cs.dds.microsoft.com` →
`dgsdeviceregistrationsatm.trafficmanager.net` → `dgs-registration-endpoint-…b02.azurefd.net`
→ `mr-b02.tm-azurefd.net` (A `150.171.110.23`, AAAA `2603:1061:14:116::1`).
`aad.cs.dds.microsoft.com` takes the analogous `dgscontinuumonlyatm` chain (A
`150.171.109.69`, AAAA `2603:1061:14:115::1`). `ztd.dds.microsoft.com` →
`aps.trafficmanager.net` → regional `autopilotservice-prod-*.cloudapp.azure.com`
(one answer `74.241.231.0`). `fd.dds.microsoft.com` and
`cdpcs.access.microsoft.com` returned NXDOMAIN. `[OBSERVED]` DNS routing is
resolver/region/time dependent; do not treat these addresses as an allow/block list.

**Auth scopes observed in token cache (`[OBSERVED]` RE):**

```
service::dds.microsoft.com::MBI_SSL_TOKEN_BROKER
service::activity.windows.com::MBI_SSL_SA_TOKEN_BROKER
```

Also seen near CDP client id: `service::ssl.live.com::MBI_SSL` / roaming key purposes. `[STATIC]` / local Settings handler strings.

These scope strings establish requested service audiences, **not** a readable claim map:
the protected ticket format has not been decoded, so the complete set of scopes that
carry or require a Device PUID remains open. `[ASSESSED]`

### 5.3 Activity / timeline

| Host | Role | Tag |
|------|------|-----|
| `activity.windows.com` | Activity Feed — cross-device roaming | `[MSDOC]` |
| `assets.activity.windows.com` | Activity assets | `[MSDOC]` |
| `edge.activity.windows.com` | Edge-related activity | `[MSDOC]` |

**When:** when Activity History / timeline / cross-device features are enabled and CDP/identity can authenticate. Turning Activity History off is a documented exposure-reduction lever (`[ASSESSED]` RE §8).

### 5.4 Delivery Optimization / Update Compliance reporting

| Surface | Role | Tag |
|---------|------|-----|
| DO cloud / WUfB reports | `UCDOStatus.GlobalDeviceId` column | `[MSDOC]` |
| DO download hosts | e.g. `*.dl.delivery.mp.microsoft.com`, `geo.prod.do.dsp.mp.microsoft.com` | `[OBSERVED]` local DO jobs |

DO **reports** GDID; it does not mint it. Rows sit beside `City`, `Country`, `ISP`, `LastCensusSeenTime`, and `TimeGenerated` is the snapshot time. `[MSDOC]`

This is evidence of a reporting channel, **not** evidence that each DO content request
has a GDID HTTP header. Public DO API documentation exposes caller-provided custom
headers but not Windows' internal service headers; a controlled wire capture is still
needed for that claim. `[MSDOC]` `[ASSESSED]`

**When:** devices participating in Delivery Optimization / Update Compliance telemetry pipelines (enterprise reports more visible; consumer still runs `dosvc`).

### 5.5 Broader telemetry (adjacent, not proven GDID carriers)

| Host | Role | Tag |
|------|------|-----|
| `v10.events.data.microsoft.com` | Diagnostic data / Connected User Experiences | `[MSDOC]` |
| `settings-win.data.microsoft.com` | Settings / config | DNS `[OBSERVED]` |

Whether these payloads embed GDID specifically is **not fully proven** in our notes — treat as adjacent census/telemetry until lab-confirmed. `[ASSESSED]`

### 5.6 What the Stokes case implies about “browsing” records

`[COURT]`: Microsoft produced records that a **specific GDID** accessed URLs (e.g. ngrok signup) at precise UTC timestamps, and accessed VPN provider IPs, plus IP history usable for correlation.

**Interpretation (careful):**

- Does **not** require that Edge sent GDID in clear to ngrok.
- **Does** require that Microsoft retained **some** association of GDID ↔ time ↔ destination/IP (OS networking telemetry, defender/smartscreen-class signals, DO/census, or other MS-side correlation — exact channel not named in press summaries).
- VPN hides path from *destination*; it does **not** hide the install’s talks to Microsoft. `[ASSESSED]` (IBTimes / Register framing)

The available court reporting identifies the **result**, not the responsible Windows
component, browser, telemetry endpoint, or retention duration. It therefore cannot
support a conclusion about Edge vs Chrome vs curl. `[COURT]` `[ASSESSED]`

---

## 6. Correlation graph (threat-relevant)

```
                    ┌──────────────┐
                    │  GDID g:…    │
                    └──────┬───────┘
           ┌───────────────┼───────────────┐
           ▼               ▼               ▼
    IP / geo history   MSA account(s)   Activity / DDS
    (DO City/ISP,      (user PUID 0003)  device graph
     case IP trail)
           │               │               │
           └───────────────┼───────────────┘
                           ▼
              third-party logs (VPN, ngrok)
              + warrants on Snap/FB/Apple
                           ▼
                    real-world identity
```

Additional residual links (`[ASSESSED]`):

- Same MSA after reinstall → multiple GDIDs footnoted in court; easy join on account.
- Hardware/TPM material in DeviceAdd → possible server-side “same machine?” matching across PUIDs.
- Advertising IDs, Entra device IDs, Autopilot hardware hash — parallel identity planes.

---

## 7. Services & binaries (runtime)

| Component | Role |
|-----------|------|
| `wlidsvc.dll` / service `wlidsvc` | Mint / MSA device identity |
| `cdp.dll` / `CDPSvc` + `CDPUserSvc` | DDS registration, cross-device |
| `dosvc` | DO; reports GlobalDeviceId upstream |
| `TokenBroker` | Web account tokens |
| `DiagTrack` | Diagnostic pipeline (adjacent) |
| OnlineId / Settings / Store / Outlook / Client.CBS | Consumers of device tickets stamped with DeviceId |

**Online workstation sample:** `CDPSvc` Running/Automatic; `wlidsvc` demand-start; `dosvc` / `DiagTrack` / `TokenBroker` typically running; `LID` present in HKCU + `.DEFAULT` + SYSTEM once minted.

---

## 8. Lifecycle summary

1. **Birth:** DeviceAdd to `login.live.com` (hardware DeviceInfo in; PUID out).
2. **Persist:** IdentityCRL `LID` / Token `DeviceId` / SYSTEM & default hives.
3. **Announce:** CDP registers `g:PUID` into DDS; obtains/uses scoped device tokens.
4. **Emit:** Activity, DO/compliance, and other MS services key telemetry on that id.
5. **Survive:** Feature updates keep it.
6. **Death (local):** Reinstall or successful forced re-provision → new PUID locally.
7. **Death (server):** Old GDID records may remain on Microsoft side (`[ASSESSED]`); local wipe does not erase history.

---

## 9. Sources

- DOJ / Stokes complaint language via Register, PCMag, Cyberpress
- [gdid-reversal](https://github.com/SmtimesIWndr/gdid-reversal) (ETW + PDB)
- [Windows-GDID-Changer README](https://github.com/gd03gd031/Windows-GDID-Changer) (DeviceAdd capture notes)
- [Call4Cloud Autopilot / x-device-token](https://call4cloud.nl/autopilot-profile-x-device-token-autopilot-marker/)
- [UCDOStatus schema](https://learn.microsoft.com/en-us/windows/deployment/update/wufb-reports-schema-ucdostatus)
- [Windows 11 endpoints (non-Enterprise)](https://learn.microsoft.com/en-us/windows/privacy/windows-11-endpoints-non-enterprise-editions)
- [MS-CDP protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cdp/f5a15c56-ac3a-48f9-8c51-07b2eadbe9b4)
- [Connectivity Policy CSP — AllowConnectedDevices](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-connectivity)
- [Microsoft Privacy Statement](https://www.microsoft.com/en-us/privacy/privacystatement)
- Local observation on Win11 26200-class lab/workstation samples (redacted)
