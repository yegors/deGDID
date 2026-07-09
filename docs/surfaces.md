# GDID Threat / Attack Surface Map

Last updated: 2026-07-09

Inventory of places GDID (or its Device PUID twin) is stored, computed against, emitted, or correlated. Companion to `architecture.md`.

---

## 1. Local persistence surfaces

### 1.1 Registry — identity store

| Path | Value | Access | Notes |
|------|-------|--------|-------|
| `HKCU\SOFTWARE\Microsoft\IdentityCRL\ExtendedProperties` | `LID` | User | Primary readable Device PUID |
| `HKCU\SOFTWARE\Microsoft\IdentityCRL\Immersive\production\Token\*` | `DeviceId`, `DeviceTicket` | User | Per-client tickets; same DeviceId |
| `HKCU\SOFTWARE\Microsoft\IdentityCRL\UserExtendedProperties` | (account props) | User | User-side MSA props |
| `HKEY_USERS\.DEFAULT\Software\Microsoft\IdentityCRL\ExtendedProperties` | `LID` | Elevated | Default profile; often present once minted |
| `HKEY_USERS\S-1-5-18\Software\Microsoft\IdentityCRL\ExtendedProperties` | `LID` | SYSTEM | SYSTEM copy; often present once minted |
| `HKLM\SOFTWARE\Microsoft\IdentityCRL\NegativeCache\<PUID>_*\` | cache keys | SYSTEM | Keyed by device PUID; scopes/tokens |
| `HKLM\SOFTWARE\Microsoft\IdentityCRL\ThrottleCache\*` | throttle | SYSTEM | Often includes client GUID |
| `HKLM\SOFTWARE\Microsoft\IdentityStore\Providers\*` | providers | SYSTEM | MSA / AzureAD provider registration |

**Do not** treat Token `DeviceTicket` blobs as safe to log or commit — credential-adjacent.

### 1.2 Token directory clients (online Win11 sample)

**AppContainer SIDs (resolved):**

| Key | App |
|-----|-----|
| `S-1-15-2-…1760938157` | Microsoft Store |
| `S-1-15-2-…3374928651` | MicrosoftWindows.Client.CBS (Accounts, Iris, Spotlight, Cross-Device Resume, …) |
| `S-1-15-2-…1255436723` | Content Delivery Manager |

**GUID MSA client IDs:**

| GUID | Resolution |
|------|------------|
| `{12E984BD-5803-4D78-9EFB-BED7B9212C26}` | CDP / Live SSL / account sync (`cdp.dll`, SettingsHandlers_UserAccount, `ssl.live.com`) |
| `{4B0964E4-58F1-47F4-A552-E2E1FC56DCD7}` | Windows Settings (`SystemSettings.dll`) |
| `{5D661950-3475-41CD-A2C3-D671A3162BC1}` | New Outlook (`olkmain.dll`) |
| `{28520974-…}`, `{2B379600-…}`, `{D6D5A677-…}`, `{E8B2105F-…}` | Built into `wlidsvc` / OnlineId (system MSA clients) |
| `{E8B2105F-…}` | Sometimes present empty (no DeviceId/ticket) |
| `{67082621-…}`, `{C89E2069-…}`, `{F0C62012-…}` | **Unresolved** — not in readable Appx; likely more MSA service clients |

### 1.3 Filesystem

| Path | Role |
|------|------|
| `%LOCALAPPDATA%\ConnectedDevicesPlatform\` | CDP local state (`.cdp`, certs). Clear ≠ new GDID |
| Feedback Hub package | UI surfaces device info |
| Autopilot / `wmansvc` caches (enterprise) | Profile cache after ZTD; sibling of DDS world |

### 1.4 UI

- Feedback Hub → Settings → Device Information (global device id)
- Settings → Accounts / cross-device / Phone Link (depend on CDP/DDS)

---

## 2. Process / service surfaces

| Service / binary | Typical start | GDID role |
|------------------|---------------|-----------|
| `wlidsvc` | Manual / demand-start | Mint & MSA device identity |
| `CDPSvc` | Automatic / often Running | DDS registration, graph |
| `CDPUserSvc_*` | Automatic (per-user) | User CDP |
| `dosvc` | Automatic / often Running | Reports GlobalDeviceId in DO/compliance |
| `TokenBroker` | Manual / often Running | Web account broker |
| `DiagTrack` | Automatic / often Running | Diagnostic pipeline (adjacent) |
| `WpnService` | often Running | Push; may interact with MSA ecosystem |

CDP user settings sample: `RomeSdkChannelUserAuthzPolicy=1`, NearShare configurable, build-dependent stamps.

Telemetry policy sample (consumer): `AllowTelemetry` / `MaxTelemetryAllowed` often `1` unless hardened.

---

## 3. Network surfaces

### 3.1 High-priority (GDID mint / graph / activity)

| Endpoint | Direction | When | GDID relevance |
|----------|-----------|------|----------------|
| `login.live.com` `/ppsecure/deviceaddcredential.srf` | Out HTTPS | Install, re-provision | **Mints** GlobalDeviceID |
| `login.live.com` `/RST2.srf` (+ related) | Out HTTPS | Token issue | Device tokens carrying/binding id |
| `*.login.live.com` | Out HTTPS | Ongoing MSA | Device auth |
| `cs.dds.microsoft.com` | Out HTTPS | DDS associations | Official DDS endpoint `[MSDOC]` |
| `dds.microsoft.com` | Out HTTPS | CDP registration | In `cdp.dll` |
| `aad.cs.dds.microsoft.com` | Out HTTPS | AAD DDS | Resolved on lab |
| `fd.dds.microsoft.com` | Out | CDP strings | NXDOMAIN on lab (2026-07-09) |
| `cdpcs.access.microsoft.com` | Out | CDP strings | NXDOMAIN on lab |
| `ztd.dds.microsoft.com` | Out HTTPS | Autopilot OOBE | DDS family; uses x-device-token |
| `activity.windows.com` | Out HTTPS | Activity feed | Token scope ties to device id |
| `assets.activity.windows.com` | Out | Activity assets | Adjacent |
| `edge.activity.windows.com` | Out | Edge activity | Adjacent |

### 3.2 Reporting / delivery (known or likely carriers)

| Endpoint / system | Notes |
|-------------------|-------|
| Delivery Optimization / WUfB `UCDOStatus` | **Documented** `GlobalDeviceId` field |
| `*.dl.delivery.mp.microsoft.com`, `geo.prod.do.dsp.mp.microsoft.com` | DO content path; id reported in compliance channel not necessarily every download URL |

### 3.3 Adjacent telemetry (confirm GDID embedding in lab)

| Endpoint | Official role |
|----------|---------------|
| `v10.events.data.microsoft.com` | Diagnostic data |
| `settings-win.data.microsoft.com` | Settings / config |
| `watson.telemetry.microsoft.com` | WER |

### 3.4 Lab DNS check (2026-07-09)

Resolved: `login.live.com`, `cs.dds.microsoft.com`, `aad.cs.dds.microsoft.com`, `activity.windows.com`, `ztd.dds.microsoft.com`, DO/geo hosts, `v10.events.data.microsoft.com`, `settings-win.data.microsoft.com`.  
Failed/empty: `fd.dds.microsoft.com`, `cdpcs.access.microsoft.com`, bare `dds.microsoft.com` A-record quirks.

No established TCP to those IPs at snapshot time (idle).

---

## 4. Generation & emission timeline (surface view)

```
t0  Install / OOBE
    └─ DeviceAdd → login.live.com          [MINT]
    └─ optional Autopilot → ztd.dds…       [ENTERPRISE SIBLING]

t1  Persist LID / DeviceId locally         [STORE]

t2  CDPSvc start / user logon
    └─ RegisterUserDevice → DDS            [ANNOUNCE]
    └─ device tokens for dds + activity    [AUTH]

t3  Ongoing
    ├─ activity.windows.com                [EMIT / SYNC]
    ├─ DO / compliance GlobalDeviceId      [EMIT]
    ├─ Store / Settings / Outlook tickets  [USE]
    └─ ??? URL/IP association channel      [COURT IMPLICATION]

t4  Update
    └─ GDID unchanged                      [COURT]

t5  Reinstall or forced re-provision
    └─ new PUID locally; old may remain
       in MS backends                      [COURT] / [ASSESSED]
```

---

## 5. Correlation surfaces (non-local)

| Surface | How it joins |
|---------|--------------|
| Microsoft GDID IP / activity history | Case: timestamps + destinations + IPs |
| MSA account | User PUID / sign-in; multi-GDID footnote |
| VPN / tunnel provider logs | Independent; joined via time + IP |
| Consumer accounts (Snap, FB, Apple, …) | Warrants; IP overlap with GDID trail |
| Hardware/TPM from DeviceAdd | Possible cross-PUID “same device” `[ASSESSED]` |
| Entra device id / Autopilot hash | Parallel enterprise identity |
| Advertising ID / other Windows IDs | Parallel consumer identity |

---

## 6. Feature surfaces that *depend* on this stack

Disabling these reduces *use* of the graph (not always the existence of LID):

- Phone Link / linking Android
- Cloud clipboard / continue on PC
- Nearby Share (CDP NearShare policy)
- Activity History / timeline
- Some Store / Xbox / MSA SSO convenience
- Autopilot (enterprise) — separate but same DeviceAdd family

---

## 7. Parallel identifiers (don’t confuse)

| ID | Relation to GDID |
|----|------------------|
| MSA user PUID (`0003…`) | Account, not install |
| Entra / AAD device ID | Work/school device object |
| Autopilot hardware hash | Enrollment; DeviceAdd shares DNA |
| Advertising ID | Resettable consumer ad id |
| MachineGuid / SQM / etc. | Other local GUIDs — different systems |
| TPM EK | Hardware root; may be *sent* at mint |

---

## 8. Surface priority for countermeasures (preview)

1. **Mint path** — `login.live.com` deviceadd (hard to block without breaking MSA/device auth)
2. **Graph announce** — CDP → DDS (`cs.dds.microsoft.com`, …)
3. **Activity emit** — `activity.windows.com`
4. **Local continuity** — IdentityCRL `LID` + tickets
5. **Reporting** — DO/compliance GlobalDeviceId
6. **Unknown court channel** — URL/time association (lab needed)

Full mitigation design belongs in `countermeasures.md` (Phase 3).
