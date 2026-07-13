# GDID Threat / Attack Surface Map

Last updated: 2026-07-13

Inventory of places GDID (or its Device PUID twin) is stored, computed against, emitted, or correlated. Companion to `architecture.md`.

The inventory is broader than the tool's release claim. The GDID-only completion
boundary is continuous DeviceAdd blocking plus removal of known active real PUID
state on a supported unmanaged, single-user Windows system. General telemetry
suppression and the exact Stokes URL sensor remain research.

---

## 1. Local persistence surfaces

### 1.1 Registry — identity store

| Path | Value | Access | Notes |
|------|-------|--------|-------|
| `HKCU\SOFTWARE\Microsoft\IdentityCRL\ExtendedProperties` | `LID` | User | Primary readable Device PUID |
| `HKCU\SOFTWARE\Microsoft\IdentityCRL\Immersive\production\Property` | value name = LID hex | User | **Required wipe-bundle member / high-confidence rehydrate store** (~346B). It was mapped before the successful expanded wipe, but unique causality was not isolated (`EXP-C3`; ablation open). |
| `HKCU\SOFTWARE\Microsoft\IdentityCRL\Immersive\production\Token\*` | `DeviceId`, `DeviceTicket` | User | Per-client tickets; same DeviceId |
| Target-user Credential Manager | `MicrosoftAccount:target=SSO_POP_Device`; `WindowsLive:target=virtualapp/didlogical` | User | Device credentials present on MSA-connected profiles; EXP-H observed the same old user LID rehydrate after the earlier registry/file bundle was cleared. Targeted cleanup added; causal rerun pending. |
| SYSTEM Credential Manager | `WindowsLive:target=virtualapp/didlogical` (and any matching device target) | SYSTEM | Found after the second delayed EXP-G machine-LID return; local machine credential source candidate, with failed network token attempts |
| `HKCU\SOFTWARE\Microsoft\IdentityCRL\UserExtendedProperties` | (account props) | User | User-side MSA props |
| `HKEY_USERS\.DEFAULT\Software\Microsoft\IdentityCRL\ExtendedProperties` | `LID` | Elevated | Default profile; often present once minted |
| `HKEY_USERS\S-1-5-18\Software\Microsoft\IdentityCRL\ExtendedProperties` | `LID` | SYSTEM | SYSTEM copy; often present once minted |
| `.DEFAULT` / SYSTEM `IdentityCRL\Immersive\production\Property` | value name = device PUID | Elevated | Delayed EXP-G machine-hive rehydrate store; same pattern as target-user Property |
| `.DEFAULT` / SYSTEM `IdentityCRL\Immersive\production\Token\*` | `DeviceId`, `DeviceTicket` | Elevated | Delayed EXP-G found nine DeviceId copies in each machine hive |
| `HKLM\SOFTWARE\Microsoft\IdentityCRL\NegativeCache\<PUID>_*\` | cache keys | SYSTEM | Keyed by device PUID; scopes/tokens |
| `HKLM\SOFTWARE\Microsoft\IdentityCRL\ThrottleCache\*` | throttle | SYSTEM | Often includes client GUID |
| `HKLM\SOFTWARE\Microsoft\IdentityStore\Providers\*` | providers | SYSTEM | MSA / AzureAD provider registration |

The identity-store rows above are `[LAB]` unless otherwise stated. EXP-C3 cleared
Property, Token, LID, and other known state as one bundle; it did not prove that
Property alone performed the rehydrate. The conservative canonical wipe keeps the
whole bundle. Decoy mode is experimental.

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
| `{67082621-8D18-4333-9C64-10DE93676363}` | WebView2-associated ticket: independent cited sandbox traces show `msedgewebview2.exe` reading its `DeviceId` / `DeviceTicket`; exact app-registration display name remains unpublished `[CITED-RE]` |
| `{C89E2069-AF13-46DB-9E39-216131494B87}` | CloudApp (CloudPlus) MSA client association — IdentityCRL negative-cache entry is scoped to `tip.cloudapp.net`; not an inbox-Windows attribution `[ASSESSED]` |
| `{F0C62012-2CEF-4831-B1F7-930682874C86}` | Microsoft Store licensing / `WinStoreAuth`: debug output calls `WinStoreAuth::AuthenticationInternal::SetMsaClientId` with this value `[STATIC]` |

The first two are source associations, not decoded ticket contents; do not infer their
scopes or privileges from the registry key alone.

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
| `wlidsvc` | Manual / demand-start | DeviceAdd client & MSA device identity; server assigns the PUID |
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
| `login.live.com` `/ppsecure/deviceaddcredential.srf` | Out HTTPS | Install, re-provision | **Provisions** Device PUID (response field varies by flow) `[CITED-RE]` |
| `login.live.com` `/RST2.srf` (+ related) | Out HTTPS | Token issue | Device tokens carrying/binding id |
| `*.login.live.com` | Out HTTPS | Ongoing MSA | Device auth |
| `cs.dds.microsoft.com` | Out HTTPS | DDS associations | Current Traffic Manager → Azure Front Door route `[MSDOC]` `[LAB]` |
| `dds.microsoft.com` | Logical DDS service name | CDP string | Bare name is currently DNS NODATA (no A/AAAA) `[STATIC]` `[LAB]` |
| `aad.cs.dds.microsoft.com` | Out HTTPS | AAD DDS | Current Traffic Manager → Azure Front Door route `[LAB]` |
| `fd.dds.microsoft.com` | Static string | Unknown | Current NXDOMAIN; legacy/role remains unproven `[STATIC]` `[LAB]` |
| `cdpcs.access.microsoft.com` | Static string | Unknown | Current NXDOMAIN; legacy/role remains unproven `[STATIC]` `[LAB]` |
| `ztd.dds.microsoft.com` | Out HTTPS | Autopilot OOBE | Current Traffic Manager → regional Autopilot Azure host `[LAB]`; use of x-device-token `[CITED-RE]` |
| `activity.windows.com` | Out HTTPS | Activity feed | Token scope ties to device id |
| `assets.activity.windows.com` | Out | Activity assets | Adjacent |
| `edge.activity.windows.com` | Out | Edge activity | Adjacent |

#### Current tool hardening

The current script integrates three defense-in-depth layers:

1. a canonical hosts region with both `0.0.0.0` and `::` entries;
2. auto-resolving dynamic-keyword FQDN outbound firewall configuration for the
   registration and adjacent endpoint set, with address hydration reported rather
   than assumed; and
3. a separate outbound service rule for `wlidsvc`, the mint-critical service.

`-Protect` verifies the hosts state, firewall objects, and the
`login.live.com` mint path before running the canonical wipe. This describes the
current implementation, not a completed longitudinal result: 24-hour/multi-reboot
and MSA-contaminated 25H2 validation remain open. Windows 10 22H2/build 19045 and
Windows 11 builds other than the lab-validated 25H2/build-26200 line are accepted
generically but require separate closure matrices.

### 3.2 Reporting / delivery (known or likely carriers)

| Endpoint / system | Notes |
|-------------------|-------|
| Delivery Optimization / WUfB `UCDOStatus` | **Documented** `GlobalDeviceId` field in a reporting snapshot |
| `*.dl.delivery.mp.microsoft.com`, `geo.prod.do.dsp.mp.microsoft.com` | DO content path; public docs do not establish a GDID header on every download request |

### 3.3 Adjacent telemetry (confirm GDID embedding in lab)

| Endpoint | Official role |
|----------|---------------|
| `v10.events.data.microsoft.com` | Diagnostic data |
| `settings-win.data.microsoft.com` | Settings / config |
| `watson.telemetry.microsoft.com` | WER |

### 3.4 DNS snapshots

Resolved: `login.live.com`, `cs.dds.microsoft.com`, `aad.cs.dds.microsoft.com`, `activity.windows.com`, `ztd.dds.microsoft.com`, DO/geo hosts, `v10.events.data.microsoft.com`, `settings-win.data.microsoft.com`.  
Failed/empty: `fd.dds.microsoft.com`, `cdpcs.access.microsoft.com`, bare `dds.microsoft.com` A-record quirks.

On the configured resolver (2026-07-11), `cs.dds.microsoft.com` chained via
`dgsdeviceregistrationsatm.trafficmanager.net` to `mr-b02.tm-azurefd.net`;
`aad.cs.dds.microsoft.com` used the analogous `dgscontinuumonlyatm` chain; and
`ztd.dds.microsoft.com` chained via `aps.trafficmanager.net` to a regional
`autopilotservice-prod-*.cloudapp.azure.com` host. `fd.dds.microsoft.com` and
`cdpcs.access.microsoft.com` still returned NXDOMAIN; bare `dds.microsoft.com`
returned NODATA. `[LAB]`

No established TCP to those IPs at either idle snapshot. DNS answers are
resolver/region/time dependent, not endpoint policy.

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

### 6.1 Supported enterprise control

[`./Device/Vendor/MSFT/Policy/Config/Connectivity/AllowConnectedDevices = 0`](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-connectivity)
is the supported device-scope policy to make CDP unavailable after reboot.
`[MSDOC]` It is a CDP/cross-device control, not a server-history eraser or a
guarantee that every identity plane stops.

The Autopilot warning belongs to a different control. Microsoft says that
**[disabling the Microsoft Account Sign-in Assistant (`wlidsvc`)](https://learn.microsoft.com/en-us/autopilot/pre-provision)**
during Autopilot
pre-provisioning can hide the Microsoft Entra sign-in option and lead to the
EULA/local-account flow. That warning is not stated for
`AllowConnectedDevices`. `[MSDOC]`

The tool does not disable `wlidsvc`; it blocks the service's outbound traffic as
defense in depth. It makes no Autopilot-compatibility claim and refuses mutation on
domain-joined, Entra-joined/registered, or MDM-enrolled systems.

### 6.2 Recall boundary

No public Recall documentation names GDID, DDS, or CDP as part of its snapshot path.
Microsoft documents Recall as opt-in local processing/storage, with encrypted snapshots
not sent to Microsoft. `[MSDOC]` This narrows the claimed relationship but does not
prove that unrelated Windows services cannot emit a GDID while Recall is enabled.

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

## 8. Surface priority for the current tool

1. **Mint path** — continuously block `login.live.com` DeviceAdd; expect MSA/device-auth breakage
2. **Local continuity** — canonical expanded wipe of known active real PUID stores and known copies
3. **Graph announce** — CDP → DDS (`cs.dds.microsoft.com`, …), blocked as defense in depth
4. **Activity emit** — `activity.windows.com`, blocked as defense in depth
5. **Reporting** — DO/compliance GlobalDeviceId
6. **Unknown court channel** — URL/time association (open research, not a release gate)

Decoy mutation is experimental. General telemetry suppression is not part of the
tool's completion claim.
