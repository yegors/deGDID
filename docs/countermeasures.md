# Countermeasures - Implemented Gate and Evidence

Last updated: 2026-07-11

Status: the hardened control path is implemented in root `degdid.ps1`. Historical Windows 11 25H2 build 26200 experiments support parts of the design, but the exact current rewrite has not yet completed an end-to-end guest validation pass.

## Objective

For a supported target, the operational objective is:

> No real server-issued GDID in the known active stores, with the DeviceAdd path blocked continuously.

The canonical implementation uses a stricter local check: after Wipe and settle, no `0018`-shaped PUID may remain in the known active inventory or matching residual registry cache, and the block gate must still be healthy.

This is a **GDID-only completion gate**. It does not claim to:

- erase Microsoft-held history;
- stop general Windows telemetry;
- suppress the unknown channel behind the court-reported GDID-to-URL/time/IP association;
- prevent correlation through MSA, IP history, hardware material, Entra IDs, advertising IDs, or other identity planes; or
- prove that the known-store inventory is exhaustive.

## Supported mutation boundary

Mutating actions other than Unblock require all of the following:

- Windows 11 build 22000 or newer; 25H2 build 26200 is the lab-validated line and other builds warn;
- unmanaged: no domain join, Entra join/registration/workplace join, or MDM enrollment;
- exactly one loaded target human-profile hive; dormant profile artifacts warn but do not refuse;
- an active interactive user, or an authenticated session that maps to the sole loaded profile;
- the target user's `HKEY_USERS\<SID>` hive loaded; and
- elevated administrator PowerShell.

`-Block`, `-Wipe`, `-Decoy`, and `-Protect` refuse unsupported, unknown,
multiple-loaded-profile, or unresolved-target states. Dormant profile artifacts are
reported without blocking the active target. `-Status` may inspect unsupported
systems and returns an explicit verdict. `-Unblock` deliberately bypasses the
target/profile preflight so recovery remains available after topology or management
state changes.

No compatibility claim in this document applies to domain, Entra, MDM, or simultaneous multi-loaded-profile mutation because the tool does not perform it.

## Strategy overview

| ID | Strategy | Current role | Main limitation |
|----|----------|--------------|-----------------|
| P1 | Offline OOBE, then block before first network access | Preferred prevention path | Current script needs a completed local profile and loaded interactive hive |
| P2 | Continuous verified DeviceAdd block | Required ongoing control | Identity and CDP workflows are expected to break; controls can drift |
| P3 | Expanded Wipe under a verified block | Canonical contaminated-system mutation | Known-store model is bounded; Microsoft history remains |
| P4 | `-Protect` = P2 then P3 | Preferred end-user path | Exact current rewrite still needs end-to-end VM validation |
| P5 | Local Decoy under a verified block | Experimental research path | Shape alone cannot prove local provenance; not a clean Status completion |
| P6 | Unblock degdid-owned network state | Recovery path | A future DeviceAdd can mint a real PUID |

Server-side first mint or remint is a control condition, not a privacy countermeasure.

## P1 - Prevent first mint

### Procedure

1. Complete OOBE offline with a local account.
2. Reach the desktop so the sole profile and interactive hive exist.
3. While still offline, run `.\degdid.ps1 -Block` from elevated PowerShell.
4. Confirm `ProtectedNoRealGdid` before enabling the NIC.
5. Keep the block gate continuous and recheck Status after relevant system changes.

An upstream gateway block can cover earlier setup traffic, but it is outside the current script.

### Evidence

- `[OBSERVED]` EXP-A1: at first desktop with the NIC disconnected, target-user, `.DEFAULT`, and SYSTEM `LID` stores were empty and no Token keys existed.
- `[OBSERVED]` EXP-A4: applying the then-current hosts block before first network access kept the inspected stores empty through a service bounce and about 90 seconds online; LiveId reported `0x800704CF`.
- `[OBSERVED]` EXP-B: removing those blocks from the never-minted image allowed a first machine-hive PUID to appear in about two minutes without MSA sign-in.

EXP-A4 is a short hosts-era observation. It does not prove indefinite prevention or validate the current dual-stack/path-verification implementation.

## P2 - Continuous DeviceAdd block

### Canonical FQDN set

The current script manages these exact names:

```text
login.live.com
account.live.com
cs.dds.microsoft.com
dds.microsoft.com
aad.cs.dds.microsoft.com
fd.dds.microsoft.com
cdpcs.access.microsoft.com
ztd.dds.microsoft.com
activity.windows.com
assets.activity.windows.com
edge.activity.windows.com
```

There is no wildcard hosts entry. The managed `hosts` region renders one `0.0.0.0` and one `::` line for every exact FQDN.

### Firewall controls

When local policy allows, the current implementation also:

1. creates one deterministic, auto-resolving Windows Firewall dynamic-keyword object for each FQDN;
2. creates one enabled outbound deny rule over the complete dynamic-keyword set; and
3. creates a separate enabled outbound deny bound to `svchost.exe` service `wlidsvc`.

These firewall objects are defense in depth rather than release gates. The dynamic
FQDN configuration avoids freezing one transient DNS snapshot, but an
AutoResolve rule is not enforced until addresses hydrate. In the first exact-rewrite
guest run, hosts suppression left the keyword address sets empty. Status therefore
reports hydration separately. Existing local or policy-owned firewall rules are
preserved where possible, and supplemental firewall failure does not abort when the
required hosts state and actual DeviceAdd connection test pass.

### Gate verification

Protection is healthy when all required checks pass:

- the managed hosts markers are structurally valid and their contents are canonical;
- every expected IPv4 and IPv6 sinkhole line is present;
- `login.live.com` A answers are only `0.0.0.0`;
- `login.live.com` AAAA answers are only the unspecified IPv6 sink; and
- TCP 443 cannot connect, or the machine is explicitly offline with the complete
  hosts configuration already valid.

Dynamic-keyword hydration, the managed FQDN rule, the `wlidsvc` rule, staging rules,
legacy rules, and firewall policy are still reported. They explain defense-in-depth
state but do not force one exact firewall topology when the required path already
verifies blocked.

The gate is a current-state test, not a durability certificate. Keep it active continuously and re-run Status after Windows servicing, security-policy changes, firewall resets, DNS-stack changes, or hosts-file edits.

### Hosts-file safety

The script:

- edits only the paired `# BEGIN degdid-registration-block` / `# END degdid-registration-block` region;
- preserves unrelated content, detected newline style, and supported encoding/BOM state;
- refuses malformed, duplicate, or marker-lookalike regions;
- refuses a hosts file that is a reparse point;
- serializes writes through a named mutex;
- creates a timestamped backup and performs atomic replacement.

### Compatibility boundary

Expected broken or degraded workflows include MSA sign-in, Store and Xbox authentication, OneDrive MSA sign-in, Phone Link, CDP graph features, and related device identity flows. Windows Update endpoints are not intentionally blocked.

Blocking Activity/DDS names may reduce those specific graph calls, but it is not evidence that general telemetry or the court-reported channel is suppressed.

## P3 - Canonical expanded Wipe

`-Wipe` is allowed only when an existing protection gate independently verifies. It does not fall back to an online warning.

The known source model includes:

- target-user, `.DEFAULT`, and SYSTEM `ExtendedProperties\LID`;
- target-user `Immersive\production\Property` values;
- target-user Token `DeviceId` and `DeviceTicket` fields;
- target-user Credential Manager device entries `SSO_POP_Device` and
  WindowsLive `didlogical` when elevation belongs to the target user;
- machine IdentityCRL NegativeCache keys whose names embed a captured PUID;
- target-user TokenBroker cache contents; and
- target-user ConnectedDevicesPlatform cache contents.

Because UAC elevation has a different logon-session credential namespace, the
script does not trust SID equality alone. It uses a short-lived limited scheduled
task in the target interactive session to inspect/delete only those two device
credentials, then removes the helper task and result file.

Before deleting files, the script verifies that each cache is under the resolved target profile and contains no reparse points. It inventories before and after quiescing identity services, captures every real-shaped PUID it can read, performs each operation with explicit accounting, restores the original service state, waits 12 seconds with eligible identity services started for settle, and re-inventories.

Wipe succeeds only if:

- inventory reads are complete;
- every captured old PUID is absent;
- no real-shaped PUID exists in a known active store;
- no real-shaped PUID exists in the inspected residual registry cache;
- all mutation operations succeeded;
- service state was restored; and
- the protection gate remained healthy.

### Evidence and source attribution

- `[OBSERVED]` EXP-C: machine-hive-only PUID state was cleared and remained empty through the tested online/reboot window with hosts blocking.
- `[OBSERVED]` EXP-C2: after HKCU contamination, clearing only LID values was insufficient; the same target-user PUID returned after reboot while `login.live.com` remained hosts-blocked.
- `[OBSERVED]` EXP-C3: the successful expanded bundle cleared Immersive Property, Token fields/tickets, LID values, and caches under continuous hosts blocking. The stores remained empty after reboot and about four minutes of forced-service soak.

EXP-C3 showed that Immersive `Property\<PUID>` was present across the failing naive wipe and was removed in the successful expanded bundle. The implementation therefore treats Immersive Property as a **required member of the successful cleanup bundle**. It is not described as the unique restore source unless a future controlled ablation isolates it from Token and cache cleanup.

## P4 - Protect: preferred contaminated path

Run:

```powershell
.\degdid.ps1 -Protect
```

Protect:

1. enforces the supported-target preflight;
2. refreshes the canonical hosts and firewall controls;
3. verifies the complete protection gate;
4. aborts before identity mutation if block application or verification fails;
5. inventories and quiesces identity services;
6. verifies the gate again immediately before identity writes;
7. performs Wipe by default;
8. verifies the gate again before service settle;
9. restores and settles services;
10. rechecks the gate, service state, operation ledger, and local postcondition.

This is fail-closed with respect to identity mutation. If the gate is lost after identity writes and before settle, the script reports failure and leaves services quiesced rather than resuming them into a known unblocked path. It does not claim transactional rollback of already-cleared identity state.

`-DryRun` reports planned work but never substitutes the planned configuration for current state or claims that protection is active.

## P5 - Experimental Decoy

Run:

```powershell
.\degdid.ps1 -Protect -UseDecoy
```

Decoy clears old state, generates one random `0018`-shaped local value, writes it to the three required LID stores, and updates existing Token `DeviceId` fields consistently. Old tickets and caches are cleared.

Decoy is not canonical because:

- it intentionally leaves a real-shaped identifier in active stores;
- Status cannot infer server versus local provenance from shape;
- a decoy is not registered in Microsoft's graph;
- EXP-F observed only short-window stickiness, not durable behavior; and
- unblocking can still permit a future real DeviceAdd.

The default `-Protect` action is Wipe.

## P6 - Recovery-safe Unblock

Run from elevated PowerShell:

```powershell
.\degdid.ps1 -Unblock
```

Unblock remains callable even if the machine is now domain/Entra/MDM managed, has multiple profiles, has no interactive user, or has an unloaded target hive. It does not touch identity stores.

It removes:

- a valid paired degdid hosts region;
- current degdid FQDN and `wlidsvc` firewall rules;
- legacy `degdid-block-*` firewall rules; and
- degdid deterministic dynamic-keyword objects.

It leaves unrelated hosts lines and firewall rules alone. A malformed or duplicate managed hosts region causes refusal rather than a guessed edit. Successful Unblock warns that a future DeviceAdd can mint a real GDID.

## Status completion oracle

Status shows the actual account, SID, profile, PUID, and GDID values by default so
the local operator can understand the machine. `-Redact` hashes those values for
share-safe output. `-Json` changes format, not disclosure level.

The exact verdicts, in precedence order, are:

| Verdict | Condition |
|---------|-----------|
| `Error` | Any material read error, opaque DeviceTicket, or unknown active identity value prevents a safe absence conclusion |
| `UnsupportedEnvironment` | Inspection is readable but the mutation contract is not met |
| `RealGdidPresent` | At least one real-shaped PUID is present in active or residual inventory |
| `BlockDegraded` | No real-shaped PUID is present, but the complete block gate is not healthy |
| `ProtectedNoRealGdid` | Supported/readable environment, no real-shaped PUID, healthy continuous block |

Because Decoy is `0018`-shaped, it can correctly yield `RealGdidPresent`. That verdict is conservative by design.

## Evidence matrix

| Experiment | Classification | Supported statement |
|------------|----------------|---------------------|
| EXP-A1 | Observed | No PUID in inspected stores at offline first desktop. |
| EXP-A4 | Partial H2 | Pre-network hosts block prevented mint for about 90 seconds through a service bounce. |
| EXP-B | First-mint control | Never-minted image produced a machine-hive PUID about two minutes after unblock without MSA. It is not H7 wipe-remint evidence. |
| EXP-C | Observed, limited shape | Machine-hive-only cleanup plus hosts block stayed empty in its tested short window and reboot. |
| EXP-C2 | Observed failure | Naive LID-only wipe did not clear target-user continuity. |
| EXP-C3 | Partial H3/H4 | Expanded bundle plus continuous hosts block stayed empty across reboot and about four minutes of forced-service soak. |
| EXP-D | **Partial H5** | Zero-pending WU scan, Defender update, successful prior blocked-period history, and no mint; no controlled pending CU installation during D. |
| EXP-E | **Partial/inferred H6** | Desktop, WU scan, Defender, and blocked LiveId path observed; most Store/Xbox/Phone Link behavior inferred, not UI-exercised. |
| EXP-F | Nuanced | No replacement/remint during approximately five-to-six-minute unblocked trials on the exercised image; no long-window conclusion. |
| EXP-H | Observed MSA field failure | Same old user LID rehydrated locally under healthy blocks after all earlier bundle operations succeeded; targeted device-credential cleanup added, rerun pending. |

## Validation still pending

The first exact-rewrite Protect run and two reboot checks now pass on the supported
25H2 guest (`EXP-G` interim). Remaining closure work:

- 24-hour online post-Protect window and remaining session/service/task transitions
- EXP-H rerun proving the MSA device-credential cleanup prevents the old user LID from returning
- all five Status verdicts against controlled states
- remaining injected fail-closed transitions and recovery-Unblock matrix
- FQDN hydration behavior beyond the observed unhydrated hosts-sink configuration
- Controlled installation of a known pending cumulative update
- Store/MSA/Xbox/Phone Link/OneDrive/Edge-sync UI checks
- Direct H7 wipe-then-unblock remint test with a defined DeviceAdd-capable client
- Feature update on a disposable snapshot
- Immersive Property versus Token/cache ablation if unique-source attribution is required

Future results must report the actual observation window. "Continuous" describes the required control state, not proof of indefinite effectiveness.

## Explicit residual risk

- Old Microsoft-side records can survive every local action.
- Unknown local stores may exist beyond the current inventory.
- Firewall, hosts, DNS, service, or policy changes can degrade the gate later.
- Other Microsoft services may emit GDID or correlate the installation through other identifiers.
- Blocking identity paths creates significant and incompletely measured compatibility costs.
- Unblock, control failure, or a bypass can permit a future DeviceAdd.
- No result here establishes suppression of the court-reported URL association.
