# degdid - High-Level Plan

Last updated: 2026-07-11

## Purpose

The project has two related tracks:

1. **Research:** map the GDID mint, local persistence, registration, reporting, and correlation pipeline with explicit evidence tags.
2. **Hardening:** provide a narrow, auditable completion gate that removes real server-issued GDID state from known local stores and continuously blocks DeviceAdd on a supported Windows 11 target.

The research track is intentionally broader than the shipped tool. `degdid.ps1` does not claim to suppress general Windows telemetry or the unidentified channel behind the court-reported GDID-to-URL/time/IP association.

## Scope

### Research scope

- GDID / Device PUID lifecycle for MSA and local-account machines
- `wlidsvc`, IdentityCRL, CDP, DDS, and Delivery Optimization relationships
- Local persistence in `LID`, Immersive Property, Token state, machine NegativeCache, and user caches
- DeviceAdd and graph endpoint inventory
- Correlation risks involving IP history, MSA, device keys, and hardware material
- Compatibility evidence for desktop, Windows Update, Defender, Store/MSA, Xbox, Phone Link, and CDP workflows

### Tool scope

- Inspect the supported environment and known GDID stores
- Redact identifiers by default and expose explicit human/JSON status modes
- Apply a canonical dual-stack hosts region
- Verify canonical dual-stack hosts and the actual DeviceAdd path; add/report FQDN and `wlidsvc` firewall controls when policy permits
- Verify the mint path independently before identity mutation
- Perform canonical expanded Wipe, or experimental Decoy
- Verify local postconditions after a service-settle interval
- Remove only degdid-managed network state through a recovery-accessible Unblock path

### Explicit non-goals

- Erasing Microsoft server-side history
- Proving that all possible local stores have been discovered
- Suppressing DiagTrack, SmartScreen, Defender, Delivery Optimization, or every telemetry plane
- Identifying or blocking the unknown court-record channel
- Guaranteeing anonymity, unlinkability, or cross-reinstall separation
- Supporting domain, Entra, MDM, or simultaneous multi-loaded-profile mutation
- Coaching evasion of lawful process

## Operational contract

### Supported mutation target

`-Block`, `-Wipe`, `-Decoy`, and `-Protect` require:

- Windows 11 build 22000 or newer; warn outside the lab-validated 25H2 build 26200 line
- no domain join
- no Entra join, registration, enterprise join, or workplace join
- no detected MDM enrollment
- exactly one loaded target human-profile hive; dormant profile artifacts are warnings
- one active interactive user, or an authenticated session mapped to the sole loaded profile
- the target user's `HKEY_USERS\<SID>` hive loaded
- elevated administrator PowerShell

Unknown join, enrollment, profile, or target state is a refusal, not a best guess. Status may inspect unsupported systems. Unblock bypasses the target/profile contract so recovery remains possible if the machine later becomes managed, gains another profile, or loses its interactive target.

### Completion condition

The canonical completion condition is:

1. supported and readable environment;
2. no real-shaped PUID in the known active stores or residual registry inventory after Wipe and settle; and
3. a healthy continuous block gate.

The corresponding Status verdict is `ProtectedNoRealGdid`. The gate is GDID-specific. It does not imply that Microsoft has forgotten old records or that unrelated telemetry stopped.

The tool recognizes `0018`-shaped PUIDs but cannot prove their provenance from shape alone. A locally generated Decoy therefore remains experimental and is not the canonical completion state.

## Success criteria

### Research deliverables

- [x] Source-tagged architecture for mint, persist, register, and report
- [x] Local and network surface inventory
- [x] Threat model separating local controls from server-side history
- [x] Historical experiment notes with redacted identifiers
- [x] Selected Token client mappings documented
- [ ] Exact current anonymous/local-account wire response and complete token claim map
- [ ] Exact component/channel behind the court-reported URL association

### Tool implementation

- [x] Explicit supported-target preflight and refusal reasons
- [x] Human-readable full Status, explicit `-Redact`, and detailed `-Json`
- [x] Exact verdict oracle: `Error`, `UnsupportedEnvironment`, `RealGdidPresent`, `BlockDegraded`, `ProtectedNoRealGdid`
- [x] Canonical IPv4/IPv6 hosts region with safe parsing and atomic replacement
- [x] Auto-resolving FQDN dynamic-keyword firewall rule
- [x] Separate outbound `wlidsvc` service rule
- [x] Mint-path A/AAAA and TCP verification
- [x] Expanded Wipe with pre/post inventory and service-state accounting
- [x] Experimental Decoy mode
- [x] Fail-closed Protect sequencing
- [x] Recovery-safe Unblock for degdid-owned state
- [x] Pure helper tests for hosts handling, redaction, verdicts, postconditions, and preflight precedence

### Release validation

- [ ] Run the exact current rewrite end to end on a supported clean Windows 11 guest
- [ ] Run the exact current rewrite on a guest contaminated in machine and target-user stores
- [ ] Re-run EXP-H on the MSA-connected profile after targeted device-credential cleanup
- [ ] Exercise every Status verdict against controlled state
- [ ] Verify dynamic-keyword FQDN and `wlidsvc` rules on the guest firewall
- [ ] Verify fail-closed behavior at each block-gate transition
- [ ] Verify Unblock after profile/topology changes and malformed-marker refusal
- [ ] Install a known pending cumulative update under the gate
- [ ] Complete the Store/MSA/Xbox/Phone Link/Edge-sync UI matrix

Implementation completion and end-to-end lab validation are separate states. The first is complete; the second is not.

`EXP-G` exposed two delayed local machine rehydrate layers—machine-hive
Property/Token state and SYSTEM `didlogical`—then passed the accepted eight-hour
threshold after both were cleared. EXP-H independently confirmed the target-user
MSA credential layer and later matched the same machine gap. Remaining work is the
clean never-mint clone, discrete transition/recovery cases, and final MSA-machine
reboot/persistence confirmation. MSA UI usability remains separate compatibility
work.

## Phase 0 - Foundations

Status: complete enough for continued validation.

- [x] July 2026 Stokes reporting and court context
- [x] Official `UCDOStatus.GlobalDeviceId` documentation
- [x] Community reverse-engineering baseline from `wlidsvc` through CDP/DDS
- [x] Local IdentityCRL and machine-hive observations
- [x] Selected Token client GUIDs resolved; no complete client catalog claimed
- [x] Glossary, threat model, architecture, surfaces, and open-question backlog
- [x] Redaction rule: never commit real PUIDs or tickets

## Phase 1 - Technical map

Status: useful and source-tagged, with named open gaps.

| Workstream | Current position |
|------------|------------------|
| **Mint** | MSA DeviceAdd is documented. EXP-B observed a local-account first mint into SYSTEM and `.DEFAULT`; exact anonymous/local-account SOAP and ETW capture remains open. |
| **Persist** | Target-user `LID`, Immersive Property, Token fields, SYSTEM, `.DEFAULT`, NegativeCache, TokenBroker, and CDP caches are in the working model. The inventory is known, not asserted exhaustive. |
| **Register** | DDS endpoints and CDP registration behavior are documented. |
| **Report** | Delivery Optimization's `GlobalDeviceId` schema is documented. Activity scopes are evidenced. The court-reported URL channel remains unknown. |
| **Correlate** | IP, MSA, hardware-input, and cross-reinstall residual risks are separated from the GDID itself. |
| **Policy** | No GDID-specific post-Stokes consumer statement, opt-out, or retention schedule was found as of 2026-07-11. |

Deliverables: `architecture.md`, `surfaces.md`, `threat-model.md`, `glossary.md`, `gdid-research.md`, and `open-questions.md`.

## Phase 2 - Historical VM evidence

Environment: Hyper-V Windows 11 25H2 build 26200, local account, no MSA. The observations validate parts of the design but predate or do not cover every hardening branch in the current rewrite.

| Hypothesis | Evidence status | Observed window and limitation |
|------------|-----------------|--------------------------------|
| H1: offline OOBE has no GDID | **Supported** by EXP-A1 | Point-in-time first-desktop inventory with NIC disconnected. |
| H2: pre-blocking prevents first mint | **Partial** via EXP-A4 | No PUID after service bounce and about 90 seconds online. This does not establish indefinite protection or validate the current complete firewall gate. |
| H3: local cleanup can remove readable GDID state | **Supported for tested stores** by EXP-C/C3 | Expanded bundle succeeded; inventory is not claimed exhaustive. |
| H4: cleanup plus continuous block survives reboot | **Partial** via EXP-C3 | Empty after reboot and about four minutes of forced-service soak. Longer validation is pending. |
| H5: Windows Update works under the block | **Partial** via EXP-D | COM scan with zero pending updates, Defender signature update, and successful prior blocked-period history. No controlled pending cumulative update was installed during EXP-D. |
| H6: compatibility impact is cataloged | **Partial/inferred** via EXP-E | Desktop, scan, and Defender were exercised. Store/MSA/Xbox/Phone Link/Edge-sync UI workflows were not. |
| H7: wipe without blocks triggers server remint | **Not directly validated** | EXP-B was a first mint after unblocking a never-minted image, not wipe-then-remint. |
| H8: feature update preserves the protected state | **Not run** | Deferred to a disposable snapshot. |

Additional evidence:

- EXP-C2 proved that naive LID-only cleanup can rehydrate the same HKCU PUID while hosts remain blocked.
- EXP-C3 identified Immersive `Property\<PUID>` and parallel Token state as members of the successful expanded cleanup bundle. No controlled ablation established one unique restore source.
- EXP-F was nuanced: a decoy was not replaced during about six minutes unblocked, and an unblocked wipe stayed empty for about five to six minutes on the exercised image. This does not prove eventual remint or durable safety.

Full notes remain under `docs/experiments/`.

## Phase 3 - Implemented hardening

Status: implemented in root `degdid.ps1`; exact-revision guest validation is in
progress, with immediate Protect and two reboots passing in interim `EXP-G`.

| Layer | Implementation | Purpose |
|-------|----------------|---------|
| **Inspect** | Status environment, target, hosts, firewall, mint path, active stores, residual caches | Produce one explicit verdict without exposing identifiers by default |
| **Prevent** | Offline OOBE, then `-Block` before first network access | Avoid first DeviceAdd after a local profile exists |
| **Block** | Required dual-stack hosts + actual DeviceAdd path test; optional/reportable FQDN and `wlidsvc` firewall layers | Keep the mint path unavailable without demanding one exact firewall topology |
| **Wipe** | Clear known active and matching residual state, caches, and tickets | Canonical local removal path |
| **Protect** | Apply/verify Block, then Wipe by default | Preserve ordering and fail closed |
| **Decoy** | Generate and install one local `0018`-shaped value after cleanup | Experimental continuity research only |
| **Unblock** | Remove only valid degdid-managed network state | Recovery without target-profile dependency |
| **Verify** | Recheck gate, settle services, inventory stores, verify service restoration | Reject partial or ambiguous completion |

The preferred contaminated path is `-Protect`, which means continuous block plus canonical Wipe. Decoy is not the preferred user path.

## Phase 4 - Exact-revision validation plan

Run from disposable snapshots and record exact timestamps:

1. **Eligibility matrix:** supported local single-loaded-target guest; then domain, Entra, MDM, multiple-loaded-profile, no-target, and unloaded-hive refusal cases. Dormant profile artifacts must warn without causing refusal.
2. **Block matrix:** absent, valid, stale paired, malformed, and duplicate hosts regions; missing/invalid keyword objects; missing FQDN or `wlidsvc` rule.
3. **Status matrix:** force and capture all five exact verdicts with default redaction and `-Json`; inspect full identifiers only in private output.
4. **Protect from contamination:** seed or naturally mint target-user and machine-hive state, run canonical Protect, reboot twice, and inspect immediately, at 5 minutes, 30 minutes, and 60 minutes online. Report the actual completed window; do not extrapolate beyond it.
5. **Fail-closed transitions:** make the gate fail before writes, after writes, and during settle on disposable snapshots; verify refusal, exit code, and service state.
6. **H5 controlled update:** start with a known pending cumulative update, scan, download, install, reboot, inspect, and retain KB/result evidence.
7. **H6 UI catalog:** exercise Store free-app download, Settings MSA sign-in, Xbox login, Phone Link pairing, OneDrive MSA sign-in if present, Edge sync, activation status, and non-MSA browsing.
8. **H7 direct test:** from a freshly contaminated snapshot, Wipe while protected, Unblock, invoke a defined DeviceAdd-capable client, and observe at stated intervals. Keep this separate from EXP-B first mint.
9. **Recovery:** run Unblock after the guest becomes unsupported and confirm only degdid-owned state is removed; separately verify malformed-marker refusal.

Optional lower-priority work:

- feature update on a disposable snapshot;
- hosts-versus-firewall ablation;
- Immersive Property/Token cleanup ablation if stronger source attribution is needed;
- multi-day continuous-block soak with explicit monitoring times.

## Working principles

1. Tag claims as `[COURT]`, `[OBSERVED]`, `[STATIC]`, `[MSDOC]`, or `[ASSESSED]`.
2. State the observation window; never convert a short soak into "permanent" or "indefinite."
3. Treat absence from known stores as a bounded inventory result, not proof of universal absence.
4. Keep Wipe canonical and Decoy experimental.
5. Never equate a local wipe with deletion of Microsoft-held history.
6. Never equate DeviceAdd blocking with suppression of all telemetry or the court-reported channel.
7. Do not blanket-block `*.microsoft.com`; compatibility must remain measurable.
8. Use VM snapshots, avoid personal MSA credentials, and never commit tickets or full identifiers.
9. Keep `docs/experiments/` as the evidence record and this plan as the progress ledger.

## Near-term actions

1. Validate the exact current rewrite end to end on a supported VM.
2. Run the controlled pending cumulative-update test.
3. Complete the UI compatibility matrix.
4. Run direct H7 wipe-then-unblock validation.
5. Publish only claims supported by those recorded windows.

## Document index

| File | Role |
|------|------|
| `docs/plan.md` | Scope, implementation state, and validation backlog |
| `docs/lab-playbook.md` | Exact-revision VM runbook and historical evidence |
| `docs/countermeasures.md` | Operational controls, gate semantics, and residual risk |
| `docs/architecture.md` | Generation, lifecycle, and network I/O |
| `docs/surfaces.md` | Storage, service, and endpoint inventory |
| `docs/threat-model.md` | Adversaries, scenarios, and limits |
| `docs/glossary.md` | Terms and confidence tags |
| `docs/open-questions.md` | Living research backlog |
| `docs/gdid-research.md` | News context and research summary |
| `docs/experiments/` | Per-run observations and redacted evidence |
