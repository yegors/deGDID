# degdid - High-Level Plan

Last updated: 2026-07-16

## Purpose

The project has two related tracks:

1. **Research:** map the GDID mint, local persistence, registration, reporting, and correlation pipeline with explicit evidence tags.
2. **Hardening:** provide a narrow, auditable completion gate that removes real server-issued GDID state from known local stores and continuously blocks DeviceAdd on a supported Windows target.

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
- Show local identifiers clearly in human and JSON status output
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

- Windows 10 22H2 build 19045, or Windows 11 build 22000 or newer; warn outside the lab-validated Windows 11 25H2 build 26200 line
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
- [x] Human-readable full Status and detailed `-Json`
- [x] Exact verdict oracle: `Error`, `UnsupportedEnvironment`, `RealGdidPresent`, `BlockDegraded`, `ProtectedNoRealGdid`
- [x] Canonical IPv4/IPv6 hosts region with safe parsing and atomic replacement
- [x] Auto-resolving FQDN dynamic-keyword firewall rule
- [x] Separate outbound `wlidsvc` service rule
- [x] Mint-path A/AAAA and TCP verification
- [x] Expanded Wipe with pre/post inventory and service-state accounting
- [x] Experimental Decoy mode
- [x] Fail-closed Protect sequencing
- [x] Recovery-safe Unblock for degdid-owned state
- [x] Focused tests for the public interface, hosts handling, verdicts, postconditions, preflight, service sequencing, and credential cleanup

### Release validation

- [x] Run the exact current rewrite end to end on a supported clean Windows 11 guest
- [ ] Run the Windows 10 22H2/build-19045 compatibility and refusal matrix, or narrow the accepted build contract
- [x] Run the exact current rewrite on naturally minted and fully contaminated machine/target-user states
- [x] Re-run EXP-H on the MSA-connected profile through sign-out/in, sleep/resume, reboot, and 18 hours
- [x] Exercise every Status verdict through focused tests and controlled observed states
- [x] Verify dynamic-keyword FQDN and `wlidsvc` rules on the guest firewall
- [x] Verify fail-closed sequencing through naturally encountered failures and focused transition tests

The disposable-guest Unblock/topology and malformed-hosts integration matrix is
explicitly deferred rather than represented as passed. Focused tests cover the
owned-state and refusal logic. Controlled cumulative updates, the broader identity
UI matrix, and feature updates are compatibility follow-up work, not gates for the
narrow GDID-only claim.

Implementation and exact-revision end-to-end validation are complete for the
measured Windows 11 25H2/build-26200 scope. Other accepted builds remain warning
paths until separately validated.

`EXP-G` exposed delayed machine-hive Property/Token, DeviceIdentities, and SYSTEM
credential layers, then remained clean beyond 33 hours after the complete
conservative cleanup. It also passed fresh-mint Protect, Unblock/remint, reprotect,
reboot, and repeated identity-trigger controls. The original offline/pre-block
series already covered first-online prevention. `EXP-H` independently confirmed
the target-user MSA credential layer; the final current-revision field run remained
protected through sign-out/in, sleep/resume, reboot, and 18 hours. MSA UI usability
and cross-build compatibility remain separate work.

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
| H2: pre-blocking prevents first mint | **Supported for the measured build-26200 path** | EXP-A4 blocked before first online and remained empty through the exercised service window; later current-gate runs held the same DeviceAdd barrier through longer reboot/trigger windows. No indefinite claim. |
| H3: local cleanup can remove readable GDID state | **Supported for tested stores** by EXP-G/H | Current Protect cleared naturally minted, contaminated local-account, and MSA-connected state; inventory is not claimed exhaustive. |
| H4: cleanup plus continuous block survives reboot | **Supported for measured windows** | EXP-G exceeded 33 hours with repeated triggers/reboots; EXP-H passed reboot, session/power transitions, and 18 hours. |
| H5: Windows Update works under the block | **Partial** via EXP-D | COM scan with zero pending updates, Defender signature update, and successful prior blocked-period history. No controlled pending cumulative update was installed during EXP-D. |
| H6: compatibility impact is cataloged | **Partial/inferred** via EXP-E | Desktop, scan, and Defender were exercised. Store/MSA/Xbox/Phone Link/Edge-sync UI workflows were not. |
| H7: wipe without blocks permits server remint | **Directly observed** | EXP-G completed Protect/wipe -> Unblock -> rebooted remint in 22 seconds under identity triggers -> reprotect -> clean reboot. The latency is not universal. |
| H8: feature update preserves the protected state | **Not run** | Deferred to a disposable snapshot. |

Additional evidence:

- EXP-C2 proved that naive LID-only cleanup can rehydrate the same HKCU PUID while hosts remain blocked.
- EXP-C3 identified Immersive `Property\<PUID>` and parallel Token state as members of the successful expanded cleanup bundle. No controlled ablation established one unique restore source.
- EXP-F was nuanced: its original short unblocked trials did not remint. EXP-G later supplied the direct triggered wipe/protect -> Unblock -> rebooted-remint control.

Full notes remain under `docs/experiments/`.

## Phase 3 - Implemented hardening

Status: implemented in root `degdid.ps1`; exact-revision guest validation is
complete for the measured Windows 11 25H2/build-26200 scope in EXP-G/H.

| Layer | Implementation | Purpose |
|-------|----------------|---------|
| **Inspect** | Status environment, target, hosts, firewall, mint path, active stores, residual caches | Produce one explicit verdict with full local identifiers for diagnosis |
| **Prevent** | Offline OOBE, then `-Block` before first network access | Avoid first DeviceAdd after a local profile exists |
| **Block** | Required dual-stack hosts + actual DeviceAdd path test; optional/reportable FQDN and `wlidsvc` firewall layers | Keep the mint path unavailable without demanding one exact firewall topology |
| **Wipe** | Clear known active and matching residual state, caches, and tickets | Canonical local removal path |
| **Protect** | Apply/verify Block, then Wipe by default | Preserve ordering and fail closed |
| **Decoy** | Generate and install one local `0018`-shaped value after cleanup | Experimental continuity research only |
| **Unblock** | Remove only valid degdid-managed network state | Recovery without target-profile dependency |
| **Verify** | Recheck gate, settle services, inventory stores, verify service restoration | Reject partial or ambiguous completion |

The preferred contaminated path is `-Protect`, which means continuous block plus canonical Wipe. Decoy is not the preferred user path.

## Phase 4 - Exact-revision validation matrix

Run from disposable snapshots and record exact timestamps:

1. **Eligibility matrix:** implemented and focused-test covered for target resolution, build boundaries, and ambiguous profiles. Windows 10 remains generic/warned rather than lab validated.
2. **Block matrix:** canonical hosts, malformed/noncanonical refusal, dynamic keywords, service rules, and actual mint-path checks are covered by focused tests and build-26200 runs.
3. **Status matrix:** all five exact verdicts are covered; repository evidence remains identifier-free.
4. **Protect from contamination:** complete for naturally minted and contaminated local-account state through EXP-G, including the beyond-33-hour window.
5. **Fail-closed transitions:** naturally encountered pre-write failures and focused transition tests cover the shipped sequencing; no claim is made that every possible Windows failure was injected in a guest.
6. **MSA persistence:** complete for the EXP-H build-26200 field machine through sign-out/in, sleep/resume, reboot, and 18 hours.
7. **H7 direct test:** complete in EXP-G via Protect/wipe -> Unblock -> rebooted remint -> reprotect -> clean reboot.
8. **Recovery integration:** explicitly deferred. Owned-state and malformed-hosts behavior remains focused-test covered, not guest-matrix validated.
9. **Compatibility follow-up:** controlled pending CU, broader MSA/Store/Xbox/Phone Link/OneDrive/Edge UI, and feature-update work remain optional.

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

1. Run the Windows 10 22H2/build-19045 closure matrix, or narrow the accepted build contract.
2. Optionally run the controlled pending cumulative-update test.
3. Optionally expand the identity-feature UI compatibility matrix.
4. Publish only claims supported by the recorded build and observation windows.

## Document index

| File | Role |
|------|------|
| `docs/usage.md` | Human-facing commands, verdicts, exit codes, and recovery |
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
