# de-gdid — High-Level Plan

Last updated: 2026-07-09

## Purpose

**Research** Microsoft’s Global Device Identifier (GDID) and related Windows identity/telemetry surfaces in high detail — then **design and validate countermeasures** against this class of unwarranted, opaque device tracking.

This is not a one-off blog summary. Goal: map the full mint → store → emit → correlate pipeline, measure what actually leaks, and ship practical mitigations users/researchers can verify.

### In scope

- GDID / Device PUID lifecycle (MSA + anonymous CDP paths)
- Connected Devices Platform (CDP), Device Directory Service (DDS), Delivery Optimization reporting
- Local persistence (IdentityCRL, tokens, Feedback Hub, Iris, etc.)
- Network endpoints and telemetry that carry or key on GDID
- Correlation risks (IP history, MSA account, hardware-bound keys, reinstall linkage)
- Countermeasures: detect, disrupt, **prevent-at-install**, **registration blocking**, **local-only offline rotate**, isolate, verify — with honest limits
- Lab validation: breakage (Store/MSA/CDP), **Windows Update** behavior under blocks/rotate

### Out of scope (for now)

- Evading lawful process in criminal investigations (we study the mechanism; we don’t coach crime)
- Non-Windows platforms (except brief comparison notes)
- General “debloat Windows” theater unrelated to device-identity tracking

### Success criteria

1. **Documented model** of how GDID is created, stored, synced, and reported — with confidence tags and repro steps.
2. **Inventory** of local + network surfaces that expose or depend on it.
3. **Countermeasure matrix**: each control → what it breaks → residual risk → how to test.
4. **Lab answers** to: prevent-at-install? local-only rotate stick? updates still work? what breaks?
5. **Tooling** (after lab): inspect; block-registration; local-rotate (offline-guarded); mitigate verify.
6. **Honest threat model**: what we can stop locally vs what Microsoft still holds server-side.

---

## Phase 0 — Foundations (done)

- [x] Stokes / July 2026 news context
- [x] Official MS crumbs (`UCDOStatus.GlobalDeviceId`)
- [x] Community RE baseline (wlidsvc → CDP/DDS → DO)
- [x] Local read of this machine’s GDID + IdentityCRL layout
- [x] Token-dir app/client mapping (partial; 3 GUIDs still unknown)
- [x] Glossary + threat model
- [ ] Repo layout: `docs/experiments/`, `tools/`

---

## Phase 1 — Deep technical map (done enough to lab)

| Workstream | Status |
|------------|--------|
| **Mint** | MSA DeviceAdd path documented; anonymous path lab-pending |
| **Persist** | IdentityCRL / Token / SYSTEM / `.DEFAULT` / CDP folder mapped |
| **Register** | DDS endpoints + CDP ETW registration flow documented |
| **Emit** | DO + activity + court URL implication; exact URL sensor unknown |
| **Correlate** | IP / MSA / hardware residual risks in threat model |
| **Policy** | Thin — no post-Stokes MS consumer statement found |

**Deliverables:** `architecture.md`, `surfaces.md`, `threat-model.md`, `glossary.md`, `open-questions.md`

---

## Phase 2 — VM lab (NEXT — primary effort)

Full runbook: **[`lab-playbook.md`](./lab-playbook.md)**.

### Countermeasure hypotheses (lab must prove)

| Priority | Question |
|----------|----------|
| ★ | **Prevent mint at install** — offline OOBE + block DeviceAdd/DDS before first online |
| ★ | **Local-only offline rotate** — change/wipe `LID` without network registration |
| ★ | **Permanent registration blocks** — keep decoy from being replaced by silent DeviceAdd |
| ★ | **Windows Update** — still works with identity registration blocked? |
| | Breakage catalog: Store, MSA, CDP, activation edge cases |
| | Contrast: online server re-mint (control only — not the privacy goal) |

### Agent execution sequence (when VM ready)

1. **L0** User: snapshot-capable Win11 VM; agent access in-guest  
2. **L1** Agent: add `tools/inspect-gdid.ps1`, `block-registration.ps1`, `local-rotate-gdid.ps1`  
3. **L2** EXP-A prevent-at-install  
4. **L3** Control natural mint  
5. **L4** EXP-C local-only rotate + blocks ★  
6. **L5** EXP-D Windows Update under blocks  
7. **L6** Write `docs/experiments/*`; promote findings into `countermeasures.md`

**Deliverable:** experiment notes + updated countermeasures with `[OBSERVED]` results.

---

## Phase 3 — Countermeasure design (draft started)

Draft matrix: **[`countermeasures.md`](./countermeasures.md)**.

| Layer | Idea | Intent |
|-------|------|--------|
| **Detect** | Read LID / Token / services | Know your fingerprint |
| **Prevent** | Offline OOBE; pre-block DeviceAdd | Never get a server GDID |
| **Starve** | Disable CDP / Activity History | Reduce graph/activity emit |
| **Block** | Hosts/firewall for login.live DeviceAdd + DDS + activity | Stop mint & re-register |
| **Local-only rotate** | Offline rewrite/wipe PUID + tickets; **no** DeviceAdd | Break local continuity without giving MS a new real id |
| **Server rotate** | Clear state online → new server PUID | Control experiment only |
| **Isolate** | Dedicated VMs; no personal MSA | Contain blast radius |
| **Verify** | Inspect + traffic + WU + breakage table | Prove it |

Preferred contaminated path to validate: **local-only rotate + permanent registration blocks (P4)**.

Each validated control must document: privileges, side effects, residual risk, rollback.

---

## Phase 4 — Tooling (after Phase 2 answers stabilize)

- `inspect` — GDID + stores + service status  
- `block-registration` — apply/remove v0 allow/deny sets (dry-run)  
- `local-rotate` — offline-guarded local mutate/wipe  
- `mitigate` — compose prevent/block/rotate with verify  

No opaque third-party “changer” as dependency; we reimplement auditable steps.

---

## Phase 5 — Hardening & disclosure

- Publish validated procedures + breakage honesty  
- Limits: historical MS records; other telemetry planes; MSA join risks  
- Optional public summary  

---

## Working principles

1. **Evidence over vibes** — tag `[COURT]` / `[OBSERVED]` / `[STATIC]` / `[ASSESSED]`.  
2. **No false safety** — local decoy ≠ MS forgot you; VPN ≠ hide from MS.  
3. **Prefer local-only + starve over server re-mint** for privacy vs Microsoft.  
4. **Don’t break Update by accident** — never blanket-block `*.microsoft.com`.  
5. **Docs are memory** — lab results in `docs/experiments/`.  
6. **Safety** — VM snapshots; no personal MSA on treatment VMs; don’t commit tickets/GDIDs.

---

## Near-term next actions

1. Stand up lab VM + snapshots (user) — then say **go** on L1 tooling.  
2. Implement inspect / block / local-rotate scripts.  
3. Run EXP-A → EXP-C → EXP-D per `lab-playbook.md`.  
4. Fill breakage + Update answers into `countermeasures.md`.  
5. (Parallel, lower) Resolve remaining Token GUIDs / anonymous mint ETW.

---

## Doc index

| File | Role |
|------|------|
| `docs/plan.md` | This plan |
| `docs/lab-playbook.md` | VM experiments + agent run order |
| `docs/countermeasures.md` | Prevent / block / local-rotate matrix (pre-lab draft) |
| `docs/architecture.md` | Generation, lifecycle, network I/O |
| `docs/surfaces.md` | Storage / services / endpoints |
| `docs/threat-model.md` | Adversaries, scenarios, limits |
| `docs/glossary.md` | Terms + confidence tags |
| `docs/open-questions.md` | Living backlog |
| `docs/gdid-research.md` | News + quick pointer |
| `docs/experiments/` | *(todo)* Per-run notes |
