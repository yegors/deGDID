# Lab Playbook — VM Testing (Agent-Executable)

Last updated: 2026-07-09

Goal: prove what happens when we **prevent mint**, **block registration**, and **rotate GDID locally offline** — including breakage to Windows features and **Windows Update**.

This is the runbook for agent-driven experiments inside an isolated Windows VM. Results land in `docs/experiments/`.

---

## 0. Hypotheses to test

| ID | Hypothesis | Pass criteria |
|----|------------|---------------|
| H1 | Offline install (no net through OOBE) → **no** `LID` / no `g:` until first DeviceAdd | No IdentityCRL Device PUID after OOBE offline — **PASS** `[OBSERVED]` EXP-A1 (26200/25H2) |
| H2 | Blocking DeviceAdd/DDS hosts **before first online** prevents mint indefinitely (until unblock) | No `0018…` LID while blocks hold; attempts fail visibly (ETW/event log) |
| H3 | On contaminated install, **local-only** rewrite of `LID`/`DeviceId` (no net) changes readable GDID | Inspect shows new value; no DeviceAdd traffic |
| H4 | Local-only fake PUID + permanent registration blocks → OS stays usable for core desktop | Boot, shell, local apps OK; document what fails |
| H5 | Windows Update still works with DeviceAdd/DDS blocked (WU endpoints allowed) | `usoclient` / WU download+install succeeds |
| H6 | Store / MSA / CDP features break under blocks or local-only rotate | Catalog failures; sign-in loops; Phone Link dead — expected |
| H7 | Clearing identity state **without** blocks → silent **server** re-mint (new real GDID) | New `0018…` after online; DeviceAdd observed |
| H8 | Feature update keeps local-only value if blocks hold; may re-mint if blocks lifted | Compare pre/post upgrade LID |

---

## 1. Lab environment (required)

### 1.1 Host / hypervisor

- Hyper-V, VMware, or VirtualBox — snapshots mandatory.
- VM: Windows 11 (match research interest; note build), **generation 2**, enough disk for one feature update (~40GB+ free).
- **NAT or host-only + controlled gateway** so we can firewall from guest *and* optionally sinkhole from host.
- Do **not** use the daily driver. Do **not** sign into personal MSA on lab VMs if avoidable.

### 1.2 Snapshot ladder (create these)

| Snap | State |
|------|-------|
| `S0-clean-iso` | Idle before first boot (optional) |
| `S1-oobe-offline` | OOBE completed, **airplane / no NIC**, local account |
| `S2-baseline-online` | First online, natural mint allowed (control VM) |
| `S3-blocked-never-mint` | Online but DeviceAdd/DDS blocked from first packet |
| `S4-contaminated` | Has real GDID (from S2) — target for offline rotate |
| `S5-post-local-rotate` | After local-only rotate + blocks |
| `S6-post-wu` | After Windows Update attempt under blocks |

### 1.3 Two VM roles (recommended)

1. **Control** — normal online mint; never mutate; reference traffic + healthy Update.
2. **Treatment** — blocks + local-only experiments; revert via snapshots.

---

## 2. Instrumentation (install once per VM)

Keep tools **offline-copyable** (ISO/share) so blocked-net VMs can still measure.

| Tool | Use |
|------|-----|
| PowerShell inspect script (repo) | LID / Token / services dump |
| `Get-NetTCPConnection`, `Resolve-DnsName` | Live egress |
| Windows Firewall + `hosts` file | Blocks |
| Optional: Microsoft Message Analyzer / Wireshark / pktmon | Confirm no DeviceAdd |
| Optional: Procmon (filter IdentityCRL, wlidsvc, cdp) | Who writes LID |
| Event Viewer: `Microsoft-Windows-LiveId`, CDP-related | Registration failures |
| ETW: CDP providers from `architecture.md` | RegisterUserDevice |

### 2.1 Standard inspect output (every experiment)

Save as `docs/experiments/<id>/inspect-before.txt` / `inspect-after.txt`:

```powershell
# gdid-inspect.ps1 (to be added under tools/ later)
$paths = @(
  'HKCU:\SOFTWARE\Microsoft\IdentityCRL\ExtendedProperties',
  'Registry::HKEY_USERS\.DEFAULT\Software\Microsoft\IdentityCRL\ExtendedProperties',
  'Registry::HKEY_USERS\S-1-5-18\Software\Microsoft\IdentityCRL\ExtendedProperties'
)
foreach ($p in $paths) {
  if (Test-Path $p) {
    $lid = (Get-ItemProperty $p -EA SilentlyContinue).LID
    [pscustomobject]@{ Path=$p; LID=$lid; GDID= if($lid){"g:$([Convert]::ToUInt64($lid,16))"} else {$null} }
  }
}
Get-Service wlidsvc,CDPSvc,dosvc,DiagTrack,TokenBroker | Format-Table Name,Status,StartType
Get-Date -Format o
[System.Environment]::OSVersion.VersionString
(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').DisplayVersion
(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild
```

Also record: Token subkey count; whether any `DeviceId` remains; CDP folder present.

---

## 3. Block list (registration / graph) — v0

**Intent:** stop mint + DDS announce. **Allow:** Windows Update CDN / WU endpoints so H5 is testable.

### 3.1 Block (hosts → `0.0.0.0` and/or Firewall Outbound Deny)

```
login.live.com
*.login.live.com          # if firewall supports SNI/wildcards; else resolve & IP-block carefully
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

Notes:

- `login.live.com` block is nuclear for **all MSA** (Store, Xbox, OneDrive SSO). That is intentional for “never mint / never re-register” tests.
- Prefer **Firewall** over hosts for TLS/SNI realities; combine both.
- IP blocks drift — re-resolve each session; document IPs in experiment log.
- Do **not** blanket-block `*.microsoft.com` or Update will die and H5 is useless.

### 3.2 Allow (sanity for Update tests)

Keep reachable (do not add to block list):

- `*.windowsupdate.com`, `*.update.microsoft.com`, `*.dl.delivery.mp.microsoft.com`
- `*.delivery.mp.microsoft.com`, `*.do.dsp.mp.microsoft.com`
- `slscr.update.microsoft.com`, `fe3*.delivery.mp.microsoft.com` (as needed)
- DNS to a real resolver (or host DNS)

Exact WU endpoint set: follow current MS Update endpoint docs during the run; paste used allow-list into experiment notes.

### 3.3 Apply / remove helpers (guest)

```powershell
# Example hosts append (Admin) — experiment only
$block = @(
  '0.0.0.0 login.live.com',
  '0.0.0.0 cs.dds.microsoft.com',
  '0.0.0.0 activity.windows.com',
  '0.0.0.0 ztd.dds.microsoft.com',
  '0.0.0.0 aad.cs.dds.microsoft.com'
)
Add-Content -Path "$env:SystemRoot\System32\drivers\etc\hosts" -Value ($block -join "`n")
ipconfig /flushdns
```

Firewall rules: New-NetFirewallRule per remote address after Resolve-DnsName — script later under `tools/`.

---

## 4. Experiment matrix

### EXP-A — Prevent generation at install

| Step | Action |
|------|--------|
| A1 | Boot ISO; disconnect NIC **before** OOBE network page (or refuse network). |
| A2 | Create **local account** only. Snapshot `S1-oobe-offline`. |
| A3 | Run inspect — expect no/empty device LID (document reality). |
| A4 | Clone path: enable NIC **with blocks already applied** → use for days; inspect daily. |
| A5 | Clone path: enable NIC **without** blocks → capture DeviceAdd (pktmon/Wireshark); inspect new LID. |

**Questions answered:** Can install complete without GDID? Does first online always mint? Do blocks prevent mint?

### EXP-B — Contaminated install: server re-mint (control)

| Step | Action |
|------|--------|
| B1 | From `S2-baseline-online`, note GDID₀. |
| B2 | Online: clear IdentityCRL device sessions / CDP state (document exact keys deleted — study GDID-Changer approach, don’t run opaque binaries blindly). |
| B3 | Reboot online; capture traffic; note GDID₁. |

**Questions:** What does “official” rotate look like? (Contrast with local-only.)

### EXP-C — Local-only rotation (offline) ★ priority

| Step | Action |
|------|--------|
| C1 | From `S4-contaminated`, **disable NIC** (airplane). Snapshot. |
| C2 | Inspect GDID₀; export Token key names (not tickets). |
| C3 | **Local-only mutate** (escalating aggressiveness — stop at first stable variant): |
| | **C3a** Overwrite `LID` / all `DeviceId` with a new random `0018…`-shaped 64-bit hex (same format). |
| | **C3b** Delete Token subkeys’ `DeviceTicket` + `DeviceId` but leave/replace `LID`. |
| | **C3c** Delete CDP `%LOCALAPPDATA%\ConnectedDevicesPlatform\*`. |
| | **C3d** Also patch `.DEFAULT` + `S-1-5-18` IdentityCRL `LID` if present. |
| C4 | Reboot **still offline**. Inspect — does value stick? Do services recreate old value from somewhere else? |
| C5 | Apply **registration blocks**, then enable NIC. |
| C6 | Monitor 1h: any DeviceAdd? Does LID revert to GDID₀? Flip to new server id? Stay at local fake? |
| C7 | Exercise: Explorer, Notepad, Edge (non-MSA site), optional Store open (expect fail), `usoclient StartScan`. |

**Questions:** Can we own the local fingerprint without talking to MS? Does Windows “heal” from a private cache? Do blocks keep a fake id from being replaced?

### EXP-D — Windows Update under blocks

| Step | Action |
|------|--------|
| D1 | On `S5` (local rotate + blocks), run Update scan/download/install cumulative or small CU. |
| D2 | If fails, binary-search: unblock WU hosts only (already allowed) vs accidental overblock. |
| D3 | After success, inspect LID — unchanged? |
| D4 | Optional: attempt feature update on a disposable snap (long). |

**Questions:** H5/H8 — updates vs identity stack coupling.

### EXP-E — Breakage catalog

For each of {blocks only, local-rotate only, both}:

| Feature | Check |
|---------|-------|
| Boot / login / desktop | Smoke |
| Windows Update | EXP-D |
| Microsoft Store | Open + download free app |
| MSA sign-in in Settings | Attempt |
| OneDrive / Xbox | Launch |
| Phone Link / CDP Near Share | Launch |
| Activation / Settings → System | Note any device auth errors |
| Edge sync | Optional |
| Defender cloud sample submit | Optional note |

Record: works / degraded / broken + error text.

### EXP-F — Revert / unblock

| Step | Action |
|------|--------|
| F1 | Remove blocks; stay on local-fake LID. |
| F2 | Watch for DeviceAdd and LID replacement. |
| F3 | Confirms: local-only is only stable **with** registration starvation. |

---

## 5. Local-only rotate — candidate procedures (research, not gospel)

> Do this **only in VMs**. Host experiments need explicit user OK.

### 5.1 Format constraints (from research)

- Real device PUIDs often `0018` + 12 hex digits.
- Server form `g:` + decimal of that uint64.
- Local-only value is **not** Microsoft-recognized; it’s a **decoy / discontinuity** unless they re-mint.

### 5.2 Minimal mutate (C3a)

1. Generate `NewLid` = `'0018' + [guid]::NewGuid().ToString('N').Substring(0,12)` (or crypto random 48 bits).
2. Set `LID` in HKCU + `.DEFAULT` + SYSTEM hives (SYSTEM needs elevated / psexec).
3. For each Token subkey with `DeviceId`, set to `NewLid` **or delete** `DeviceId`+`DeviceTicket` (prefer delete tickets — avoids auth with mismatched id).
4. Do **not** upload tickets anywhere.

### 5.3 Expected failure modes

| Symptom | Likely cause |
|---------|--------------|
| LID reverts after reboot offline | Another local store rewriting it |
| LID reverts after online | DeviceAdd / provision succeeded |
| Store/MSA broken | Expected with blocks or wiped tickets |
| WU broken | Over-broad block list |
| CDP errors in Event Log | Expected when DDS unreachable |
| Activation weirdness | Possible if device auth tied; document |

---

## 6. Agent execution plan (how I will run this)

When user says **go** and a lab VM is available (RDP/SSH/Hyper-V access or user runs commands I provide):

### Phase L0 — Prep (user)

1. Create Win11 VM + snapshots capability.
2. Confirm agent can run commands in-guest (Cursor on VM, or remoting).
3. Copy this repo into the guest (or sync `docs/` + future `tools/`).

### Phase L1 — I implement tooling in-repo

1. `tools/inspect-gdid.ps1` — read-only snapshot.
2. `tools/block-registration.ps1` — apply/remove v0 block list (hosts + firewall), dry-run flag.
3. `tools/local-rotate-gdid.ps1` — **offline-only guard** (abort if default route / live.net); mutate LID; log actions.
4. `docs/experiments/README.md` — index.

### Phase L2 — I run EXP-A on treatment VM

1. Guide offline OOBE if user must click UI; then I inspect.
2. Apply blocks; go online; monitor; write `docs/experiments/EXP-A/notes.md`.

### Phase L3 — Control mint (EXP-A5 / S2)

1. Separate snap without blocks; capture mint; save GDID₀ (redact in public docs).

### Phase L4 — EXP-C local-only ★

1. Contaminate or use S2 clone → airplane.
2. Run local-rotate tool; reboot offline; inspect.
3. Enable blocks; online; 1h soak; inspect + pktmon summary.
4. Write results + breakage table.

### Phase L5 — EXP-D Update

1. Attempt CU under blocks; document success/fail; LID stability.

### Phase L6 — Synthesize

1. Update `countermeasures.md` with **Prevent-at-install**, **Block**, **Local-only rotate** rows.
2. Update `architecture.md` / `open-questions.md` with `[OBSERVED]` lab tags.
3. Explicit “will Windows break?” section with evidence.

### Stop conditions

- Cannot obtain snapshot-capable VM → pause; deliver scripts + manual checklist only.
- Accidental use of personal MSA → abort treatment; revert snap.
- WU fails and blocks too broad → narrow allow-list; don’t declare H5 failed until allow-list verified.

---

## 7. Safety / ethics

- Lab VMs only for destructive identity edits.
- Redact real GDIDs in committed notes (`g:REDACTED`, prefix `0018` OK).
- No coaching to evade lawful process; goal is consumer agency + breakage science.
- Don’t decode or exfiltrate `DeviceTicket` blobs into git.

---

## 8. Success deliverables from this lab

1. Answer: **Can we prevent GDID at install?** (yes/no/partial + method)
2. Answer: **Does local-only rotate stick offline?** (yes/no + which stores)
3. Answer: **Do registration blocks keep a decoy from being replaced?** 
4. Answer: **What breaks?** (table)
5. Answer: **Do updates still work?** (H5)
6. v0 recommended procedure in `countermeasures.md` — or a documented dead end
