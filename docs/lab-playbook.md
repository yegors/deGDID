# Lab Playbook - Exact-Revision VM Validation

Last updated: 2026-07-13

## Goal

Validate the current `degdid.ps1` implementation on disposable Windows virtual machines and record bounded, reproducible evidence for:

- prevention of first GDID mint;
- continuous DeviceAdd blocking;
- canonical expanded Wipe;
- fail-closed Protect sequencing;
- redacted Status and exact verdicts;
- recovery-safe Unblock;
- optional Windows Update and feature compatibility; and
- optional direct wipe-then-unblock remint behavior.

The completion target is narrow: no real server-issued GDID in known active stores plus a continuously healthy DeviceAdd block. This playbook does not test general telemetry suppression or the unidentified channel behind the court-reported GDID-to-URL/time/IP association.

Results belong under `docs/experiments/` with full identifiers and machine details redacted.

## 0. Evidence ledger before the next run

Historical environment: Hyper-V Windows 11 25H2 build 26200, local account, no MSA.

| ID | Hypothesis | Current evidence classification |
|----|------------|---------------------------------|
| H1 | Offline OOBE reaches first desktop without a GDID | **Supported for the observed baseline.** EXP-A1 found no PUID in target-user, `.DEFAULT`, SYSTEM, or Token stores at first desktop while offline. |
| H2 | Blocking before first online prevents first mint | **Partial.** EXP-A4 kept the inspected stores empty through a service bounce and about 90 seconds online with the historical hosts block. No indefinite claim; current firewall controls remain to be validated. |
| H3 | Expanded local cleanup removes readable GDID state | **Supported for the tested bundle and stores.** EXP-C/C3 cleared the observed state. The store inventory is not claimed exhaustive. |
| H4 | Wipe plus continuous block survives reboot and service activity | **Partial.** EXP-C3 remained empty across reboot and about four minutes of forced-service soak. Longer windows remain open. |
| H5 | Windows Update works under the block gate | **Partial.** EXP-D completed a WU COM scan with zero pending updates, updated Defender signatures, and showed successful prior blocked-period update history. It did not install a controlled pending cumulative update during D. |
| H6 | Identity-feature breakage is cataloged | **Partial/inferred.** Desktop, WU scan, Defender, and blocked LiveId were observed. Store/MSA/Xbox/Phone Link/Edge-sync UI workflows were not exercised. |
| H7 | Wipe followed by Unblock causes a new server PUID | **Not directly validated.** EXP-B was first mint after unblocking a never-minted image, not wipe-then-remint. |
| H8 | Feature update preserves the protected state | **Not run.** Requires a disposable long-running snapshot. |

Additional historical controls:

- EXP-B: first machine-hive PUID appeared about two minutes after blocks were removed from a never-minted online image.
- EXP-C2: naive LID-only cleanup allowed the same target-user PUID to return after reboot while hosts remained blocked.
- EXP-C3: clearing Immersive Property, Token fields/tickets, LID values, and caches as one bundle prevented that return in the observed window.
- EXP-F: a decoy was not replaced during about six minutes unblocked; an unblocked wipe stayed empty for about five to six minutes on the exercised image. This is nuanced short-window evidence, not proof of durable safety or eventual remint.

Do not convert any of these windows into "permanent" or "indefinite."

## 1. Required lab environment

### 1.1 Host and hypervisor

- Hyper-V, VMware, or VirtualBox with snapshots/checkpoints.
- Generation 2 Windows 10 or Windows 11 guest where applicable.
- NAT or a controlled gateway that can be disconnected before OOBE.
- At least 40 GB free if a feature-update experiment is planned.
- A private, offline-copyable copy of this repository.
- No daily-driver host mutation.
- No personal MSA on treatment guests.

### 1.2 Supported treatment profile

The positive-path guest must match the script's mutation contract:

- Windows 10 22H2 build 19045, or Windows 11 build 22000 or newer;
- Windows 11 25H2 build 26200 remains the only lab-validated line; use a separate Windows 10 clone for its pending compatibility matrix;
- not domain joined;
- not Entra joined, registered, enterprise joined, or workplace joined;
- not MDM enrolled;
- exactly one loaded target human-profile hive; dormant profile artifacts are allowed and reported;
- one active interactive user, or the authenticated lab session mapped to that sole loaded profile;
- target `HKEY_USERS\<SID>` hive loaded; and
- elevated PowerShell for mutations.

Separate snapshots or disposable clones are required for refusal tests involving domain, Entra, MDM, multiple profiles, no interactive user, or an unloaded target hive. Do not convert a personally managed machine into a test subject.

### 1.3 VM roles

1. **Control:** normal network access, first-mint reference, healthy Windows Update baseline, no local mutation unless the specific H7 protocol calls for it.
2. **Treatment:** degdid blocks, Wipe/Decoy, fault injection, compatibility testing, and recovery tests.

### 1.4 Snapshot ladder

| Snapshot | State |
|----------|-------|
| `S0-clean-iso` | Before first boot |
| `S1-oobe-offline` | Offline OOBE complete, one local profile, first desktop |
| `S2-offline-current-blocked` | Current revision Block applied and verified before first network access |
| `S3-control-first-minted` | Control image with a real server-issued PUID |
| `S4-user-and-machine-contaminated` | Real PUID represented in target-user and machine stores |
| `S5-current-protect-complete` | Current revision Protect returned success |
| `S6-post-reboot-soak` | Protected state after planned reboots and timed inspections |
| `S7-pending-cu` | Protected state with a known pending cumulative update |
| `S8-post-update` | After controlled CU installation and reboot |
| `S9-recovery` | Blocked state reserved for Unblock/topology tests |

Snapshot names may include timestamps, but public notes must not include the hostname, account, SID, or full PUID.

## 2. Instrumentation and evidence handling

### 2.1 Primary Status capture

Use the root script as the primary inspection surface.

Local human report with full values:

```powershell
.\degdid.ps1 -Status
```

Private full-value JSON, never committed:

```powershell
.\degdid.ps1 -Status -Json
```

Full Status output stays local and should be deleted when the experiment no longer
needs it. Commit only identifier-free summaries and explicitly computed comparison
hashes, never raw Status output.

Every status record must include:

- timestamp;
- OS product, build, and display version;
- environment support and refusal reasons;
- target resolution and loaded-hive state;
- hosts state and IPv4/IPv6 counts;
- firewall keyword/rule state;
- mint-path A/AAAA and TCP result;
- active-store, unknown-identity, opaque DeviceTicket, and residual-cache counts;
- exact verdict; and
- command exit code where an action was run.

### 2.2 Supporting instrumentation

| Instrument | Purpose |
|------------|---------|
| LiveId Operational log | DeviceAdd-class success/failure and service activity |
| CDP event logs / ETW | DDS registration attempts |
| `pktmon` or Wireshark | Destination and timing metadata; no ticket publication |
| Procmon filtered to IdentityCRL, TokenBroker, CDP, and `wlidsvc` | Local writer attribution |
| Windows Update Agent COM/API and update history | Controlled H5 evidence |
| Defender status/history | Signature-update evidence |
| Windows Firewall inspection | Dynamic keywords, FQDN rule, and `wlidsvc` service filter |
| `tools/hunt-lid-source.ps1` | Research-only mapping and ablation support |

Microsoft Message Analyzer is retired and is not a required tool.

### 2.3 Evidence record template

For each run, record:

1. snapshot source and exact start/end timestamps;
2. script commit or working-tree hash/diff identity;
3. exact command line;
4. redacted before/after Status JSON;
5. exit code and verdict;
6. elapsed online time and reboot count;
7. relevant event IDs and timestamps;
8. update KB/title/result when applicable;
9. UI action and exact error text for compatibility checks;
10. deviations from protocol; and
11. explicit non-claims.

Do not commit:

- full hexadecimal PUIDs or `g:<decimal>` values;
- account names, SIDs, profile paths, hostnames, IP histories, or VM IDs;
- `DeviceTicket` values;
- cookies, tokens, credentials, or packet payloads containing them; or
- unredacted Status/error output.

## 3. Current implementation under test

### 3.1 Exact managed FQDNs

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

The script does not install wildcard hosts entries or static DNS-derived IP rules.

### 3.2 Block composition

`-Block` must produce:

- one canonical managed hosts region;
- one `0.0.0.0` and one `::` entry per exact FQDN.

When local firewall policy permits, it should also refresh/report:

- one auto-resolving dynamic-keyword object per FQDN, with current address
  hydration reported separately;
- one enabled outbound deny over the complete keyword set; it is not assumed
  enforced while all keyword address sets are empty;
- one enabled outbound deny for `svchost.exe` service `wlidsvc`.

Those supplemental rules are not mandatory if another firewall policy/state exists
or cannot be rewritten and the actual DeviceAdd path still verifies blocked.

The independent mint-path check must show:

- sinkholed A and AAAA answers for `login.live.com`;
- no unexpected address;
- TCP 443 blocked when online; or
- `OfflineAccepted` only when the complete canonical hosts configuration is valid.

Do not blanket-block `*.microsoft.com`. The activity and DDS names in this set support the GDID registration/graph boundary; their presence is not evidence of general telemetry or court-channel suppression.

### 3.3 Mutation inventory

The current expanded bundle covers:

- target-user, `.DEFAULT`, and SYSTEM `LID`;
- target-user, `.DEFAULT`, and SYSTEM Immersive Property values;
- target-user, `.DEFAULT`, and SYSTEM Token `DeviceId` and `DeviceTicket`;
- `.DEFAULT` and SYSTEM `DeviceIdentities\production` state, including logs and
  all per-SID device identity sessions;
- target-user and SYSTEM Credential Manager device targets;
- matching machine NegativeCache keys;
- target-user TokenBroker cache contents; and
- target-user ConnectedDevicesPlatform cache contents.

The file-cache safety check must reject paths outside the resolved target profile and any cache tree containing a reparse point.

Wipe is canonical. Decoy is experimental.

### 3.4 Exact Status verdicts

| Verdict | Required interpretation |
|---------|-------------------------|
| `Error` | Inspection is incomplete; no safety conclusion |
| `UnsupportedEnvironment` | Readable but outside the mutation contract |
| `RealGdidPresent` | A real-shaped PUID exists in active or residual inventory; provenance is not inferred |
| `BlockDegraded` | No real-shaped PUID found, but the continuous gate is incomplete |
| `ProtectedNoRealGdid` | Supported/readable, no real-shaped PUID in known inventory, complete gate healthy |

Verdict precedence is the table order. A local `0018`-shaped Decoy can yield `RealGdidPresent`; that is expected.

### 3.5 Exit codes

| Code | Meaning |
|------|---------|
| `0` | Action success |
| `1` | Unexpected or administrator failure |
| `2` | Unsupported mutation environment |
| `3` | Block verification failure |
| `4` | Safe hosts-file refusal |
| `5` | Wipe/Decoy operation or postcondition failure |
| `6` | Target-user resolution failure |

Status communicates state through its verdict. Record both verdict and process exit code.

## 4. Exact-revision experiment matrix

### VAL-A - Offline baseline and first-mint prevention

From `S0-clean-iso`:

1. Disconnect the guest NIC before OOBE network access.
2. Complete OOBE with one local account.
3. At first desktop, capture redacted Status JSON.
4. Require `Environment.Supported=True`, no active/residual real-shaped PUID, and `BlockDegraded` before blocks exist.
5. Run `.\degdid.ps1 -Block` while still offline.
6. Capture Status and require the complete block state plus `ProtectedNoRealGdid`.
7. Snapshot as `S2-offline-current-blocked`.
8. Connect the NIC.
9. Inspect immediately, at 5 minutes, 30 minutes, and 60 minutes.
10. Reboot twice, inspecting after each interactive login.
11. Record LiveId/CDP events and any unexpected PUID.

Acceptance for this run is bounded to the actual completed interval and reboot count. A 60-minute result is not an indefinite result.

Control clone:

1. Restore `S1-oobe-offline`.
2. Leave degdid blocks absent.
3. Connect the NIC and capture first-mint timing.
4. Record the first real-shaped PUID by redacted hash and store location.
5. Preserve as `S3-control-first-minted`.

This control is a first mint, matching the class observed in EXP-B. It is not H7.

### VAL-B - Hosts and firewall state matrix

On disposable clones, test:

| Case | Expected action |
|------|-----------------|
| No managed hosts region or rules | Block creates canonical current state |
| Valid canonical region and rules | Block refreshes idempotently and verifies |
| Structurally paired but noncanonical region | Block and Unblock refuse it |
| Malformed marker | Block and Unblock refuse with exit code 4 |
| Duplicate region | Block and Unblock refuse with exit code 4 |
| Hosts file reparse point | Refuse to follow it |
| Missing keyword | Status `BlockDegraded`; Block recreates complete set |
| Invalid/duplicate keyword | Status degraded; Block replaces managed keyword state |
| Missing or invalid FQDN rule | Status degraded; Block recreates it |
| Missing or invalid `wlidsvc` rule | Status degraded; Block recreates it |

For every hosts case, compare unrelated lines, newline style, encoding/BOM, and backup creation. Never run malformed-marker tests on a non-disposable host.

### VAL-C - Canonical Protect from full contamination

From `S4-user-and-machine-contaminated`:

1. Confirm one real server-issued PUID is represented in target-user and machine stores; capture only its redacted hash in committed notes.
2. Confirm Immersive Property and Token state are present when naturally available.
3. Run `.\degdid.ps1 -Protect`.
4. Record each phase message, exit code, operation-failure count, and elapsed time.
5. Require `ProtectedNoRealGdid` immediately after success.
6. Confirm original service running/stopped states were restored.
7. Reboot twice.
8. Inspect immediately after login and at 5, 30, and 60 minutes online.
9. Force only documented, reversible identity-service activity and record exact commands/events.
10. Confirm the old redacted PUID hash never returns and no new real-shaped PUID appears during the completed window.

If any inventory read fails, the result is `Error`, not success. If a different real-shaped PUID appears, the result is `RealGdidPresent`, not "old ID removed."

### VAL-D - Fail-closed Protect transitions

Use only disposable snapshots and a controlled fault-injection harness. Record the exact fault and timing.

Required cases:

1. block application fails before mutation;
2. block verifies initially but fails immediately before identity writes;
3. gate is lost after identity writes and before service settle;
4. gate is lost during/after settle;
5. an identity-store operation fails;
6. a service cannot be stopped, resumed, or restored.

Expected properties:

- no identity write when initial block application or pre-write verification fails;
- explicit exit code 3 for gate failure;
- services remain quiesced when the gate is lost after writes and before settle;
- no success when any operation ledger entry, service restoration, inventory read, or postcondition fails; and
- already-cleared state is not falsely described as transactionally rolled back.

The fail-closed sequencing is implemented. These fault transitions are not yet lab-validated on the exact rewrite.

### VAL-E - Controlled Windows Update test

Historical EXP-D is only partial H5 evidence. The new run must begin with a **known pending cumulative update**.

1. Restore `S7-pending-cu` with current Protect already successful.
2. Capture Status, update title, KB, download state, and baseline history.
3. Run a Windows Update scan through a documented COM/API or UI path.
4. Download and install the selected cumulative update without changing the degdid block set.
5. Reboot if required.
6. Capture final update result/history and Status.
7. Require the same protected verdict and no real-shaped PUID.
8. Run Defender signature update as a separate check and record result/version.

Classify outcomes:

- **Supported for this KB/build/window:** selected CU installed successfully and protection remained complete.
- **Failed:** the selected CU failed for a demonstrated block-related reason.
- **Inconclusive:** no update was pending, update infrastructure was independently unhealthy, or causality was not isolated.

Optional H8: repeat with a feature update on a separate disposable snapshot. Do not fold a feature-update absence into H5.

### VAL-F - Compatibility matrix

Test at least three controlled states:

1. unblocked baseline;
2. Block only with a real PUID still present; and
3. Protect complete with no real-shaped PUID.

| Feature | Required check |
|---------|----------------|
| Boot / local login / desktop | Two reboots, Explorer, local app launch |
| Non-MSA browsing | Load defined HTTPS sites in Edge and one non-Edge client |
| Windows Update | VAL-E controlled CU |
| Defender signatures | Update and record version/result |
| Microsoft Store | Open, sign in if using a disposable test MSA, download a free app |
| Settings MSA | Attempt add/sign-in; capture exact error |
| OneDrive | Launch and attempt disposable MSA sign-in if package exists |
| Xbox | Launch and attempt disposable MSA authentication |
| Phone Link | Launch and attempt pairing |
| Nearby sharing / CDP | Exercise a defined peer workflow if available |
| Edge sync | Attempt with a disposable test MSA |
| Activation | Record pre/post status without attributing a pre-existing condition |

Record each result as `works`, `degraded`, `broken`, `not installed`, or `not run`. Package presence is not evidence that authentication works. A blocked dependency may justify an engineering expectation, but it remains **inferred** until the UI workflow is exercised.

### VAL-G - Unblock and recovery

Normal recovery:

1. From `S9-recovery`, preserve unrelated hosts lines and firewall rules as comparison fixtures.
2. Run `.\degdid.ps1 -Unblock`.
3. Verify only the current canonical hosts region, deterministic dynamic keywords, and exact current rules are gone.
4. Verify unrelated fixtures are unchanged.
5. Confirm the warning that future DeviceAdd can mint.

Unsupported-topology recovery:

1. Apply a valid block while the guest is supported.
2. On disposable clones, make the guest fail one target/profile preflight condition.
3. Verify Unblock remains callable without target resolution.
4. Confirm identity stores are untouched.

Safe refusal:

1. Corrupt or duplicate only the managed markers on a disposable clone.
2. Verify Unblock refuses instead of guessing.
3. Record that firewall removal does not proceed after the hosts refusal.

Recovery-safe means independent of the mutation target and conservative about owned state. It does not mean malformed files are auto-repaired.

### VAL-H - Direct H7 wipe-then-unblock remint

Do not use EXP-B as a substitute.

1. Start from a freshly contaminated `S4` clone with a recorded old PUID hash.
2. Run canonical Protect and require `ProtectedNoRealGdid`.
3. Run Unblock.
4. Confirm `login.live.com` A/AAAA and TCP 443 are reachable.
5. Invoke one predefined, documented DeviceAdd-capable client or service action.
6. Inspect at 2, 5, 15, 30, and 60 minutes and after one reboot.
7. Correlate any new real-shaped PUID with LiveId/packet timing.

Possible classifications:

- **H7 observed:** a new server-issued PUID appears after the defined DeviceAdd action and differs from the captured old PUID.
- **No remint in stated window:** no PUID appears; this is not proof that remint cannot occur later.
- **Inconclusive:** no evidence that a DeviceAdd-capable client actually ran.

### VAL-I - Experimental Decoy

1. Restore a contaminated disposable snapshot.
2. Run `.\degdid.ps1 -Protect -UseDecoy`.
3. Verify all required LID stores contain the same generated decoy and old PUIDs are absent.
4. Record the conservative Status verdict; do not expect `ProtectedNoRealGdid`.
5. Reboot twice under continuous blocks and inspect at the same planned intervals as VAL-C.
6. On a separate clone, Unblock and run the VAL-H DeviceAdd stimulus.

Decoy results must remain separate from canonical Wipe results.

## 5. C3 source-attribution protocol

Current evidence supports a bundle claim, not a unique-source claim.

Observed:

- naive LID-only cleanup failed in EXP-C2;
- Immersive `Property\<PUID>` and Token device state were present during mapping;
- the expanded cleanup bundle removed those stores and succeeded in the EXP-C3 window; and
- plaintext scans of selected AppData trees found no raw PUID.

Current implementation therefore clears Immersive Property as a required member of the successful bundle. To claim that it is the unique restore source, run controlled ablation on separate clones:

| Clone | Clear | Deliberately retain | Question |
|-------|-------|---------------------|----------|
| C3-A | LID only | Property, Token, caches | Reproduce known C2 failure |
| C3-B | LID + Property | Token and caches | Does rehydrate still occur? |
| C3-C | LID + Token | Property and caches | Does rehydrate still occur? |
| C3-D | LID + Property + Token | selected caches | Are file caches independently sufficient? |
| C3-E | Full current bundle | nothing in known model | Positive cleanup control |

Run ablation only in isolated VMs with registration blocked before any online period. The public tool should continue clearing the full bundle regardless of attribution results.

## 6. Failure interpretation

| Symptom | Interpretation to test |
|---------|------------------------|
| Old PUID returns while gate is healthy | Incomplete local source inventory or cleanup |
| Different PUID appears | DeviceAdd bypass, gate loss, or incorrect provenance assumption |
| `BlockDegraded` after servicing | Hosts/firewall/DNS drift; protection is incomplete |
| `Error` verdict | Inspection failure; do not infer absence |
| Store/MSA/Xbox/Phone Link failure | Expected dependency impact, but record the exact exercised workflow |
| Windows Update failure | Establish whether the selected endpoint/control caused it before attributing |
| Activation change | Compare baseline and avoid causality claims without isolation |
| Services remain stopped | Check for intentional fail-closed behavior and operation errors |
| Unblock refuses | Inspect managed marker structure; do not manually delete unrelated hosts content |

## 7. Stop conditions

- No snapshot-capable disposable VM: do not run identity mutation experiments.
- Personal MSA or production management enrollment appears: stop and revert.
- Full PUID or ticket enters a repository file: remove and rotate/recreate the experiment output before continuing.
- Supported-target facts cannot be established: expect refusal; do not bypass the preflight.
- Gate failure after identity writes: preserve evidence and restore only through the documented recovery procedure.
- Update infrastructure is independently unhealthy: classify H5 as inconclusive.
- Fault injection cannot be timed or reversed safely: defer that branch rather than improvising on a live host.

## 8. Deliverables

The GDID-only release validation is complete only when it produces:

1. exact current-revision identity and test-environment record;
2. supported-target and refusal matrix;
3. all five Status verdict examples with default redaction;
4. hosts/firewall state matrix, including `wlidsvc`;
5. canonical Protect result with stated online duration and reboot count;
6. fail-closed transition evidence or an explicit still-pending list;
7. a real target-user/machine contamination-shape Protect result;
8. Unblock recovery and malformed-marker results; and
9. updated countermeasure claims limited to the observed windows.

The controlled cumulative update, broader UI compatibility table, direct H7
classification, feature update, and C3 ablation remain useful follow-on research.
They are not required to close the narrow GDID-only promise unless a corresponding
compatibility or unique-source claim is promoted.

No new result should be labeled complete merely because the script returned zero once. State can drift, so every claim must include its observed window and postcondition evidence.
