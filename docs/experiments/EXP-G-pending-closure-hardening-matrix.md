# EXP-G - Pending closure / hardening matrix

Status: **FAILED AT ~7 HOURS — machine-hive Property/Token rehydrate found; expanded three-hive fix pending rerun**

This began as an experiment design. The bounded interim observations below are now recorded; unexecuted rows remain pending and no longer-duration outcome is implied.

## GDID-only completion gate

The required rows close only the narrow question of whether the inspected local GDID stores remain empty under the stated conditions. They do not establish anonymity, erase server-side history, prove that every mint path is blocked, or certify general Windows compatibility.

For each future run:

- Start from a documented disposable snapshot and record only redacted state.
- Inspect HKCU, `.DEFAULT`, SYSTEM, Immersive Property, and Token DeviceId/Ticket state before and after each transition.
- Record block continuity and any exposure gap; a gap invalidates a continuous-block result.
- Record elapsed time and the exact transitions/triggers exercised.
- Keep raw or redacted command output out of version control; commit only identifier-free summaries.
- Mark a row pass, fail, or partial from captured evidence. Do not infer an unexercised path.

## Pending matrix

| ID | Pending dimension | Designed check |
|----|-------------------|----------------|
| G1 | Dual-stack | Exercise IPv4 and IPv6 with registration blocks already active; verify relevant A/AAAA resolution and blocking behavior, then inspect for a local GDID. |
| G2 | Duration + reboot | Hold continuous blocks for **>=24h**, inspect at defined intervals, and complete **2 reboots** before the final inspection. |
| G3 | Session + power transitions | Under continuous blocks, exercise sign-out/in and sleep/resume, inspecting after each transition. |
| G4 | Service and task triggers | Restart the identity/CDP services and invoke the relevant Device Information/DDS scheduled-task triggers; record exact trigger names and inspect after each. |
| G5 | Real user-hive contamination | From a disposable single-user snapshot with a real PUID in LID, Property, Token/Ticket, and machine residual stores, run canonical Protect and inspect across G2-G4 transitions. Actual MSA UI sign-in is compatibility work, not a GDID-state requirement. |
| G6 | Optional build expansion | Repeat the same redacted protocol on 24H2 before adding that build to the supported contract; keep its results separate from 25H2. |
| G7 | `-Protect` fail-closed | Inject controlled failures into block/wipe prerequisites and verify `-Protect` leaves registration blocked or aborts without an exposure gap; any fail-open path fails this row. |
| G8 | Malformed hosts / `-Unblock` preservation | Use a synthetic hosts file containing malformed managed markers plus unrelated comments and entries; verify safe failure and that `-Unblock` preserves all unrelated content byte-for-byte. |
| G9 | Pending CU (optional) | With a real pending cumulative update on a disposable snapshot, perform a controlled search/download/install/reboot under continuous blocks, then inspect GDID state. This optional row is required only to advance H5 beyond partial. |
| G10 | Optional C3 ablation | Revert to the same HKCU-contaminated snapshot and compare one-store omissions only if unique-source attribution is still desired; canonical Wipe continues clearing the full bundle regardless. |

## Interim exact-rewrite run — 2026-07-11

Environment: Hyper-V Windows 11 25H2 build 26200, unmanaged, one loaded human
profile, local account with target-user and machine GDID state already present.
This was **not** a Microsoft-account UI/sign-in compatibility validation. For the
GDID-only gate, the exercised real LID/Property/Token/Ticket/NegativeCache state
shape is the required contamination case; MSA UI behavior remains outside completion.

The first disposable attempts found three implementation defects:

1. Atomic hosts replacement rejected a null backup path. Protect exited before
   identity mutation and left the staging `wlidsvc` deny active.
2. An operation-ledger parameter shadowed service names. Protect exited before
   identity writes and reported every failed stop.
3. Native Property deletion opened the key read-only. The wipe partially cleared
   other stores, retained the old Property PUID, returned failure, and Status
   remained `RealGdidPresent`.

After correcting those defects:

- `-Protect` returned `0`;
- the block gate reported canonical 11-host IPv4 + IPv6 entries;
- the FQDN and `wlidsvc` firewall rule configuration validated;
- FQDN keyword address hydration remained `0` under the hosts sink, so it is not
  treated as an independently enforced address layer in this result;
- A and AAAA returned only sink addresses and TCP 443 failed;
- all 23 recorded mutation/service operations succeeded;
- active real-shaped PUID count was `0`;
- residual NegativeCache PUID count was `0`; and
- verdict was `ProtectedNoRealGdid`.

Two forced VM reboots followed. After each reboot, an authenticated sole-profile
PowerShell Direct session loaded the target hive and Status again returned
`ProtectedNoRealGdid`, with canonical dual-stack hosts, both firewall rules valid,
and no active or residual real-shaped PUID.

The identity-service/task trigger row was then exercised: `wlidsvc`, `CDPSvc`, and
the available `CDPUserSvc` instance were started/restarted; the DeviceDirectoryClient
and Device Information registration tasks were invoked; and the guest soaked for
60 seconds. Status remained `ProtectedNoRealGdid` with no active/residual real-shaped
PUID.

Boundaries:

- G1 is supported for sinkholed A/AAAA and the integrated service rule on this
  guest; it was not an IPv6-only routed-network test.
- The two-reboot portion of G2 passed initially, but the duration row later failed
  at roughly seven hours when a machine PUID returned.
- G4 passed for the named service/task triggers and 60-second post-trigger window.
- G5's target-user shape passed, but machine-hive Immersive Property/Token coverage
  was incomplete and invalidates full closure.
- G7 has concrete fail-closed evidence for three naturally encountered defects;
  the complete injected transition matrix remains pending.
- G8 remains covered by pure hosts tests, not yet by the disposable-guest matrix.

## Delayed failure — 2026-07-12

At the later soak check, Status found one PUID in SYSTEM and `.DEFAULT` LID while:

- the canonical hosts region remained valid;
- A and AAAA remained sinkholed;
- TCP to `login.live.com` remained blocked; and
- the enforced `wlidsvc` service rule remained active.

The returned PUID differed from the pre-wipe target-user PUID. LiveId logs showed
repeated SOAP attempts (`6115`) followed by `WLIDAcquireTokens` failure
`0x80048051`; no successful DeviceAdd completion was observed.

The current machine PUID was also present locally in both SYSTEM and `.DEFAULT`:

- `Immersive\production\Property\<PUID>`; and
- nine Token `DeviceId` copies in each hive.

Interpretation: this is another local rehydrate gap, not evidence of successful
server mint under the block. The current rewrite inventoried/cleared Property and
Token only in the target-user hive. The source model now covers target-user,
`.DEFAULT`, and SYSTEM LID + Property + Token/Ticket stores symmetrically.

The failed state was checkpointed before cleanup. A fresh Protect/soak rerun is
required; the prior immediate and reboot passes remain useful but do not satisfy G2.

## Three-hive remediation rerun

The updated source model inventoried and cleared LID, Immersive Property, Token
DeviceId, and DeviceTicket state in the target-user, `.DEFAULT`, and SYSTEM hives.

Immediate rerun result:

- canonical hosts and the actual DeviceAdd path verified;
- Protect returned `0`;
- all 40 operations succeeded;
- active and residual real-shaped PUID count was `0`;
- device-ticket and device-credential count was `0`; and
- verdict was `ProtectedNoRealGdid`.

An eight-hour threshold check is armed to exceed the prior roughly seven-hour
failure point. This immediate result does not yet close G2.

## Closure rule

To close the validated 25H2/build-26200 line, rerun canonical Protect with the
three-hive source model, restart G2, run the remaining G3 transitions, and finish
the disposable-guest G7/G8 matrix.
G6 is optional expansion to 24H2. G9 is optional, but H5 remains partial until a
controlled pending CU is exercised. G10 is optional research because the public
tool already clears the full conservative bundle; Immersive Property remains a
required/high-confidence member without a unique-cause claim.

Unlisted rows remain **NOT RUN / pending**.
