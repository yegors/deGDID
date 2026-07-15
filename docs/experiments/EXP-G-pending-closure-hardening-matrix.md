# EXP-G - Pending closure / hardening matrix

Status: **PASS BEYOND 33 HOURS + CLEAN S1 ONE-PASS CONTROL — current Protect held after a fresh natural mint, reboot, and repeated identity triggers**

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

The first three-hive rerun again passed immediately but the same machine PUID
returned after eight hours. At that point only SYSTEM/`.DEFAULT` LID was visible;
Property and Token stores remained empty. LiveId SOAP attempts still failed with
`0x80048051`. A temporary SYSTEM-context credential audit found
`WindowsLive:target=virtualapp/didlogical` in the SYSTEM Credential Manager vault.
The wipe now inspects/deletes the two device-credential targets in both the target
interactive session and the SYSTEM session.

The failed state was preserved before cleanup. A fresh Protect/soak rerun with
SYSTEM credential cleanup is required; the prior immediate and reboot passes remain
useful but do not satisfy G2.

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

That threshold check failed with the same machine PUID in SYSTEM/`.DEFAULT` LID
while Property and Token stores remained empty. A SYSTEM-context Credential Manager
audit found `WindowsLive:target=virtualapp/didlogical`. LiveId attempts continued to
fail with `0x80048051`.

The next revision added target-user **and SYSTEM-session** device-credential
inspection/deletion. Immediate rerun:

- Protect returned `0`;
- all 39 operations succeeded;
- all three hives were clear;
- target-user and SYSTEM device-credential counts were `0`; and
- verdict was `ProtectedNoRealGdid`.

An eight-hour threshold check was armed to exceed both earlier failure windows.

## Final delayed-rehydrate result — PASS beyond 33 hours

At eight hours, and again more than 33 hours after the SYSTEM-credential revision:

- verdict remained `ProtectedNoRealGdid`;
- target-user, `.DEFAULT`, and SYSTEM active-store counts were `0`;
- residual PUID count was `0`;
- DeviceTicket count was `0`;
- target-user and SYSTEM device-credential count was `0`;
- TokenBroker and ConnectedDevicesPlatform cache counts were `0`;
- canonical A/AAAA sink responses remained active; and
- TCP to `login.live.com` remained blocked.

This exceeds both earlier delayed-failure windows (roughly seven and eight hours)
and the original 24-hour criterion. G2 is closed for the measured 33-hour window;
no indefinite-duration claim is made.

The VM was then refreshed with the current script and force-rebooted once more.
Pre-reboot and post-heartbeat Status both returned `ProtectedNoRealGdid`, with zero
PUIDs, tickets, target/SYSTEM device credentials, and cache entries. The canonical
hosts and actual DeviceAdd path remained healthy after reboot.

## Clean S1 one-pass control — 2026-07-15

To separate current-script behavior from the repeatedly restored contaminated
checkpoint, the lab returned to the offline S1 snapshot exactly once and did not
bounce between checkpoints afterward.

- Before network attachment, no readable PUID was present and the canonical blocks
  were absent. Status still treated unresolved opaque identity state in the old
  snapshot as an error rather than claiming a clean state.
- After attaching the Default Switch and starting the identity services/tasks, one
  real PUID appeared naturally in two LID stores after approximately one second.
- The current `-Protect` was run exactly once on that same timeline. It captured one
  real PUID, completed all 35 recorded operations without failure, and immediately
  returned `ProtectedNoRealGdid`.
- The immediate postcondition contained zero PUIDs, machine DeviceIdentities roots,
  DeviceTickets, or target/SYSTEM device credentials.
- After a normal guest reboot, Status again returned `ProtectedNoRealGdid` with all
  four counts still zero.
- Ten further observation cycles repeatedly started `wlidsvc`/`CDPSvc`, invoked the
  available DeviceDirectoryClient and Device Information registration tasks, and
  checked full Status. The final check at 497 seconds remained
  `ProtectedNoRealGdid`, with all four counts at zero.

This is a current-revision one-pass result from a freshly and naturally minted S1
control. It does not reproduce or explain the earlier recurrence from the heavily
contaminated minted checkpoint, and it does not replace the separate 33-hour
duration evidence or the pending MSA-connected EXP-H rerun. It does show that the
current conservative DeviceIdentities cleanup is sufficient for the clean S1 mint
path exercised here; no further speculative source deletion is justified by this
run.

## Closure rule

G2 is closed for the measured 33-hour bounded window. Remaining discrete matrix
work is G3 session/power transitions and a disposable-guest G8 confirmation; G7 has
multiple real fail-closed defects plus unit coverage but not every synthetic branch.
G6 is optional expansion to 24H2. G9 is optional, but H5 remains partial until a
controlled pending CU is exercised. G10 is optional research because the public
tool already clears the full conservative bundle; Immersive Property remains a
required/high-confidence member without a unique-cause claim.

The clean S1 control also passes the current one-Protect natural-mint/reboot/trigger
path. The contaminated-checkpoint recurrence remains a distinct unresolved lab
artifact and is not used to weaken or inflate that bounded result.

Unlisted rows remain **NOT RUN / pending**.
