# EXP-H - MSA profile local LID rehydrate

Date: 2026-07-12 to 2026-07-16
Evidence: **PASS AT 18 HOURS — current Protect remained clean through reboot, sign-out/in, and sleep/resume on the MSA-connected profile**

## Environment

- Windows 11 25H2 build 26200
- Unmanaged, one loaded target profile
- Target profile connected to a Microsoft Account
- Full identifiers, hostname, account, SID, and profile path omitted here

## Before Protect

- Registration protection absent
- One active target-user PUID in LID, Immersive Property, and 13 Token DeviceId copies
- A different active machine PUID in SYSTEM and `.DEFAULT`
- Two additional PUIDs in machine NegativeCache only
- 13 opaque DeviceTickets

## First exact-rewrite Protect result

The block phase passed:

- canonical IPv4/IPv6 hosts region;
- firewall/service rule valid; and
- `login.live.com` A/AAAA/TCP blocked.

The wipe recorded 38 operations with zero operation failures, but its postcondition
correctly returned failure. After settle:

- Property, Token DeviceId, DeviceTicket, machine LID, NegativeCache, and file-cache
  cleanup had succeeded;
- the **same original target-user PUID** existed again in
  `ExtendedProperties\LID`; and
- no new machine PUID appeared.

## Interpretation

This was not a server remint: the registration path remained blocked and the exact
old user PUID returned alone. The MSA profile therefore has another local
device-identity rehydrate input outside the earlier Property/Token/file-cache bundle.

The same identity shape on an inspected MSA workstation included these target-user
Credential Manager entries:

- `MicrosoftAccount:target=SSO_POP_Device`
- `WindowsLive:target=virtualapp/didlogical`

Those are device credentials, not the MSA user account credential. The hardened wipe
now inventories and removes those two device targets before deleting LID. Because
UAC elevation uses a different credential logon session, an elevated run uses a
short-lived limited scheduled task in the target interactive session rather than
assuming equal SIDs share Credential Manager state.

## Final-rerun criteria

- [x] Re-run `-Protect` on the reporting MSA machine with the updated script.
- [x] Confirm the targeted device credentials and known GDID state are absent
  through the `ProtectedNoRealGdid` postcondition.
- [x] Confirm `ProtectedNoRealGdid` after reboot, sign-out/in, and sleep/resume.
- [x] Exceed the earlier approximately 20-minute MSA-machine return window.

The conditional registry-audit escalation was not needed because the same LID did
not return. User-account identity properties were not broadened or deleted.

## Second field attempt — staging-rule false refusal

The credential-aware revision correctly reported:

- only the old target-user LID remained;
- both targeted MSA device credentials were present; and
- the permanent `wlidsvc` rule was active with enforcement
  `ProfileInactive Enforced`.

Protect then aborted before identity mutation because the temporary staging rule was
not itself marked enforced. JSON showed the permanent rule was already enforced and
one staging rule existed. Windows had optimized the duplicate temporary rule while
the identical permanent deny was active.

This was a guardrail error, not another wipe failure. The handoff now accepts either
the permanent or staging deny before replacement, removes the permanent rule, then
waits for and requires the staging deny to become enforced before continuing. A
stale owned staging rule no longer makes otherwise valid protection report malformed.

## Third field attempt — target-user remediation passed

After relaxing the duplicate-rule handoff, Protect completed:

- block/path verification passed;
- all 32 operations succeeded;
- target-user LID and both MSA device credentials were absent; and
- immediate verdict was `ProtectedNoRealGdid`.

About 20 minutes later, the original **machine** PUID returned in SYSTEM and
`.DEFAULT` LID while the target user and MSA device credentials stayed clear. This
separates the two causes: target-user MSA rehydrate was fixed; machine identity had
the same delayed machine-hive/SYSTEM-credential gaps found independently in EXP-G.

The current script now applies the EXP-G three-hive and SYSTEM Credential Manager
cleanup to this case as well. At this stage a final MSA-machine rerun/reboot
remained pending; the completed result is recorded below.

## Fourth field attempt — busy wlidsvc refused normal stop

The latest pre-state showed the original machine PUID across `.DEFAULT` and SYSTEM:

- both LID stores;
- both Immersive Property stores;
- 26 Token DeviceId copies;
- 26 DeviceTickets; and
- two device Credential Manager targets.

Protect verified the required hosts and actual DeviceAdd path, then aborted before
identity mutation because running `wlidsvc` rejected the ordinary service stop.
Operation accounting showed one failed stop and no identity writes, so the
fail-closed behavior was correct.

The service quiesce path now waits through stop-pending, then—only for busy
`wlidsvc`—temporarily sets startup to Disabled, retries via SCM, and restores the
original startup type before normal resume. It does not terminate the shared
`svchost` process or indiscriminately stop dependencies. At this stage the rerun
remained pending.

## Final field rerun — PASS at 18 hours

The reporting MSA-connected machine ran the current Protect revision successfully.
Status reported `ProtectedNoRealGdid` after the wipe and remained protected through:

- sign-out and sign-in;
- sleep and resume;
- a normal reboot; and
- the final check 18 hours after Protect.

This exceeds the earlier approximately 20-minute MSA-machine return and both
approximately seven-to-eight-hour machine rehydrate windows found during EXP-G.
Together with EXP-G's separate beyond-33-hour local-account result, it closes the
known target-user credential and machine-state rehydrate paths for the measured
Windows 11 25H2/build-26200 scenarios.

This field result validates the current overall quiesce/cleanup path. It does not
claim that the bounded `wlidsvc` disable/SCM fallback branch itself activated during
this successful run; that branch remains covered by focused tests.
