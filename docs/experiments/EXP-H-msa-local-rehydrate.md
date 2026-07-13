# EXP-H - MSA profile local LID rehydrate

Date: 2026-07-12  
Evidence: **user-provided field run; target-user remediation passed; delayed machine-hive remediation pending rerun**

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

## Pending

- Re-run `-Protect` on the reporting MSA machine with the updated script.
- Confirm both device credential targets are absent after settle.
- Confirm `ProtectedNoRealGdid` immediately and after reboot/service triggers.
- If the same LID still returns, enable the registry audit helper before broadening
  cleanup into MSA account properties. Do not delete user-account identity stores
  speculatively.

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
cleanup to this case as well. A final MSA-machine rerun/reboot remains pending.
