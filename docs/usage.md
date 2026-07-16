# Usage and CLI Reference

Last updated: 2026-07-16

`degdid.ps1` inspects local GDID state, blocks the Microsoft DeviceAdd mint path,
and removes known local copies of real server-issued Device PUIDs.

## Requirements

Mutating actions require:

- elevated 64-bit Windows PowerShell;
- Windows 10 22H2/build 19045, or Windows 11 build 22000 or newer;
- no domain, Entra, workplace, or MDM enrollment;
- exactly one loaded human profile and one resolvable target user; and
- the target user's registry hive loaded.

Windows 11 25H2/build 26200 is the fully lab-validated line. Other accepted builds
produce a warning. Status can inspect unsupported systems, but mutation refuses
unknown or unsafe topology.

If Windows marks the downloaded script as Internet-origin, inspect it and remove
that file marker once:

```powershell
Unblock-File .\degdid.ps1
```

This is unrelated to the script's `-Unblock` action.

## Recommended workflow

Open an elevated PowerShell window:

```powershell
.\degdid.ps1 -Status
.\degdid.ps1 -Protect
.\degdid.ps1 -Status
```

`ProtectedNoRealGdid` is the only complete canonical result.

For a new offline installation, finish local-account OOBE, reach the desktop, run
`-Block` before connecting the NIC, and require `ProtectedNoRealGdid` before going
online.

## Commands

- `.\degdid.ps1 -Status` — human-readable diagnosis with full local identifiers.
- `.\degdid.ps1 -Status -Json` — full structured diagnostics.
- `.\degdid.ps1 -Block` — apply and verify the DeviceAdd network gate.
- `.\degdid.ps1 -Protect` — block, verify, then run canonical Wipe.
- `.\degdid.ps1 -Wipe` — wipe only when an existing gate already verifies.
- `.\degdid.ps1 -Protect -UseDecoy` — block and install an experimental decoy after cleanup.
- `.\degdid.ps1 -Decoy` — install a decoy only when an existing gate verifies.
- `.\degdid.ps1 -Unblock` — remove valid degdid-owned network controls.
- `.\degdid.ps1 <action> -DryRun` — report intended work without substituting planned state for current state.

Use `-Protect` for the normal contaminated-system path. `-Wipe` and `-Decoy`
refuse to mutate without a verified block.

## Status verdicts

- `Error` — inspection was incomplete or opaque identity state prevents a safe conclusion.
- `UnsupportedEnvironment` — readable, but outside the mutation contract.
- `RealGdidPresent` — a real-shaped PUID exists in known active or residual state.
- `BlockDegraded` — no real-shaped PUID was found, but the continuous gate is incomplete.
- `ProtectedNoRealGdid` — supported and readable, known real-shaped state absent, gate healthy.

Verdict precedence follows that order. Status displays the actual account, profile,
registry PUIDs, and `g:<decimal>` values; do not publish its full output.

## What Protect changes

Protect first applies and verifies:

1. a canonical dual-stack managed hosts region; and
2. the actual `login.live.com` DeviceAdd path as blocked.

It also refreshes dynamic-FQDN and `wlidsvc` firewall rules when local policy allows
them. Those firewall rules are reported defense in depth; the verified hosts and
actual path state are the required gate.

After the gate verifies, Wipe clears known GDID state from the target user,
`.DEFAULT`, and SYSTEM, including:

- LID, Immersive Property, Token DeviceId, and DeviceTicket state;
- machine `IdentityCRL\DeviceIdentities\production` state;
- matching NegativeCache and target-user cache artifacts; and
- targeted target-user and SYSTEM device credentials that can restore device identity.

For target-user device credentials, the script may create a short-lived limited
scheduled task in the interactive logon session, delete only the two known device
targets, then remove the task and result file. It does not delete the user's MSA
account credential.

Protect rechecks the gate before mutation and after settling services. A failed gate
or postcondition returns failure rather than claiming partial success.

## Unblock and recovery

```powershell
.\degdid.ps1 -Unblock
```

Unblock removes only the current canonical hosts region, deterministic dynamic
keywords, and exact firewall rules owned by degdid. It remains available after
profile or management topology changes, but still requires elevation.

It refuses malformed, duplicate, or noncanonical managed hosts state rather than
guessing. Once controls are removed, Windows can mint a real GDID again; the lab
observed a rebooted remint in 22 seconds under identity triggers.

## Decoy mode

Decoy writes a locally generated `0018`-shaped value. Shape alone cannot prove
whether Microsoft issued a value, so decoy mode is research-only and may correctly
produce `RealGdidPresent`. Canonical protection uses Wipe.

## Exit codes

- `0` — success.
- `1` — unexpected or administrator failure.
- `2` — unsupported mutation environment.
- `3` — block verification failure.
- `4` — safe hosts-file refusal.
- `5` — Wipe/Decoy operation or postcondition failure.
- `6` — target-user resolution failure.

For control semantics and residual risk, see
[`countermeasures.md`](countermeasures.md). For storage and endpoint details, see
[`surfaces.md`](surfaces.md).
