# degdid

Last updated: 2026-07-16

Research and practical hardening for Microsoft's **Global Device Identifier (GDID)**, a server-assigned installation identifier that Windows can acquire even when the interactive user has only a local account.

The repository documents the wider GDID lifecycle. The shipped `degdid.ps1` has a narrower operational objective:

> On a supported Windows target, remove real server-issued GDID state from the known local stores and keep the DeviceAdd path continuously blocked.

That is a GDID completion gate. It is not a general telemetry, browser-privacy, or court-record-channel suppression claim.

## Why it exists

GDID is a server-assigned 64-bit Device PUID that Windows can mint through
Microsoft's DeviceAdd infrastructure and retain across several local identity
stores. A local Windows account does not prevent that machine-level mint.

Court reporting in 2026 established that Microsoft held a GDID-to-URL/time/IP
association in one investigation. The public record does not identify the Windows
component or network channel responsible; this tool makes no claim to block that
unknown channel.

## Is this for my PC?

The mutation path is designed for an unmanaged personal Windows installation with
one loaded human profile:

- Windows 10 22H2/build 19045, or Windows 11 build 22000 or newer;
- no domain, Entra, workplace, or MDM enrollment; and
- an elevated 64-bit Windows PowerShell session.

Windows 11 25H2/build 26200 is the fully lab-validated line. Other accepted builds
warn. Managed systems, ambiguous users, and multiple loaded human profiles are
refused instead of guessed at.

Status can still inspect unsupported systems. See the
[`usage guide`](docs/usage.md) for the complete eligibility rules.

## Quick start

Open an elevated PowerShell window:

```powershell
.\degdid.ps1 -Status
.\degdid.ps1 -Protect
.\degdid.ps1 -Status
```

`ProtectedNoRealGdid` is the only complete result. Re-run Status after major Windows,
firewall, security-product, or hosts-file changes.

To remove degdid's network controls:

```powershell
.\degdid.ps1 -Unblock
```

Unblock allows Windows to mint a real GDID again. See the
[`usage and CLI reference`](docs/usage.md) for every command, verdict, exit code,
DryRun behavior, pre-first-online setup, and recovery details.

## What Protect does

Protect:

1. applies a dual-stack hosts block and checks the actual DeviceAdd path;
2. refreshes firewall defense-in-depth where policy allows it;
3. clears known GDID copies and device-identity rehydrate sources from the target
   user, `.DEFAULT`, and SYSTEM; and
4. waits, rechecks the network gate, and refuses success if identity state returns.

The network gate is applied before identity mutation. If a required check fails, the
script stops instead of continuing with a partial protection state.

Canonical protection uses Wipe. Decoy mode exists for research but is not considered
a clean completion state. Technical mutation details live in
[`countermeasures.md`](docs/countermeasures.md) and
[`surfaces.md`](docs/surfaces.md).

## What success means

`ProtectedNoRealGdid` means the supported environment was readable, no real-shaped
PUID remained in the known inventory, and the DeviceAdd gate verified. It does not
mean Microsoft deleted historical records or that unrelated telemetry stopped.

Status intentionally displays full local account, profile, PUID, and `g:<decimal>`
values. Treat its output as private machine-identifying data.

## Lab evidence and limits

The completed Windows 11 25H2/build-26200 lifecycle includes:

- prevention before first network access;
- natural mint, Protect, reboot, and repeated identity triggers;
- more than 33 hours protected on the local-account lab VM;
- Unblock, observed remint, reprotect, and clean reboot; and
- an MSA-connected field run that remained protected through sign-out/in,
  sleep/resume, reboot, and 18 hours.

The evidence is bounded to the recorded machines and windows. Windows 10 and other
Windows 11 builds are accepted with warnings, not equivalent lab claims. See the
[`experiment index`](docs/experiments/README.md) for the failures, fixes, timings,
and limitations that produced the current design.

## Expected compatibility impact

- Blocking `login.live.com`, `account.live.com`, DDS, and the `wlidsvc` service path is expected to break or degrade MSA sign-in, Store and Xbox authentication, OneDrive MSA sign-in, Phone Link, CDP graph features, and related identity workflows.
- Core desktop access worked in the lab.
- Windows Update scan, Defender update, and historical blocked-period installs were observed, but a controlled pending cumulative update and feature update remain unvalidated.
- Domain, Entra, MDM, and multiple-loaded-profile systems are refused rather than assigned speculative compatibility claims.

## Read more

- [`docs/usage.md`](docs/usage.md) — commands, verdicts, exit codes, and recovery.
- [`docs/countermeasures.md`](docs/countermeasures.md) — exact gate, wipe scope, and residual risk.
- [`docs/architecture.md`](docs/architecture.md) — GDID generation and lifecycle model.
- [`docs/surfaces.md`](docs/surfaces.md) — registry, credential, service, and endpoint inventory.
- [`docs/experiments/`](docs/experiments/) — complete lab and field evidence.
- [`docs/open-questions.md`](docs/open-questions.md) — the short remaining research backlog.

## Safety and ethics

- Use this work for research, privacy hardening, and analysis of opaque device identity.
- It is not a guide to evade lawful process or commit crimes.
- Do not commit private machine GDIDs, device tickets, unredacted Status JSON, or machine-identifying dumps. A cited public court example is source material, not a lab secret.

## License

Licensed under the [MIT License](./LICENSE). The work is provided as-is, without warranty; you are responsible for changes made to your systems.
