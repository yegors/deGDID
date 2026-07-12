# degdid

Last updated: 2026-07-11

Research and practical hardening for Microsoft's **Global Device Identifier (GDID)**, a server-assigned installation identifier that Windows can acquire even when the interactive user has only a local account.

The repository documents the wider GDID lifecycle. The shipped `degdid.ps1` has a narrower operational objective:

> On a supported Windows 11 target, remove real server-issued GDID state from the known local stores and keep the DeviceAdd path continuously blocked.

That is a GDID completion gate. It is not a general telemetry, browser-privacy, or court-record-channel suppression claim.

## Supported target

`-Block`, `-Wipe`, `-Decoy`, and `-Protect` mutate only when all of the following are established:

- Windows 11 **25H2, build 26200** (the currently enabled test target; exact-rewrite closure is still pending)
- not domain joined
- not Entra joined, registered, or workplace joined
- not MDM enrolled
- exactly one loaded target human-profile hive; dormant non-special profile artifacts are reported but do not block
- an active interactive user, or an authenticated session whose SID maps to the sole loaded profile
- that user's `HKEY_USERS\<SID>` hive is loaded
- elevated administrator PowerShell

Mutation is refused when any of those facts is false or cannot be established. More
than one simultaneously loaded human-profile hive is unsupported because the tool
does not guess between active targets. Dormant sandbox/tool/profile artifacts are
counted and warned about, but they are not mistaken for active human sessions.

Other Windows 11 releases, including 24H2, remain research targets rather than advertised mutation support until the same closure matrix is run there.

`-Status` remains available for inspection on unsupported systems. `-Unblock` is the recovery exception: it does not require a supported profile topology and removes only degdid-managed network state, although a real unblock still requires elevation.

## What GDID is

- A **64-bit Device PUID**, represented by Microsoft as `g:<decimal>` and commonly stored locally as 16 hexadecimal digits beginning with `0018`.
- Minted through Microsoft identity infrastructure, notably the `login.live.com` DeviceAdd path.
- Persisted in IdentityCRL state, including target-user, SYSTEM, and `.DEFAULT` `LID` values, target-user Immersive Property and Token state, and related caches.
- Used as a durable Windows installation key across identity, device-graph, and reporting systems. It is not simply a local hash of hardware serials; DeviceAdd can still send durable hardware material to Microsoft.

Court reporting in 2026 established that Microsoft held a GDID-to-URL/time/IP association in one investigation. The public record does not identify the responsible Windows component or network channel. See `docs/` for sources and confidence tags.

## What the tool does not claim

- It does not erase Microsoft's server-side history for an old GDID.
- It does not stop all Windows telemetry. DiagTrack, SmartScreen, Defender, Delivery Optimization, and other planes are outside this completion gate unless explicitly described.
- It does not identify or suppress the unknown channel behind the court-reported URL association.
- It does not prevent correlation through an MSA, IP history, TPM or hardware material, advertising IDs, Entra IDs, or other identity systems.
- It does not guarantee anonymity or make a VPN conceal Windows-to-Microsoft traffic.

## Implemented protection gate

`-Block` installs and verifies all of the following:

1. A canonical managed `hosts` region containing both `0.0.0.0` and `::` entries for the registration host set.
2. Windows Firewall dynamic-keyword objects for each exact FQDN and one outbound deny rule over that set; current address hydration is reported separately and is not assumed when hosts suppress DNS.
3. A separate outbound service-scoped deny rule for `wlidsvc`, which is the independent firewall mint control when FQDN addresses are unhydrated.
4. A mint-path check: canonical hosts state, valid firewall/service state, sinkholed A and AAAA answers for `login.live.com`, and a failed TCP connection, or an explicitly accepted offline state.

The controls must remain in place continuously. The lab observations below cover stated short windows; they do not prove that a control will remain effective indefinitely. Re-run `-Status` after Windows servicing, firewall-policy changes, security-product changes, or manual hosts-file edits.

`-Protect` is fail-closed with respect to identity mutation. It refreshes and verifies the block first, aborts before identity writes if that phase fails, verifies again immediately before writing, and checks the gate and local inventory after a service-settle interval. If the gate is lost after identity writes, the script reports failure and can intentionally leave identity services quiesced rather than resume into an unblocked mint path.

## Wipe is canonical; decoy is experimental

The default protection action is:

```powershell
.\degdid.ps1 -Protect
```

This applies the block gate and performs the expanded **Wipe**. The wipe covers known target-user, SYSTEM, and `.DEFAULT` active stores, target-user Immersive Property and Token device fields, matching machine NegativeCache entries, and target-user TokenBroker and ConnectedDevicesPlatform caches. It then waits, re-inventories, and requires the old PUIDs and any other real-shaped PUID to be absent.

Decoy mode is available for research:

```powershell
.\degdid.ps1 -Protect -UseDecoy
```

It writes one generated `0018`-shaped local value consistently after clearing old state. The tool cannot later prove from shape alone that such a value was locally generated rather than server issued. Consequently, decoy mode is not the canonical `ProtectedNoRealGdid` completion path and remains experimental.

## Status and exact verdicts

Status is the default action:

```powershell
.\degdid.ps1 -Status
```

Status is written for the person at the keyboard: it shows the actual account,
profile, registry PUIDs, and `g:<decimal>` GDIDs by default. Use explicit redaction
only when preparing output to share:

```powershell
.\degdid.ps1 -Status -Redact
```

Structured JSON follows the same rule:

```powershell
.\degdid.ps1 -Status -Json
.\degdid.ps1 -Status -Json -Redact
```

The verdict is exactly one of:

| Verdict | Meaning |
|---------|---------|
| `Error` | Inspection was incomplete/unreliable, or opaque DeviceTicket/unknown active identity state prevents an absence conclusion. |
| `UnsupportedEnvironment` | The machine is readable but outside the mutation contract. |
| `RealGdidPresent` | At least one `0018`-shaped PUID exists in a known active store or residual registry cache. Shape does not prove provenance. |
| `BlockDegraded` | No real-shaped PUID was found, but the continuous block gate is incomplete. |
| `ProtectedNoRealGdid` | The supported environment is readable, no real-shaped PUID is present in the known inventory, and the block gate is healthy. |

Verdict precedence follows the table from top to bottom. `ProtectedNoRealGdid` is the only complete canonical state.

## Commands

| Command | Meaning |
|---------|---------|
| `.\degdid.ps1 -Status` | Human-readable diagnosis with actual local GDID values. |
| `.\degdid.ps1 -Status -Redact` | Share-safe diagnosis with identifying values hashed. |
| `.\degdid.ps1 -Status -Json` | Emit full technical diagnostics as JSON. |
| `.\degdid.ps1 -Block` | Refresh and verify the dual-stack hosts and firewall gate. |
| `.\degdid.ps1 -Protect` | Block, verify, then run canonical Wipe. |
| `.\degdid.ps1 -Protect -UseDecoy` | Block, verify, then run experimental Decoy. |
| `.\degdid.ps1 -Wipe` | Run Wipe only when an existing block gate already verifies. |
| `.\degdid.ps1 -Decoy` | Run experimental Decoy only when an existing block gate verifies. |
| `.\degdid.ps1 -Unblock` | Remove valid degdid-owned hosts/firewall state and warn that a future DeviceAdd may mint. |
| `.\degdid.ps1 <action> -DryRun` | Report planned work without substituting planned state for current state. |

`-Wipe` and `-Decoy` do not merely warn about a missing block; they refuse to mutate. Use `-Protect` for the normal order.

`-Unblock` remains usable if the machine later becomes managed, gains another profile, or has no interactive user. It removes a valid paired managed hosts region, managed dynamic keywords, and current or legacy `degdid-block-*` firewall rules. It refuses malformed or duplicate hosts markers rather than guessing at unrelated content.

## Lab evidence and limits

Historical experiments used a Hyper-V Windows 11 25H2 build 26200 local-account VM. They validate parts of the design, not every branch of the current hardened rewrite.

| Experiment | What was observed | Limit |
|------------|-------------------|-------|
| EXP-A1 | Offline OOBE reached the desktop with no PUID in the inspected stores. | Point-in-time offline baseline. |
| EXP-A4 | Hosts applied before first network access prevented mint through a service bounce and about 90 seconds online. | Short soak; not the current complete dual-stack/firewall gate. |
| EXP-B | Removing blocks from a never-minted image produced a first machine-hive PUID in about two minutes without MSA sign-in. | First mint, not H7 wipe-then-remint. |
| EXP-C2 | A naive LID-only wipe allowed the same HKCU PUID to return after reboot while hosts remained blocked. | Demonstrates incomplete local cleanup. |
| EXP-C3 | The expanded cleanup bundle, including Immersive Property and Token state, plus continuous hosts blocking stayed empty across reboot and about four minutes of forced-service soak. | No ablation proved Immersive Property to be the unique source. |
| EXP-D | WU COM scan returned zero pending updates, Defender signature update succeeded, prior blocked-period update history was successful, and no PUID appeared. | **Partial H5:** no controlled pending cumulative update was downloaded and installed during this experiment. |
| EXP-E | Desktop access, update scan, and Defender worked; the LiveId path was blocked. Store/Xbox/Phone Link effects were mostly inferred from blocked dependencies and package presence. | **Partial/inferred** breakage catalog; UI workflows were not exercised. |
| EXP-F | A decoy was not replaced during about six minutes unblocked; an unblocked wipe stayed empty for about five to six minutes on the exercised image. | Nuanced short result; neither eventual remint nor durable safety was proved. |
| EXP-G (in progress) | The exact rewrite completed Protect with 23 successful operations, no active/residual real-shaped PUID, and `ProtectedNoRealGdid`; the same verdict held after two reboots and service/task triggers. Three earlier attempts failed closed and exposed implementation defects that were fixed. | 24-hour, remaining transition, and full recovery matrices remain pending; FQDN keywords were configured but unhydrated under the hosts sink. |

Exact-rewrite validation is now in progress rather than untouched. Immediate Protect,
dual-stack resolution, firewall configuration, and two reboot checks passed on the
25H2 guest. The 24-hour window, remaining fail-closed/recovery matrix, and optional
MSA/UI compatibility studies remain open.

## Expected compatibility impact

- Blocking `login.live.com`, `account.live.com`, DDS, and the `wlidsvc` service path is expected to break or degrade MSA sign-in, Store and Xbox authentication, OneDrive MSA sign-in, Phone Link, CDP graph features, and related identity workflows.
- Core desktop access worked in the lab.
- Windows Update scan, Defender update, and historical blocked-period installs were observed, but a controlled pending cumulative update and feature update remain unvalidated.
- Domain, Entra, MDM, and multiple-loaded-profile systems are refused rather than assigned speculative compatibility claims.

## Repository layout

| Path | Role |
|------|------|
| [`degdid.ps1`](./degdid.ps1) | Public Status, Block, Protect, Wipe, Decoy, and Unblock entry point. |
| [`tests/degdid.Tests.ps1`](./tests/degdid.Tests.ps1) | Pure helper tests for hosts rendering, redaction, verdicts, postconditions, and preflight precedence. |
| [`tools/hunt-lid-source.ps1`](./tools/hunt-lid-source.ps1) | Research-only rehydrate mapping and registry audit helper. |

## Documentation

| Document | Contents |
|----------|----------|
| [`docs/architecture.md`](docs/architecture.md) | Mint, store, register, and emit research model. |
| [`docs/surfaces.md`](docs/surfaces.md) | Registry, service, and endpoint inventory. |
| [`docs/countermeasures.md`](docs/countermeasures.md) | Implemented controls, completion gate, evidence, and residual risk. |
| [`docs/lab-playbook.md`](docs/lab-playbook.md) | Historical evidence and remaining validation runbook. |
| [`docs/threat-model.md`](docs/threat-model.md) | Adversaries and explicit limits. |
| [`docs/experiments/`](docs/experiments/) | Per-experiment notes and observed windows. |
| [`docs/open-questions.md`](docs/open-questions.md) | Remaining research gaps. |
| [`docs/glossary.md`](docs/glossary.md) | Terms and confidence tags. |

## Safety and ethics

- Use this work for research, privacy hardening, and analysis of opaque device identity.
- It is not a guide to evade lawful process or commit crimes.
- Do not commit private machine GDIDs, device tickets, unredacted Status JSON, or machine-identifying dumps. A cited public court example is source material, not a lab secret.

## License

Licensed under the [MIT License](./LICENSE). The work is provided as-is, without warranty; you are responsible for changes made to your systems.
