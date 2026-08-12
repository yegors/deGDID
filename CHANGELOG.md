# Changelog

Newest entries go on top. Existing entries are never edited or removed — a later
correction is recorded as its own dated entry.

## 2026-08-12

### Fixed

- **Protect no longer crashes the shared `svchost.exe` host on machines with 16 GB
  of RAM or less.** Where physical RAM is below `SvcHostSplitThresholdInKB`
  (16 GB by default), Windows does not split services into per-service processes, so
  `wlidsvc` and `TokenBroker` share one `svchost.exe -k netsvcs -p` process with
  `Schedule` (Task Scheduler) and `Winmgmt` (WMI). Force-stopping a co-hosted
  identity service could fail-fast that host — `svchost.exe` faulting in
  `combase.dll` with `0xC0000602` — taking Task Scheduler and WMI down with it. The
  credential helper runs as a scheduled task and the `ScheduledTasks` cmdlets go
  through CIM, so Protect was destroying the services it depends on and then failing
  with `Credential helper produced no result. LastTaskResult=3221225786`.

  `Get-GdidServiceHostConflict` now maps every service Protect intends to stop to its
  host process and aborts with exit code `5` before anything is stopped when one of
  them shares that process with `Schedule` or `Winmgmt`. The error names the conflict
  and the `SvcHostSplitThresholdInKB` remedy.

- **A failed quiesced inventory no longer leaves `wlidsvc` disabled.** Nothing has
  been written to an identity store at that point, so the run is now a clean abort
  that calls `Resume-GdidServices` and restores the original start types. Previously
  it returned with services stopped and `wlidsvc` still on the temporary `Disabled`
  start type — which persists across reboots and silently breaks Microsoft Account
  sign-in — without staging a fail-closed barrier.

- **The credential helper survives a Task Scheduler restart.** `Invoke-CredentialTask`
  waits for the `Schedule` service before registering its task and retries once when
  the task produces no output. A helper that ran and reported its own errors is still
  never retried. Task result codes are decoded, so `0xC000013A` is now reported as a
  terminated helper process rather than a bare integer.

### Added

- Any service left on the temporary `Disabled` start type is now named in the run
  output along with the exact `Set-Service` command that restores it. Fail-closed
  exits keep their security posture; they just stop being silent about it.
- Twelve tests covering host-conflict detection, the Protect preflight, the quiesced
  inventory rollback, task result decoding, and the disabled-service report.

### Documentation

- `README.md` — added the service-host requirement to the eligibility list and
  described the preflight and service-restoration behavior under Protect.
- `docs/usage.md` — added the requirement bullet, a `Shared svchost refusal` section
  with the threshold remedy, a `Service state after a failed run` section, and
  widened the exit code `5` description to include service-host preconditions.

## Earlier

Changes before 2026-08-12 are recorded in git history rather than in this file, which
starts here. Notable recent work:

- 2026-08-08 — credential task registration when a SID resolves to a bare name (#15),
  Unblock completing without dynamic-keyword cmdlets (#12), battery-safe
  credential-helper task settings (#4), and PR #7 resolution (#20).
- 2026-07-30 — identity-service snapshot scoped to the named services, with its
  classification extracted and covered by tests.
- 2026-07-16 — documentation refresh across README, architecture, countermeasures,
  and the lab playbook for the EXP-G and EXP-H results.
- 2026-07-15 — deprecated parameters removed and managed hosts region handling
  clarified, with Unblock refusing noncanonical hosts state.
