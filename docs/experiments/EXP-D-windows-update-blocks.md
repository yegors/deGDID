# EXP-D — Windows Update under registration blocks

Date: 2026-07-11  
State: expanded wipe empty LID + hosts registration blocks (`EXP-C3` clean)
Status: **`[OBSERVED]` H5 partial - zero-pending scan + Defender + history; no controlled pending CU**

## Protocol

1. Confirm blocks + all LID paths empty  
2. WU COM search for pending software updates  
3. `Update-MpSignature` (Defender) under blocks  
4. Review WU history; re-inspect LID  

## Results

| Check | Result |
|-------|--------|
| Hosts block | Present (`login.live.com` → `0.0.0.0`) |
| Pre LID | HKCU / `.DEFAULT` / SYSTEM **empty** |
| WU search | **Completed** — `SearchResultCount=0` (image already current; no pending CU exercised) |
| Defender `Update-MpSignature` | **OK** under blocks |
| WU history (same day) | Result=2 success for CU **KB5094126**, .NET **KB5087051**, Defender platform/intel, MSRT — includes installs from earlier blocked period (`EXP-C2` step 0) |
| Post LID | Still **empty** (scan + Defender update did not mint) |

## Verdict

**H5 PARTIAL:** The Windows Update COM scan completed but found zero pending updates, Defender signature update succeeded, and WU history contained successful installs from the earlier blocked period. No GDID appeared during the scan + Defender observation window.

This run did **not** perform a controlled pending cumulative-update download/install, so it does not close full Windows Update servicing compatibility. A pending CU remains optional in the closure matrix; a feature update (enablement package) was not attempted.

## Notes

- `Resolve-DnsName download.windowsupdate.com` returned empty in one probe; COM search and history still succeeded — do not treat that DNS quirk as WU failure.
- Lab activation was already `LicenseStatus=5` (notification) — unrelated to this D run.
