# EXP-D — Windows Update under registration blocks

Date: 2026-07-11  
State: expanded wipe empty LID + hosts registration blocks (`EXP-C3` clean)

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
| WU search | **Works** — `SearchResultCount=0` (image already current) |
| Defender `Update-MpSignature` | **OK** under blocks |
| WU history (same day) | Result=2 success for CU **KB5094126**, .NET **KB5087051**, Defender platform/intel, MSRT — includes installs from earlier blocked period (`EXP-C2` step 0) |
| Post LID | Still **empty** (scan + Defender update did not mint) |

## Verdict

**H5 PASS (practical):** Windows Update / Defender servicing paths work with DeviceAdd/DDS hosts blocked. No GDID mint from update activity in this run. Feature-update (enablement package) not attempted (optional long disposable snap).

## Notes

- `Resolve-DnsName download.windowsupdate.com` returned empty in one probe; COM search and history still succeeded — do not treat that DNS quirk as WU failure.
- Lab activation was already `LicenseStatus=5` (notification) — unrelated to this D run.
