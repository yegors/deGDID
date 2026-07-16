# Open Questions

Last updated: 2026-07-16

This file contains only unresolved questions with a concrete decision or experiment.
Completed evidence belongs in `docs/experiments/`; broad speculation is not a
backlog.

The GDID-only gate is complete for the measured unmanaged, single-user Windows 11
25H2/build-26200 scope. None of the research questions below blocks that result.

## 1. Build portability — product decision

**Question:** Does the current gate behave correctly on Windows 10 22H2/build 19045
and a representative non-26200 Windows 11 build?

**Why it matters:** those builds are accepted by the mutation contract but currently
receive warnings because only build 26200 has complete lifecycle evidence.

**Closure:** either run the same block, natural-mint, Protect, reboot, and
postcondition matrix on those builds, or narrow the accepted build contract to the
validated line.

## 2. Anonymous DeviceAdd wire response — high-value research

**Question:** What request and response fields does the current local-account
DeviceAdd flow actually use, including the returned `GlobalDeviceID`, `DevicePUID`,
or `HWPUIDFlipped` field?

**Why it matters:** EXP-B proves the mint outcome and static analysis identifies
candidate XML paths, but neither is a current wire capture.

**Closure:** capture ETW plus a sanitized SOAP request/response from a disposable
local-account VM. Keep credentials, tickets, hardware identifiers, and full PUIDs
out of the repository.

## 3. GDID emission / court channel — high-value research

**Question:** Which Windows component and network channel produced the
court-reported GDID association with URL, time, and IP data?

**Why it matters:** this is the largest unresolved link between local GDID state and
the reported server-side record. The public record does not identify the process,
endpoint, or payload.

**Closure:** use process-correlated ETW and packet capture around controlled browsing
and Windows background activity. Do not attribute the channel to Edge, SmartScreen,
DiagTrack, CDP, Delivery Optimization, or another component without direct evidence.

## 4. Delivery Optimization wire behavior — focused research

**Question:** Do Windows Delivery Optimization download or reporting requests carry
GDID directly, or is GDID only present in the documented `UCDOStatus` compliance
snapshot?

**Why it matters:** the public schema proves that `GlobalDeviceId` exists in a
reporting snapshot, not that it appears in download headers or payloads.

**Closure:** capture a controlled DO transfer and reporting cycle with
process-correlated network evidence.

## 5. Servicing under the gate — optional compatibility

**Question:** Can a known pending cumulative update download, install, reboot, and
complete while the GDID gate remains healthy?

**Why it matters:** update scans, Defender updates, and prior blocked-period history
passed, but no controlled pending cumulative update was installed during EXP-D.

**Closure:** run one pending cumulative update on a disposable protected VM and
record the KB, result, reboot, final gate health, and local GDID inventory.

Everything else is either answered, outside the GDID-only scope, not practically
testable with available evidence, or too low-value to remain an active question.
