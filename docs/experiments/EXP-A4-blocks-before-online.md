# EXP-A4 - Registration blocks before first online

Date: 2026-07-11  
VM: Hyper-V Win11 lab (build 26200 / 25H2), local account, no MSA  
Checkpoint before NIC: `S1b-offline-blocked-*`
Status: **`[OBSERVED]` GDID-only short-soak result**

## Procedure

1. Confirmed offline baseline: no `LID`, TokenKeys=0 (EXP-A1).
2. Deployed scripts into guest.
3. Applied `degdid.ps1 -Block` **while NIC disconnected** (hosts file marker region).
4. Checkpoint `S1b-offline-blocked-*`.
5. Connected VM NIC to Hyper-V **Default Switch**.
6. Restarted `wlidsvc` + `CDPSvc`; soaked ~90s; inspected.

## Network checks (guest)

| Probe | Result |
|-------|--------|
| Ethernet | **Up** (NAT IP on Default Switch) |
| `example.com` HTTP | **200** (general Internet works) |
| `login.live.com` DNS | **0.0.0.0** via hosts |
| `login.live.com` HTTPS | fail / name unresolved - **blocked** |

## GDID / identity after online+blocks

| Check | Result |
|-------|--------|
| HKCU / `.DEFAULT` / SYSTEM `LID` | **HasLid=False** (all) |
| TokenKeys / DeviceIdKeys | **0** |
| `IdentityCRL` root (HKCU) | path present |
| `ExtendedProperties` | **absent** |

## LiveId Operational log (sample)

Repeated:

- `WLIDCreateContext` -> `0x800704CF` (network location unreachable)
- `UserHostAuthenticationOperation::SetupIdentity` ErrorVerifier

Interpretation: identity stack **tried** to talk, failed because DeviceAdd/login path was starved. No server PUID written.

## Tooling notes

- Hosts-file blocks are the effective control here.
- First Apply while offline created firewall rules to `0.0.0.0` (DNS followed hosts) - those rules were removed as useless; hosts retained.
- Historical follow-up at the time used explicit-resolver IP rules with job timeouts. The current hardened rewrite no longer freezes DNS answers into static IP rules; it uses dynamic FQDN objects plus a service-scoped `wlidsvc` deny.

## Verdict

**`[OBSERVED]` H2 supported for the tested short soak:** With registration hosts blocked **before** first online, general Internet worked and **no GDID/Device PUID appeared in the inspected stores** after a service bounce + ~90s. LiveId errors confirm failed provision attempts during that window.

The completion gate is GDID-only and limited to this short window. Longer soak, reboot, Store launch, and bypass resistance were not tested; DoH/hardcoded IPs could bypass hosts (firewall IP list still TODO when online).

## Next

- Optional: reboot guest under blocks; re-inspect.
- EXP control mint: restore/clone without blocks -> confirm natural mint.
- Or EXP-C path after intentional contamination.
