# EXP-A4 - Registration blocks before first online

Date: 2026-07-11  
VM: Hyper-V Win11 lab (build 26200 / 25H2), local account, no MSA  
Checkpoint before NIC: `S1b-offline-blocked-*`

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
- Follow-up: block path resolves via an explicit DNS server (e.g. `Resolve-DnsName -Server 1.1.1.1`) **before** relying on hosts, when adding IP firewall rules (implemented with job timeouts in `degdid.ps1`).

## Verdict

**`[OBSERVED]` H2 PASS (short soak):** With registration hosts blocked **before** first online, general Internet works and **no GDID/Device PUID is minted** after service bounce + ~90s. LiveId errors confirm failed provision attempts.

Caveats: longer soak / reboot / Store launch not yet tested; DoH/hardcoded IPs could bypass hosts (firewall IP list still TODO when online).

## Next

- Optional: reboot guest under blocks; re-inspect.
- EXP control mint: restore/clone without blocks -> confirm natural mint.
- Or EXP-C path after intentional contamination.
