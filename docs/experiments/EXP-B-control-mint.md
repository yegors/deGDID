# EXP-B - Control mint after unblocking registration

Date: 2026-07-11  
VM: same lab guest as EXP-A4 (local account, no MSA)  
Prior state: online with hosts/firewall blocks -> no `LID`  
Checkpoint before unblock: `S2-blocked-online-nomint-*`  
Checkpoint after mint: `S3-control-minted-*`
Status: **`[OBSERVED]` first-chance mint control**

## Procedure

1. Inspect while still blocked -> no `LID` (confirm A4 hold).
2. `degdid.ps1 -Unblock`.
3. Confirm `login.live.com` resolves and HTTPS returns (status 200).
4. Restart `wlidsvc` + `CDPSvc`.
5. Soak ~120s; inspect.

## Results

| Store | Before unblock | After ~2 min |
|-------|----------------|--------------|
| HKCU `ExtendedProperties\LID` | absent | **still absent** |
| `.DEFAULT` `LID` | absent | **present** `0018...` (16 hex) |
| SYSTEM `S-1-5-18` `LID` | absent | **present** `0018...` |
| `.DEFAULT` vs SYSTEM | - | **SameValue=True** |
| HKCU TokenKeys | 0 | 0 |

LiveId log flipped from repeated `0x800704CF` errors (while blocked) to Information events `6115/6116/6117` after unblock (DeviceAdd-class activity; see Autopilot literature for 6115).

## Verdict

**`[OBSERVED]` First-chance mint control:** Removing registration blocks from this blocked-never-minted, online local-account image was followed by a **server-assigned device PUID** (`0018` class) appearing in **SYSTEM and `.DEFAULT`** within ~2 minutes - without MSA sign-in and without HKCU `LID` yet.

### Implications

1. The same image minted promptly after the A4 blocks were lifted, supporting the blocks as the relevant control.
2. **Anonymous / local-account mint is real** - no MSA required for machine-level Device PUID.
3. **Inspect must check SYSTEM / `.DEFAULT`**, not only HKCU - user hive can lag or stay empty on local accounts.
4. Contaminated image now available at `S3-control-minted-*` for EXP-C (local-only rotate).

This is a first-chance mint control. The image had not previously minted and then been wiped, so EXP-B is **not** evidence of wipe-remint behavior.

## Redacted dump

Full PUID not committed.
