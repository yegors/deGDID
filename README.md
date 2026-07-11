# degdid

Research and practical countermeasures for Microsoft's **Global Device Identifier (GDID)** — a server-assigned install fingerprint Windows can carry even on a local account with no Microsoft account signed in.

This repo documents how GDID is minted and stored, what we validated in a Windows 11 lab, and ships **one elevated PowerShell script** you can run to inspect, wipe or decoy the local id, and block registration endpoints that mint a new one.

## What GDID is

- A **64-bit Device PUID**, often shown as `g:<decimal>` (local registry form is usually a hex string starting with `0018...`).
- Minted by talking to Microsoft identity infrastructure (notably `login.live.com` DeviceAdd), then kept in **IdentityCRL** registry state (HKCU / SYSTEM / `.DEFAULT`), with extra copies in Immersive Property blobs and device tickets.
- Used as a durable *install* identifier in Microsoft's device/telemetry ecosystem (including Delivery Optimization's `GlobalDeviceId` surface). It is **not** simply your hardware serial hashed locally — a clean reinstall typically gets a **new** GDID, but Microsoft may still receive hardware material at mint time.

Court reporting in 2026 described GDID being used to associate browsing activity with an install. See `docs/` for sources and confidence tags.

## What this does *not* do

- Erase Microsoft's **server-side history** of an old GDID.
- Stop all Windows telemetry (DiagTrack and other planes remain).
- Guarantee anonymity, VPN magic, or "undetectable" browsing.
- Keep Microsoft account / Store sign-in / Phone Link / CDP graph features happy — those are the intentional tradeoff when registration is blocked.

## Lab testing (summary)

Validated on a Hyper-V **Windows 11 25H2** (build 26200) local-account VM. Details live under [`docs/experiments/`](docs/experiments/).

| Result | Evidence |
|--------|----------|
| Offline OOBE -> no GDID | EXP-A1 |
| Block DeviceAdd/DDS hosts **before** first online -> no mint (short soak) | EXP-A4 |
| Unblock -> anonymous machine mint into SYSTEM/`.DEFAULT` (~2 min), no MSA | EXP-B |
| Naive LID-only wipe fails once HKCU is contaminated (local rehydrate) | EXP-C2 |
| Expanded wipe (incl. Immersive `Property\<LID>`) + **continuous** blocks -> stays empty | EXP-C3 |
| Windows Update / Defender servicing under blocks; no mint from that activity | EXP-D |
| Desktop usable; MSA/LiveId path broken as expected under blocks | EXP-E |
| Decoy/wipe without blocks != instant remint; eager remint still real (see EXP-B) | EXP-F |

## Quick start (end users)

1. Clone or download this repo.
2. Open **PowerShell as Administrator**.
3. Allow the script once if needed:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
cd path\to\degdid
```

4. See whether you already have a local GDID:

```powershell
.\degdid.ps1 -Status
```

5. **Recommended one-shot** — block registration endpoints, then wipe local GDID state:

```powershell
.\degdid.ps1 -Protect
```

Or block, then install a **local decoy** id (random `0018...`, not server-issued):

```powershell
.\degdid.ps1 -Protect -UseDecoy
```

6. Confirm:

```powershell
.\degdid.ps1 -Status
```

### Other actions

| Command | Meaning |
|---------|---------|
| `.\degdid.ps1 -Block` | Only apply hosts + firewall registration blocks |
| `.\degdid.ps1 -Unblock` | Remove those blocks (may allow a future real mint) |
| `.\degdid.ps1 -Wipe` | Expanded local wipe only (warns if online without blocks) |
| `.\degdid.ps1 -Decoy` | Local decoy only (same warning) |
| `.\degdid.ps1 -DryRun ...` | Print planned changes without writing |

**Order matters:** always block *before* wiping while online. A hosts gap can allow a fresh server mint.

### Expected breakage after `-Protect`

- Microsoft account sign-in, Store auth, Xbox/MSA, Phone Link / CDP sync: **expect broken or degraded**
- Local desktop, non-MSA browsing, Windows Update: **intended to keep working** (lab-validated for CU/Defender-class servicing; feature-update not exercised)

## Tools layout

| Path | Role |
|------|------|
| [`degdid.ps1`](./degdid.ps1) | **Public entry point** — status / protect / wipe / decoy / block |
| [`tools/hunt-lid-source.ps1`](./tools/hunt-lid-source.ps1) | Research-only LID rehydrate hunter / registry audit |

## Documentation

| Doc | Contents |
|-----|----------|
| [`docs/architecture.md`](docs/architecture.md) | Mint -> store -> register -> emit pipeline |
| [`docs/surfaces.md`](docs/surfaces.md) | Registry, services, endpoints |
| [`docs/countermeasures.md`](docs/countermeasures.md) | Prevent / block / local wipe matrix + lab tags |
| [`docs/threat-model.md`](docs/threat-model.md) | Adversaries and honest limits |
| [`docs/experiments/`](docs/experiments/) | Per-experiment notes |
| [`docs/open-questions.md`](docs/open-questions.md) | Remaining research gaps |
| [`docs/lab-playbook.md`](docs/lab-playbook.md) | How the lab matrix was run |
| [`docs/glossary.md`](docs/glossary.md) | Terms + confidence tags |

## Safety / ethics

- For research, privacy hardening, and understanding opaque device tracking.
- **Not** a guide to evade lawful process or commit crimes.
- Do not commit real GDIDs, tickets, or machine-identifying inspect dumps.

## License

Research notes and scripts are provided as-is, without warranty. You are responsible for changes you make to your systems.
