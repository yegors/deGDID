# Experiments index

Per-run notes from the Win11 25H2 lab. **Do not commit real GDIDs, tickets, hostnames, or raw inspect dumps.**

Public how-to: root [`README.md`](../../README.md) and [`degdid.ps1`](../../degdid.ps1).

These notes use a **GDID-only completion gate**: a run may close only the local GDID/LID behavior it directly inspected. It does not close long-duration durability, bypass resistance, UI compatibility, servicing compatibility, or enforcement hardening unless that path was actually exercised. The pending closure work is designed in [EXP-G](./EXP-G-pending-closure-hardening-matrix.md).

| ID | Evidence label | Summary |
|----|----------------|---------|
| [EXP-A1](./EXP-A1-offline-baseline.md) | Observed baseline | Offline local OOBE; no GDID in inspected stores |
| [EXP-A4](./EXP-A4-blocks-before-online.md) | Observed - short soak | Blocks before first online; no mint during ~90-second window |
| [EXP-B](./EXP-B-control-mint.md) | Observed - first-chance mint control | Unblock of never-minted image -> SYSTEM/`.DEFAULT` mint (~2 min); no MSA |
| [EXP-C](./EXP-C-local-wipe-blocks.md) | Observed - continuous-block short window | Machine-hive-only contamination; wipe stayed empty through tested reboot/window |
| [EXP-C2](./EXP-C2-continuity-drill.md) | Observed negative result | HKCU continuity; naïve LID-only wipe rehydrated |
| [EXP-C3](./EXP-C3-hkcu-rehydrate-source.md) | Observed bundle - short window; ablation pending | Expanded bundle stayed empty under continuous blocks; Immersive Property remains required/high-confidence |
| [EXP-D](./EXP-D-windows-update-blocks.md) | **H5 partial** | Zero-pending WU scan + Defender + history; no controlled pending CU |
| [EXP-E](./EXP-E-breakage-catalog.md) | **Partial / inferred** | Named UI paths were not exercised |
| [EXP-F](./EXP-F-unblock-remint.md) | Observed - short window | Decoy/wipe unblock behavior; **wipe-remint not proven**; EXP-B is first-chance mint only |
| [EXP-G](./EXP-G-pending-closure-hardening-matrix.md) | **Failed at ~7h; fix pending rerun** | Machine PUID rehydrated locally from SYSTEM/`.DEFAULT` Property and Token stores despite healthy network blocks; three-hive wipe added |
| [EXP-H](./EXP-H-msa-local-rehydrate.md) | **Observed field failure; fix pending rerun** | MSA profile restored the same user LID locally under healthy blocks; targeted MSA device-credential cleanup added |
