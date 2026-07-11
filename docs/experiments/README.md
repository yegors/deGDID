# Experiments index

Per-run notes from the Win11 25H2 lab. **Do not commit real GDIDs, tickets, hostnames, or raw inspect dumps.**

Public how-to: root [`README.md`](../../README.md) and [`degdid.ps1`](../../degdid.ps1).

| ID | Summary |
|----|---------|
| [EXP-A1](./EXP-A1-offline-baseline.md) | Offline local OOBE -> no GDID |
| [EXP-A4](./EXP-A4-blocks-before-online.md) | Hosts blocks before first online -> no mint (short soak) |
| [EXP-B](./EXP-B-control-mint.md) | Unblock -> SYSTEM/`.DEFAULT` mint (~2 min); no MSA |
| [EXP-C](./EXP-C-local-wipe-blocks.md) | Machine-hive wipe + blocks -> stayed empty |
| [EXP-C2](./EXP-C2-continuity-drill.md) | HKCU mint continuity; naÃ¯ve wipe rehydrates |
| [EXP-C3](./EXP-C3-hkcu-rehydrate-source.md) | Immersive Property is rehydrate store; expanded wipe works |
| [EXP-D](./EXP-D-windows-update-blocks.md) | WU/Defender under blocks; LID stays empty |
| [EXP-E](./EXP-E-breakage-catalog.md) | Breakage: desktop/WU OK; MSA path broken (expected) |
| [EXP-F](./EXP-F-unblock-remint.md) | Decoy sticky short-term; eager remint = EXP-B |
