# Experiments index

Per-run notes from the Win11 25H2 lab. **Do not commit real GDIDs, tickets, hostnames, or raw inspect dumps.**

Public how-to: root [`README.md`](../../README.md), [`docs/usage.md`](../usage.md),
and [`degdid.ps1`](../../degdid.ps1).

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
| [EXP-F](./EXP-F-unblock-remint.md) | Observed + later direct control | Original short window did not remint; EXP-G later proved Protect/wipe -> Unblock -> rebooted remint -> reprotect |
| [EXP-G](./EXP-G-pending-closure-hardening-matrix.md) | **PASS beyond 33h + lifecycle controls** | Current Protect held after a fresh mint and repeated triggers; same-timeline Unblock produced a rebooted remint in 22 seconds, then reprotect held after reboot |
| [EXP-H](./EXP-H-msa-local-rehydrate.md) | **PASS at 18h** | Current Protect on the MSA-connected profile held through sign-out/in, sleep/resume, reboot, and 18 hours; prior user-credential and machine-state return windows were exceeded |
