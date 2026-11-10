# Initial state of the project (audit of 2026-10-25)

Snapshot taken **before** any change in the 2026-10-25 session. Every statement below was
checked against local files or command output on the user's machine. Later work is recorded in
`WORK_LOG.md` and `MILESTONE_TRACKER.md`.

## 1. Workspace

| Item | Finding |
|---|---|
| Project root | `C:\Users\06ven\Downloads\federated-ids` (not a Git repository; `git status` not applicable) |
| Code | `src/federated_ids/data/audit.py` (533 lines, streaming CSV audit) and `inventory.py` (120 lines, per-folder row counts). No model, split, federated, attack or GridStratLLM code. |
| Tests | `tests/test_audit.py`, `tests/test_inventory.py` + synthetic fixtures; `pytest -q` -> **28 passed** (re-run 2026-10-25) |
| Docs | `README.md` (status "Milestones 0-1 only"), `docs/docs/DECISIONS.md`, `docs/docs/RUN_LOG.md` |
| Existing results | `results/audit/ciciot_full/` (exact full audit, created 2026-10-04 11:55 UTC) and `results/audit/ciciot_inventory/` (row inventory). No metrics, models or checkpoints anywhere. |
| Empty scaffolding | `data/data/{raw,processed}/.gitkeep`, `results/results/{audit,metrics,plots}/.gitkeep` (doubly nested, unused) |
| Handoff docs | `Claude_Project_Handoff.zip` (= `Downloads/Claude_Project_Handoff (1).zip`, byte-identical): `CLAUDE_HANDOFF.md`, `MILESTONE_TRACKER.md`, `DATASET_REGISTER.md`, `WORK_LOG.md` |
| Phase-1 documents | `Downloads/Phase1_Final_Verified/` (3 DOCX + form text + verification report + README, 16 Oct). Older, different-size drafts of the three DOCX files also sit directly in `Downloads/` (12:47, 16 Oct). |
| Methods paper | `Downloads/2601.05022v1.pdf` (Knowledge-to-Data preprint, arXiv 2601.05022) |

## 2. Environment and hardware

| Item | Value |
|---|---|
| OS | Windows 11 Home 10.0.26200 |
| CPU | AMD Ryzen 5 5600H, 6 cores / 12 threads |
| RAM | 15.3 GB total, ~4.6-8.8 GB free during the session |
| GPU | NVIDIA RTX 3050 Laptop, 4 GB, CUDA driver 13.3; **not used** (CPU PyTorch wheel installed because C: had too little space for CUDA wheels; the MLP is small) |
| Disk | **C: 3.3 GB free at start** (fell to 1.0 GB); D: 80.9 GB free; E: 14.1 GB free |
| Python | venv `.venv`, Python 3.14.6; numpy 2.5.3, pandas 3.0.6, pytest 9.1.1 only |
| Constraint | Windows Application Control blocks some native DLLs: `pyarrow._parquet` and `duckdb` fail to import. `polars` 2.1.0 works and is used for Parquet I/O. |

## 3. Datasets found locally (identified from contents, not names)

| Dataset | Location | Evidence | Status |
|---|---|---|---|
| **CICIoT2023** (CSV, per-attack layout) | `federated-ids/data/raw/CICIoT2023/` (309 CSV + `README_CSV.pdf`, 8.4 GB); source archive `Downloads/CSV.zip` (1.43 GB, 345 entries) | 34 folders named after the 33 attacks + Benign of Neto et al. (2023); CIC `README_CSV.pdf` | **Present** |
| CICIoT2023 duplicate | `federated-ids/data/raw/CSV/CSV/` (8.4 GB) | SHA-256 identical to the copy above for all 309 CSVs and the README | Duplicate; **deleted with the user's approval** on 2026-10-25 to free C: |
| **GridStratLLM** | `Downloads/10.35097-bx5337kcykte438h.tar` (6.50 GB, BagIt bag of DOI 10.35097/bx5337kcykte438h) | `bag-info.txt` External-Identifier `bx5337kcykte438h`; `dataset/README.md` names GridStratLLM; licence CC BY 4.0 in `descriptive-md` | **Present** (not extracted at start) |
| CIC-IDS2017 | - | No file or folder matching CIC-IDS2017 names (`MachineLearningCVE`, `GeneratedLabelledFlows`, `*ids2017*`) on C:\Users\06ven\Downloads, D: or E: (depth 4) | **Not present** |
| UNSW-NB15 | - | No `*unsw*` / `*nb15*` file on the same drives | **Not present** |

Conclusion: the two downloaded datasets are **CICIoT2023 and GridStratLLM**. Neither legacy candidate
(CIC-IDS2017, UNSW-NB15) is on disk; both are outside the approved scope (handoff: "do not add them
to active scope without evidence"), so their absence blocks nothing. Knowledge-to-Data (arXiv
2601.05022) is a methods paper, present as PDF, not a dataset.

### Provenance discrepancy (CICIoT2023)
The bundled `README_CSV.pdf` says the 309 CSVs are "a combined and shuffled dataset" with a
`label` feature. The local files have **no label column**, are organised one folder per attack,
and are **not shuffled** (consecutive rows are about 2x more similar than shuffled pairs; see
`reports/dataset_audit.md`). The 39 columns also differ from the 46-47 features in the paper's
Table 4 (no `ts`, `flow_duration`, `Srate`, `Drate`, `urg_count`, `Magnitue`, `Radius`,
`Covariance`, `Weight`; `Duration` appears as `Time_To_Live`; `IGMP` added). Zip timestamps are
2024-07 to 2024-10, consistent with a later CIC re-release of the CSVs. Labels are therefore
derived from folder names (validated in `reports/dataset_audit.md`).

## 4. Completed vs. incomplete work at the start

| Milestone | Status at start | Evidence |
|---|---|---|
| M0 workspace audit | Not done | - |
| M1 Phase-1 proposal | Documents drafted (16 Oct), verified at source-metadata level only | `Phase1_Final_Verified/05_Verification_Report.txt` |
| M2 dataset audit | Partly done: exact full CICIoT2023 audit + row inventory existed (2026-10-04); no cross-file / cross-label duplicate analysis, no label validation, GridStratLLM not inspected | `results/audit/ciciot_full/`, `results/audit/ciciot_inventory/` |
| M3-M9 | Not started (no code, no results) | - |

Note: `docs/docs/RUN_LOG.md` quotes anomaly counts (619 +inf Rate, 461 missing) from a
*first-100k-rows* run. The exact full-data counts are different (1,037 +inf Rate; 704/705 missing
Std/Variance); see `reports/dataset_audit.md`.

## 5. Main blockers identified

1. **Disk space on C:** (3.3 GB -> 1.0 GB free). Resolved: large intermediates go to
   `D:\federated-ids-work` (config `configs/data.yaml`, env `FIDS_WORK_DIR`); duplicate dataset
   copy removed with approval (C: back to 8.4 GB free).
2. **Blocked native libraries** (pyarrow Parquet, DuckDB). Resolved by using polars; the
   GridStratLLM `merged_datasets.duckdb` (4.5 GB) cannot be opened locally, but the same tables
   (except raw packet BLOBs) are in the per-dataset Parquet files, which are used instead.
3. No label column in CICIoT2023; labels must be derived from folder names and validated.

## 6. Next three actions (as planned at the time of the audit)

1. Re-run the CICIoT2023 audit with checksums; add cross-file and cross-label duplicate analysis
   and label-plausibility checks; verify/extract GridStratLLM against its MD5 manifest.
2. Build a leakage-aware, file/time-aware split with train-only preprocessing, and tests.
3. Train and evaluate the centralized baseline; then start the federated simulation.
