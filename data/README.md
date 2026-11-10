# Data

Raw data is never committed (see `.gitignore`) and never modified. Large derived files live
outside the repository in the work directory (`configs/data.yaml: work_dir`, default
`D:/federated-ids-work`, override with env `FIDS_WORK_DIR`), because C: has little free space.

## Datasets in scope

| Dataset | Use | Raw location | Integrity record |
|---|---|---|---|
| CICIoT2023 (CSV, per-attack folders, 309 files, 39 features, no label column) | Conventional IoT IDS: centralized, federated, poisoning, evasion | `data/raw/CICIoT2023/` (from `Downloads/CSV.zip`) | SHA-256 per file: `reports/data/ciciot_file_manifest.json`; exact audit: `results/audit/ciciot_full_rerun_20261025/` |
| GridStratLLM (BagIt, DOI 10.35097/bx5337kcykte438h, CC BY 4.0) | Separate analysis of LLM-coordinated smart-grid attacks | `Downloads/10.35097-bx5337kcykte438h.tar` -> extracted to `D:/federated-ids-work/raw/GridStratLLM/` | MD5 of all 14 payload files OK: `reports/gridstrat/bagit_verification.json` |

Not present and not in scope: CIC-IDS2017, UNSW-NB15 (see `reports/initial_state.md`).
The two datasets are never merged: different domains (IoT flow windows vs. smart-grid
S7/Modbus HIL captures), feature spaces and label semantics.

## Obtaining the data

* CICIoT2023: request/download from https://www.unb.ca/cic/datasets/iotdataset-2023.html (accept
  CIC's terms), take the `CSV` folder (one sub-folder per attack, `*.pcap.csv`), and place it so that
  `data/raw/CICIoT2023/<Attack>/<file>.pcap.csv` exists. Cite Neto et al. (2023), doi:10.3390/s23135941.
* GridStratLLM: download the bag from https://doi.org/10.35097/bx5337kcykte438h. Cite the dataset DOI
  and Kellerer & Hagenmeyer, doi:10.1145/3765611.3815147.

## Derived data (all regenerable)

```
python -m federated_ids.data.audit data/raw/CICIoT2023 --check-duplicates --checksum --output-dir results/audit/ciciot_full_rerun_20261025
python -m federated_ids.data.ciciot convert data/raw/CICIoT2023 --work-dir D:/federated-ids-work
python -m federated_ids.data.ciciot_checks --work-dir D:/federated-ids-work --output-dir reports/data
python -m federated_ids.data.splits                       # fixed holdout split ciciot_v1
python -m federated_ids.data.bagit_verify Downloads/10.35097-bx5337kcykte438h.tar --dest D:/federated-ids-work/raw/GridStratLLM --extract --skip-extract data/dataset/merged_datasets.duckdb --unzip
```

| Path (under work_dir) | Content | Size |
|---|---|---|
| `processed/ciciot2023/parquet/NNN.parquet` | one Parquet per CSV, values unchanged + `file_id`, `row` | 1.6 GB |
| `processed/ciciot2023/row_hash.npy`, `row_file_id.npy`, `row_index.npy` | 64-bit row hash per row (duplicate analysis) | ~650 MB |
| `processed/ciciot2023/file_manifest.json` | files, labels, rows, bytes, SHA-256 | small |
| `splits/ciciot_v1/{train,val,test}.npz` | sampled working sets (raw features + labels + leakage flags) | ~400 MB |
| `splits/ciciot_v1/test_pool_idx.npy` | global row ids of the full test pool | 70 MB |
| `raw/GridStratLLM/...` | verified, extracted bag | 6.3 GB |

The split manifest (which file/rows went to which split, seeds, per-class counts) is small and
lives in the repository: `artifacts/splits/ciciot_v1/split_manifest.json`.

## Labels

* CICIoT2023: label = folder name, mapped by an explicit table to 34 classes and 8 categories
  (Benign + 7 attack families of Neto et al., 2023). Validation: `reports/dataset_audit.md` §1.3.
* GridStratLLM: attack-session activity intervals from `attack_exec_steps.parquet`; session metadata
  from `attack_session_llm.parquet`. Packet-level labels (`attack_datamod_history.packet_id`) are
  incomplete and only reported. See `reports/dataset_audit.md` §3.3.
