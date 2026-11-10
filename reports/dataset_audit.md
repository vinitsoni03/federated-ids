# Dataset audit (Milestone 2)

All numbers below come from scripts run on 2026-10-25/26 on the local copies. Machine-readable
sources are named next to each table.

## 1. CICIoT2023

**Source:** Canadian Institute for Cybersecurity, https://www.unb.ca/cic/datasets/iotdataset-2023.html;
Neto et al. (2023), *Sensors* 23(13):5941, https://doi.org/10.3390/s23135941.
**Local copy:** `data/raw/CICIoT2023/` (309 `*.pcap.csv` + `README_CSV.pdf`), extracted from
`Downloads/CSV.zip` (1,430,268,604 bytes, 345 entries). Raw files were only read, never modified.

### 1.1 Integrity and manifest
| Check | Result | Evidence |
|---|---|---|
| Files, rows, schema | 309 CSV files, **46,776,700 rows**, 39 columns, identical header in every file, 0 parse failures | `results/audit/ciciot_full_rerun_20261025/audit_report.json` |
| Reproducibility of the 2026-10-04 audit | Totals, all per-column statistics and all per-file duplicate counts **identical** (0 differences) | comparison script output, `WORK_LOG.md` 2026-10-25 |
| SHA-256 | recorded for all 309 files | same JSON (`files[].sha256`) and `D:/federated-ids-work/processed/ciciot2023/file_manifest.json` |
| Second local copy `data/raw/CSV/CSV` | 309/309 SHA-256 identical, README identical -> deleted with user approval | `file_manifest.json` (`copy_sha256_equal`) |
| Columnar copy | 309 Parquet files (zstd, values unchanged, + `file_id`, `row`), 1.6 GB on D: | `python -m federated_ids.data.ciciot convert ...` |

### 1.2 Invalid and missing values (exact, all 46,776,700 rows)
| Issue | Rows | Notes |
|---|---|---|
| `Rate` = +inf | 1,037 | present in almost every class; replaced by NaN then train-median imputed |
| Any missing value | 705 | `Std` 704, `Variance` 705, `IAT`/`Number`/`Tot size` 3, `AVG` 2, most other columns 1 |
| `IAT` < 0 | 2 | min -0.0178 s (DDoS-UDP_Flood, DoS-UDP_Flood); semantically invalid, kept (signed-log transform) |
| `Max` < `Min` | 1 | DoS-UDP_Flood |
| `Max` > 1514 bytes | 716,937 | larger than an Ethernet frame; plausible with capture offloading (TSO/GRO), kept |
| `AVG` outside [Min, Max] | 0 | |
| `Variance` != `Std`^2 (>1 %) | 0 | `Variance` is exactly redundant with `Std` in this release |
| `Tot size` != `AVG` | 0 | `Tot size` is exactly redundant with `AVG` |
| `Tot sum` != `AVG` x `Number` (>1 %) | 0 | |
| flag/protocol ratios outside [0, 1] | 0 | |
Source: `reports/data/ciciot_semantic_checks.json`. The earlier "619 +inf / 461 missing" figures
came from a first-100k-rows run, not from the full data.

### 1.3 Labels
No label column exists (contrary to `README_CSV.pdf`). Labels are taken from the folder name via an
explicit table (`src/federated_ids/data/ciciot.py: FOLDER_MAP`); an unknown folder raises an error.
* 34 folders = 33 attacks + Benign; grouped into 7 families + Benign exactly as in Neto et al. (2023):
  DDoS 12, DoS 4, Recon 5, Web 6, BruteForce 1, Spoofing 2, Mirai 3 (unit test `test_label_map_matches_paper_taxonomy`).
* **Content plausibility** (`reports/data/ciciot_label_plausibility.csv`, mean of indicator features per class):
  ICMP flood ICMP = 0.996; UDP floods UDP = 0.982-0.994; SYN floods syn_flag = 0.954-0.997;
  RSTFIN flood rst_flag = 0.996; PSHACK flood psh_flag = 0.966 & ack_flag = 0.968; HTTP floods HTTP = 0.54-0.78;
  Mirai GRE floods TCP/UDP/ICMP ~ 0 (GRE, protocol 47). The folder labels agree with the traffic.
  Benign, Recon, Spoofing, Web and BruteForce windows have very similar protocol mixes, which is
  where most classification errors occur later.
* **Caveat:** Spoofing-ARP windows have mean ARP = 0.018, i.e. mostly relayed traffic, not ARP packets.

### 1.4 Duplicates and cross-label conflicts
Exact duplicates were detected via a deterministic 64-bit hash of the 39 values
(`hash_matrix`, splitmix64 over float64 bit patterns; checked against polars `unique()` on a full file).
| Quantity | Value |
|---|---|
| Distinct feature vectors | 21,056,274 (45.0 % of rows) |
| Duplicate rows | **25,720,426 (55.0 %)**; DDoS-ICMP_Flood 72.5 % duplicates |
| Rows whose vector occurs in >1 file | 27,296,676 |
| Rows whose vector also occurs **under another class34 label** | **14,321,020 (30.6 %)** |
| ... under another 8-way category | 13,807,710 (29.5 %) |
| Largest conflicting pairs (shared vectors) | DDoS-SYN <-> DDoS-SynonymousIP 174,712; DDoS-TCP <-> DoS-TCP 174,396; DDoS-SYN <-> DoS-SYN 151,303; DDoS-UDP <-> DoS-UDP 117,099 |
Source: `reports/data/ciciot_duplicates.json`. Consequence: DDoS vs DoS of the same flood type is
partly **not separable** from these features (identical inputs, different labels), which bounds
achievable accuracy for the 8-way task.

### 1.5 Shortcut features
The paper extracts features over 100-packet windows for DDoS/DoS/Mirai and 10-packet windows for
all other scenarios. `Number` is 100 for >= 99.1 % of DDoS/DoS/Mirai rows and 10 for >= 99.9 % of the
others, so it encodes the extraction setting, not traffic. `Tot sum` (= AVG x Number) and the
`*_count` columns (max 100) also scale with the window. These six columns are excluded from the
primary feature set (`configs/data.yaml: window_dependent`); the all-39 set is kept as an ablation.

### 1.6 Row order
Rows within a file are time-ordered windows, not shuffled: the mean squared difference between
consecutive standardised rows is ~0.5x that of shuffled rows (e.g. BenignTraffic 5.03 vs 10.01,
Recon-PortScan 6.20 vs 9.98). Random row-level splitting would therefore put near-identical
neighbouring windows into train and test.

## 2. Split (Milestone 3) - `artifacts/splits/ciciot_v1/split_manifest.json`
* **File-level** split for the 17 classes with >= 3 files (whole capture files assigned to one split, seeded).
* **Contiguous-block** split (70/15/15 by row position, 0.5 % of rows purged at each boundary) for the 17 classes
  with 1-2 files (all Recon, Web, Spoofing, BruteForce, DDoS-HTTP, DDoS-SlowLoris, DoS-HTTP). *Limitation:*
  for these classes, train and test come from the same capture session, separated in time only.
* Pools: train 28,573,126 / val 9,196,777 / test 8,980,013 rows.
* Within each split: exact duplicates removed per class, then down-sampled per class
  (caps 25,000 / 5,000 / 10,000, seed 20231026). Working sets: train 664,187, val 132,923, test 253,328.
* Leakage flags: 31,011 test rows (12.2 %) have a feature vector that also occurs in the train pool;
  2,590 (1.0 %) occur there under a different category. Metrics are also reported on the "unseen" subset.
* Tests: `tests/test_ciciot_and_splits.py` (no (file,row) in two splits, no file-split file in two splits,
  block ranges disjoint, no within-split duplicates, seen-flags consistent).

## 3. GridStratLLM

**Source:** Kellerer & Hagenmeyer, KIT RADAR4KIT, DOI https://doi.org/10.35097/bx5337kcykte438h,
licence **CC BY 4.0** (`descriptive-md/dataset.desc_md.xml`); paper DOI 10.1145/3765611.3815147.
The GitHub repository https://github.com/nbke/GridStratLLM contains only an MIT `LICENSE` file
(checked 2026-10-25), so no labelling code is available.

### 3.1 Integrity
`python -m federated_ids.data.bagit_verify` streamed the 6,496,524,288-byte tar once: **all 14 payload
files match `manifest-md5.txt`**, every inner zip passed its CRC test. Extracted to
`D:\federated-ids-work\raw\GridStratLLM` (except `merged_datasets.duckdb`, verified but not extracted:
DuckDB cannot be loaded on this machine; the same tables are in the per-dataset Parquet files).
Report: `D:\federated-ids-work\raw\GridStratLLM\bagit_verification.json` (copy in `reports/gridstrat/`).

### 3.2 Contents (per sub-dataset: Parquet tables, `packets.pcap`, Zeek logs, commercial NSM events)
| Dataset | LLM (`model_name`) | Capture h | Packets | Sessions | Coordinated |
|---|---|---|---|---|---|
| 20260225_normal | - (normal operation) | 1.75 | 2,153,724 | 0 | 0 |
| 20260228_openai | openai/gpt-5.3-codex | 4.54 | 4,280,238 | 149 | 26 |
| 20260301_google | google/gemini-3.1-pro-preview | 6.14 | 7,785,175 | 54 | 13 |
| 20260301_sonnet | anthropic/claude-sonnet-4.6 | 2.55 | 1,660,791 | 69 | 62 |
| 20260302_minimax | minimax/minimax-m2.5 | 6.93 | 4,733,867 | 118 | 88 |
| 20260303_sonnet | anthropic/claude-sonnet-4.6 | 2.18 | 3,448,550 | 46 | 23 |
436 sessions in total (212 coordinated), matching the dataset record ("436 attacks with 212 coordinated").
Plan step types: `arp_mitm`, `s7_data_modification`, `modbus_data_modification`; five target states.

### 3.3 Label provenance and quality
* README: a packet is an attack-script packet iff its id appears in `attack_datamod_history.packet_id`.
  These ids exist only for records with `state = match`; e.g. in 20260228_openai only 152,515 of
  355,274 records (43 %) link to a captured packet (others `pending` / `no_match`). **Packet labels
  are an incomplete lower bound** and are not used for training.
* Attack-labelled packets are S7 (TCP/102) traffic between the PLC/PCS IPs, relayed by the attack
  workers' MAC addresses (ARP MITM). A detector using MAC/IP identities would learn this testbed's
  attacker hosts; identity values are therefore excluded from features.
* Session activity intervals come from `attack_exec_steps` (first/last `exec_ts`; median 51 s per
  session in 20260228_openai; every session has steps).
* **Commercial NSM timestamps could not be aligned** with the capture clock: in every dataset the
  first NSM event is ~72-73 min after the first packet, the best-overlapping offset differs between
  datasets (-1 h to 0 h), and NSM events sometimes extend past the end of the capture. NSM detection
  rates are therefore **not** reported. Zeek logs use capture epoch timestamps and are used instead.
