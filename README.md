# AI-Enabled Cyberattack Detection and Adversarially Robust Federated Intrusion Detection

Final-year research project - Vinit Soni (E23CSEU0437).

An offline, reproducible research pipeline with four **separate** studies:

| | Study | Data | Code | Report |
|---|---|---|---|---|
| A | Centralized vs. federated IDS (FedAvg, FedProx; IID / Dirichlet non-IID) | CICIoT2023 | `experiments/centralized.py`, `federated/` | `reports/final_report.md` §4-5 |
| B | Federated model-update poisoning + robust aggregation | CICIoT2023 | `attacks/poisoning.py`, `federated/aggregators.py` | §6 |
| C | Constrained black-box inference-time evasion | CICIoT2023 | `attacks/evasion.py`, `experiments/evasion_exp.py` | §7 |
| D | LLM-coordinated smart-grid attacks, leave-one-LLM-out detection | GridStratLLM | `gridstrat/analysis.py` | §8 |

Threat models: `reports/threat_models.md`. Status of every milestone: `MILESTONE_TRACKER.md`.
Datasets: `data/README.md`.

**Written deliverables** (each `.md` source has a `.docx` and `.pdf` build):

| Document | Source | Build |
|---|---|---|
| Final report (every number traced to a table; results matrix, confusion matrices, comparison with published work) | `reports/final_report.md` | `python scripts/build_docs.py reports/final_report.md` |
| Literature review, with a detailed comparison against the closest published studies | `reports/literature_review.md` | `python scripts/build_docs.py reports/literature_review.md` |
| Research paper (IEEE conference, LaTeX) | `paper/main.tex`, `paper/refs.bib` | Overleaf (pdfLaTeX + BibTeX) |

Figures for these documents: `python scripts/make_doc_figures.py`.

Nothing here attacks a real system: all attacks are simulated on recorded data.
Federated learning here gives **no formal privacy guarantee**; no differential privacy or secure
aggregation is implemented.

## Setup (Windows PowerShell; tested on Python 3.14.6, CPU only)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements-lock.txt --extra-index-url https://download.pytorch.org/whl/cpu
pip install -e . --no-deps               # the package itself, versions from the lock
pytest -q                                # 69 tests
```
`requirements-lock.txt` pins the exact versions every result was produced with (verified in a fresh
venv on 2026-11-11). `pip install -r requirements.txt` (= `-e .[dev]`, latest versions) also works
but is not what the results were run on. Large intermediates go to `configs/data.yaml: work_dir`
(default `D:/federated-ids-work`; override with `$env:FIDS_WORK_DIR`).
On machines where Windows Application Control blocks unsigned DLLs, `pyarrow.parquet` and `duckdb`
may fail to import; the code only needs `polars` for Parquet.

## Live demo dashboard

```powershell
powershell -ExecutionPolicy Bypass -File scripts\run_demo.ps1   # opens http://127.0.0.1:8000
```
Runs locally from `demo/bundle/` (built by `python scripts/build_demo_bundle.py`; committed, so no dataset is
needed): the 8-class v2 MLP before and after adversarial training, its validation thresholds, 320 real test
windows (40 per class) and the recorded Flower run. Tabs: **Detect** (probabilities, attack score vs. calibrated
threshold, scan of all windows), **Evasion attack** (the constrained black-box attacker of §7, query by query, and
frozen vs. hardened on all 280 attack windows), **Federated training** (replay of the Azure + laptop Flower run),
**Results** (read live from `reports/tables/`). Binds to localhost only; the secured API endpoint is `serving/app.py`.

## Real-traffic test

Score your own capture (Wireshark/Npcap `.pcapng` or `.pcap`) with the same two models (report §4.2):
```powershell
python -m federated_ids.live.score D:\federated-ids-work\captures\my_capture.pcapng   # -> <work_dir>\live\my_capture\
python scripts\live_analysis.py "laptop=D:\federated-ids-work\live\my_capture\features.csv"   # -> reports\tables\live_*.csv
```
The capture is cut into the dataset's 10-packet windows and turned into the CICIoT2023 features
(`src/federated_ids/live/`, pure Python, no extra packages). Keep captures out of the repository: they contain
addresses and visited hosts. Capture only traffic you own.

## Reproduce everything (in order)

```powershell
# M2 - audits and integrity (raw data is only read)
python -m federated_ids.data.audit data\raw\CICIoT2023 --check-duplicates --checksum --output-dir results\audit\ciciot_full_rerun_20261025
python -m federated_ids.data.ciciot convert data\raw\CICIoT2023 --work-dir D:/federated-ids-work
python -m federated_ids.data.ciciot_checks --work-dir D:/federated-ids-work --output-dir reports\data
python -m federated_ids.data.bagit_verify $HOME\Downloads\10.35097-bx5337kcykte438h.tar --dest D:/federated-ids-work/raw/GridStratLLM --extract --skip-extract data/dataset/merged_datasets.duckdb --unzip
# M3 - fixed holdout split (seeded; manifest -> artifacts\splits\ciciot_v1)
python -m federated_ids.data.splits
# M4 - centralized baselines (~10 min)
python -m federated_ids.experiments.centralized
python -m federated_ids.experiments.centralized --feature-set all39 --seeds 0
python -m federated_ids.experiments.centralized --task class34 --seeds 0 --no-full-test
# M8 - GridStratLLM (~5 min)
python -m federated_ids.gridstrat.analysis --root D:/federated-ids-work/raw/GridStratLLM/10.35097-bx5337kcykte438h/data/dataset/unzipped --output-dir reports\gridstrat
# M7 - evasion (~2 min)
python -m federated_ids.experiments.evasion_exp
# M5/M6 - federated grids (~3.5 min per run, 73 runs; resumable)
python scripts\run_fl_grid.py m5 m5_mu m6 m6_frac m6_seeds
# M9 - all tables and figures from the artifacts above
python scripts\make_figures.py
```
A single FL run, e.g.:
`python -m federated_ids.federated.simulation --partition dirichlet --alpha 0.1 --algorithm fedprox --mu 0.01 --seed 0 --run-name my_run`

## Layout

```
configs/            data.yaml, centralized.yaml, federated.yaml
src/federated_ids/
  data/             audit, inventory, ciciot (labels/convert/hash), ciciot_checks, splits, preprocess, dataset, bagit_verify
  models/mlp.py     MLP + local training (FedProx term) + param helpers
  federated/        partition (IID/Dirichlet), aggregators (fedavg/median/trimmed_mean/norm_clip), simulation
  attacks/          poisoning (sign-flip, label-flip+boost), evasion (constrained black-box)
  evaluation/       metrics, full_test (whole test pool)
  experiments/      centralized, evasion_exp, common
  gridstrat/        analysis (GridStratLLM)
scripts/            run_fl_grid.py, make_figures.py
tests/              unit + leakage tests
artifacts/splits/   split manifest;  artifacts/runs/<run>/  configs, metrics, histories, models
reports/            initial_state, dataset_audit, threat_models, phase1_review, final_report,
                    literature_review, data/, gridstrat/, tables/, figures/
paper/              IEEE conference paper (main.tex, refs.bib, figures/)
results/audit/      CICIoT2023 audits (2026-10-04 and rerun 2026-10-25)
docs/docs/          earlier decisions and run log (sessions 1-2)
```

## Citations
Neto et al. (2023), CICIoT2023, *Sensors* 23(13):5941, doi:10.3390/s23135941.
Kellerer & Hagenmeyer (2026), GridStratLLM dataset, doi:10.35097/bx5337kcykte438h (CC BY 4.0);
paper doi:10.1145/3765611.3815147. Method references: `reports/final_report.md` §References.
