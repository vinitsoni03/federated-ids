# Milestone Tracker

Student: Vinit Soni (E23CSEU0437)
Project: AI-Enabled Cyberattack Detection and Adversarially Robust Federated Intrusion Detection
Last updated: 2026-11-11 (final submission Fri 2026-11-13: report, slides, GitHub, live demo)

Statuses: `Not started` / `In progress` / `Blocked` / `Done (verified)`. "Done (verified)" means the
command/tests ran successfully and the evidence file exists; code alone never counts.

| ID | Milestone | Status | Evidence (command -> output) |
|---|---|---|---|
| M0 | Workspace / environment / dataset inventory | Done (verified) | `reports/initial_state.md`; datasets present: CICIoT2023, GridStratLLM; absent: CIC-IDS2017, UNSW-NB15 |
| M1 | Phase-1 problem definition & positioning | Done (verified) - student marked Phase 1 complete on 2026-10-26; Phase 2 plan in `PHASE2_PLAN.md` | `reports/phase1_review.md`; corrected copy `Downloads/Phase1_Rev2_20261026/03_*.docx`; 4 references verified online. Pending: student accepts/rejects proposed RQ and reference additions; supervisor approval not available |
| M2 | Dataset inventory & audit | Done (verified) | `results/audit/ciciot_full_rerun_20261025/` (exact, SHA-256, identical to 2026-10-04 run); `reports/data/ciciot_{duplicates,semantic_checks}.json`, `ciciot_label_plausibility.csv`; `reports/gridstrat/bagit_verification.json` (14/14 MD5); `reports/dataset_audit.md` |
| M3 | Preprocessing & leakage-aware splits | Done (verified) | `python -m federated_ids.data.splits` -> `artifacts/splits/ciciot_v1/split_manifest.json`; train-only `Preprocessor` (JSON per run); `pytest -q` 47 passed incl. leakage tests on the real split; mutation checks (purge gap, dedup) caught |
| M4 | Centralized baseline | Done (verified) - 3 tasks on GPU | `artifacts/runs/centralized_{category,class34,binary}_window_invariant/` (MLP x3 seeds + RF, val/test/unseen/full pool) + `centralized_category_all39`; `reports/tables/m4_*.csv`. Calibrated operating points: done in WP3 |
| M5 | Federated learning (Centralized vs FedAvg vs FedProx; IID/non-IID) | Done (verified) | Simulator: 63 runs x 3 tasks, `reports/tables/m5_federated.csv`, `m5_convergence_*.png`. Flower: local 10-SuperNode run matches simulator (`artifacts/runs/flower_memtest_10c/`); hybrid Azure+laptop run, 30 rounds, TLS - `artifacts/runs/flower_azure_hybrid_category_iid_s0/` (test macro-F1 0.6692 = simulator s0 0.6692); report §5.4. 60-round convergence check (WP1, planned, run 2026-11-11): `m5_r60` grid |
| M6 | Model-update poisoning & mitigation | Done (verified) | 180 runs x 3 tasks (all exit 0), `reports/tables/m6_poisoning.csv`, `reports/figures/m6_poisoning_*.png`; unit tests for attack activation/aggregators pass |
| M7 | Inference-time evasion | Done (verified) - 3 tasks on GPU | `artifacts/runs/evasion_centralized_*_window_invariant/metrics.json` (0 constraint violations, re-queried); `reports/tables/m7_*.csv`, `m7_evasion_*.png`. Fixed-FPR comparison (WP5) still open |
| M8 | GridStratLLM analysis | Done (verified) | `python -m federated_ids.gridstrat.analysis ...` -> `reports/gridstrat/{inventory,results}.json`; `reports/tables/m8_*.csv`, `reports/figures/m8_gridstrat_auc.png` |
| WP3 | Improve centralized detector (search, calibration, two-stage, HGB, freeze v2) | Done (verified) | Search 72 + re-check 18 runs; `wp3_detectors` (val); `wp3_freeze` one-time test eval -> `artifacts/runs/centralized_v2/`, `reports/tables/wp3_test_operating_points.csv`. Frozen: v2 MLP (h256-128, sqrt-inverse) + HGB; two-stage = negative result |
| WP5 | Adversarial training vs evasion (fixed FPR) | Done (verified) | `python -m federated_ids.experiments.wp5_advtrain` exit 0 (resumed 2026-11-10, done 23:37); 36 evals, 0 constraint violations in 108 attacked evaluations -> `reports/tables/wp5_evasion.csv`, `wp5_advtrain_summary.csv`, `wp5_advtrain_per_family_fpr1.csv`, `reports/figures/wp5_advtrain_evasion.png`; report §7.1 |
| WP6 | GridStratLLM without the ARP signature (core) | Done (verified) | `python -m federated_ids.gridstrat.wp6_no_arp --root ...` (45 s, M8 volume folds reproduced exactly) -> `reports/gridstrat/wp6_results.json`, `reports/tables/wp6_gridstrat_no_arp.csv`, `reports/figures/wp6_gridstrat_no_arp_auc.png`; report §8.1. Sensitivity (window/guard) = future work (student: core only) |
| WP4 | Federated with v2 + realism checks | Done (verified) | 45 runs exit 0; `python -m federated_ids.experiments.wp4_eval` -> `reports/tables/wp4_federated.csv` (72 runs at calibrated 5 %/1 % FPR, comm, rounds to 95 %) |
| M9 | Final report, demo & reproducibility | Done (verified) | Report complete incl. §11 conclusion, §5/§5.3 re-checked against tables -> `final_report.{md,docx,pdf}`; 13-slide deck `final_slides.{pptx,pdf}` (validated + visually QA'd); fresh venv on D: from `requirements-lock.txt` -> **63 passed** (2026-11-11); repo public, tag **v1.0.0** + GitHub release with both PDFs. Remaining before Fri: demo rehearsal (start Azure VMs `fids-server`/`fids-clients`, currently deallocated) |

## Open items / blockers
* Waiting for the student: (1) laptop sleep restored to 10 min on 2026-11-01 (done); (2) WP3 search size - decided 2026-11-01: full grid.
* Not done (out of scope or infeasible here, documented): commercial-NSM detection rates (clock not
  alignable), replay of evasion perturbations through the CIC feature extractor, differential privacy /
  secure aggregation, WP6 window/guard-band sensitivity (student: core only).
* Azure endpoint (`serving/`, planned as Azure's second role): **Done (verified) 2026-11-11** - Docker container
  on `fids-server`, serving the Flower-trained model; `tunnel_endpoint.sh` smoke test passed (health 200, no key
  401, key 200, 400 test windows served == offline 1.0000). Student approved adding <redacted>/32 to the NSG
  rule `allow-ssh-operator` (port 443 only; the two earlier ISP IPs kept).
* After the final demo (plan): delete `fids-rg`. Budget alert `fids-budget` is 10 INR/month, not $10.
