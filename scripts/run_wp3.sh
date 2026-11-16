#!/usr/bin/env bash
# WP3 after the seed-0 grid search: seed re-check of the top-3 configs per task (seeds 1, 2), then
# calibrated operating points for every detector (validation only; test is never loaded).
# Usage: bash scripts/run_wp3.sh   (from the repository root; resumable - finished runs are skipped)
set -u
PY=${PY:-D:/federated-ids-work/venv-cuda/Scripts/python.exe}
LOG=${LOG:-D:/federated-ids-work/tmp/wp3}
mkdir -p "$LOG"
export PYTHONIOENCODING=utf-8
# step 1: rerun the 3 best settings per task with seeds 1 and 2
"$PY" -m federated_ids.experiments.hparam_search --top-k 3 --seeds 1 2 > "$LOG/recheck.log" 2>&1
echo "recheck=$?"
# step 2: score all candidate detectors on validation at the three decision rules
"$PY" -m federated_ids.experiments.wp3_detectors > "$LOG/detectors.log" 2>&1
echo "detectors=$?"
