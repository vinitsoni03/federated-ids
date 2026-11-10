#!/usr/bin/env bash
# Phase 2 pipeline on the GPU environment (sequential so timings are not distorted).
# Usage: bash scripts/run_phase2_gpu.sh   (from the repository root)
set -u
PY=${PY:-D:/federated-ids-work/venv-cuda/Scripts/python.exe}
LOG=${LOG:-D:/federated-ids-work/tmp/phase2}
mkdir -p "$LOG"
export PYTHONIOENCODING=utf-8
for task in category class34 binary; do
  "$PY" -m federated_ids.experiments.centralized --task "$task" --device cuda > "$LOG/central_$task.log" 2>&1
  echo "central_$task=$?"
done
"$PY" -m federated_ids.experiments.centralized --task category --feature-set all39 --seeds 0 --device cuda > "$LOG/central_all39.log" 2>&1
echo "central_all39=$?"
for task in category class34 binary; do
  "$PY" -m federated_ids.experiments.evasion_exp --baseline-run "centralized_${task}_window_invariant" > "$LOG/evasion_$task.log" 2>&1
  echo "evasion_$task=$?"
done
"$PY" scripts/run_fl_grid.py --tasks category class34 binary m5 m5_mu m6 m6_frac m6_seeds > "$LOG/fl_grid.log" 2>&1
echo "fl_grid=$?"
