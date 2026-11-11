"""Run the federated experiment grids sequentially (resumable: finished runs are skipped).

    python scripts/run_fl_grid.py [--tasks category class34 binary] GRID [GRID ...]
Every grid is run once per task; run names are prefixed with the task, e.g.
fl_binary_iid_fedavg_s0. Use the interpreter of the environment that should run them
(e.g. D:/federated-ids-work/venv-cuda/Scripts/python.exe for the GPU).

    python scripts/run_fl_grid.py m5        # clean FL: partitions x {FedAvg, FedProx} x 3 seeds
    python scripts/run_fl_grid.py m5_mu     # FedProx mu sensitivity (Dirichlet 0.1, seed 0)
    python scripts/run_fl_grid.py m6        # poisoning x aggregators x partitions (seed 0)
    python scripts/run_fl_grid.py m6_frac   # malicious-fraction sweep
    python scripts/run_fl_grid.py m6_seeds  # headline poisoning cells, seeds 1 and 2
    python scripts/run_fl_grid.py wp4       # v2 MLP (centralized_v2 config per task): partitions x FedAvg x 3 seeds
    python scripts/run_fl_grid.py wp4_real  # v2 MLP realism: 50 % participation / 20 clients / 2 local epochs
Runs are written to artifacts/runs/<name>/; a per-run log goes to artifacts/runs/<name>/log.txt.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable
PARTS = {"iid": ["--partition", "iid"], "dir1.0": ["--partition", "dirichlet", "--alpha", "1.0"],
         "dir0.1": ["--partition", "dirichlet", "--alpha", "0.1"]}
ALGOS = {"fedavg": ["--algorithm", "fedavg"], "fedprox": ["--algorithm", "fedprox", "--mu", "0.01"]}
AGGS = ["fedavg", "median", "trimmed_mean", "norm_clip"]
ATTACKS = {"clean": [], "signflip": ["--attack", "sign_flip", "--malicious-fraction", "0.2", "--scale", "5"],
           "targeted": ["--attack", "label_flip_boost", "--malicious-fraction", "0.2", "--targets", "DDoS"]}


def grid(name: str) -> list[tuple[str, list[str]]]:
    runs = []
    if name == "m5":
        for seed in (0, 1, 2):
            for p, pa in PARTS.items():
                for al, aa in ALGOS.items():
                    runs.append((f"fl_{p}_{al}_s{seed}", pa + aa + ["--seed", str(seed)]))
    elif name == "m5_mu":
        for mu in ("0.001", "0.1", "1.0"):
            runs.append((f"fl_dir0.1_fedprox_mu{mu}_s0", PARTS["dir0.1"] + ["--algorithm", "fedprox", "--mu", mu,
                                                                            "--seed", "0"]))
    elif name == "m5_r60":
        runs.append(("fl_iid_fedavg_r60_s0", PARTS["iid"] + ALGOS["fedavg"] + ["--rounds", "60", "--seed", "0"]))
        for seed in (0, 1, 2):
            runs.append((f"fl_dir0.1_fedavg_r60_s{seed}", PARTS["dir0.1"] + ALGOS["fedavg"]
                         + ["--rounds", "60", "--seed", str(seed)]))
    elif name == "m6":
        for p in ("iid", "dir1.0"):
            for att, aa in ATTACKS.items():
                for agg in AGGS:
                    runs.append((f"poison_{p}_{att}_{agg}_s0", PARTS[p] + aa + ["--aggregator", agg, "--seed", "0"]))
    elif name == "m6_frac":
        for att in ("signflip", "targeted"):
            for frac in ("0.1", "0.3"):
                for agg in ("fedavg", "trimmed_mean", "median"):
                    aa = [x if x != "0.2" else frac for x in ATTACKS[att]]
                    runs.append((f"poison_iid_{att}_f{frac}_{agg}_s0", PARTS["iid"] + aa + ["--aggregator", agg,
                                                                                         "--seed", "0"]))
    elif name == "m6_seeds":
        for seed in (1, 2):
            for att in ("clean", "signflip", "targeted"):
                for agg in ("fedavg", "trimmed_mean", "median", "norm_clip"):
                    runs.append((f"poison_iid_{att}_{agg}_s{seed}", PARTS["iid"] + ATTACKS[att]
                                 + ["--aggregator", agg, "--seed", str(seed)]))
    elif name == "wp4":
        for seed in (0, 1, 2):
            for p, pa in PARTS.items():
                runs.append((f"fl_v2_{p}_fedavg_s{seed}", pa + ALGOS["fedavg"] + ["--seed", str(seed)]))
    elif name == "wp4_real":
        for p in ("iid", "dir1.0"):
            for v, va in REALISM.items():
                runs.append((f"fl_v2_{p}_fedavg_{v}_s0", PARTS[p] + ALGOS["fedavg"] + va + ["--seed", "0"]))
    else:
        raise SystemExit(f"unknown grid {name}")
    return runs


REALISM = {"part0.5": ["--participation", "0.5"], "c20": ["--n-clients", "20"], "le2": ["--local-epochs", "2"]}
TASKS = ("category", "class34", "binary")


def v2_model_args(task: str) -> list[str]:
    """Architecture/lr of the frozen centralized v2 MLP (WP3) for this task."""
    m = json.loads((ROOT / "artifacts" / "runs" / "centralized_v2" / task / "config.json").read_text(encoding="utf-8"))["mlp"]
    return ["--hidden", *map(str, m["hidden"]), "--dropout", str(m["dropout"]), "--lr", str(m["lr"])]
DEVICE = os.environ.get("FIDS_DEVICE", "cuda")


def main() -> int:
    argv = sys.argv[1:]
    tasks = list(TASKS)
    if argv and argv[0] == "--tasks":
        argv = argv[1:]
        tasks = []
        while argv and argv[0] in TASKS:
            tasks.append(argv.pop(0))
    jobs = []
    for g in argv:
        for task in tasks:
            for run_name, args in grid(g):
                prefix, rest = run_name.split("_", 1)  # fl_iid_... -> fl_<task>_iid_...
                extra = v2_model_args(task) if g.startswith("wp4") else []
                jobs.append((f"{prefix}_{task}_{rest}", args + extra + ["--task", task]))
    print(f"{len(jobs)} runs planned", flush=True)
    for run_name, args in jobs:
        out = ROOT / "artifacts" / "runs" / run_name
        if (out / "metrics.json").exists():
            print(f"skip {run_name} (done)", flush=True)
            continue
        out.mkdir(parents=True, exist_ok=True)
        t = time.time()
        cmd = [PY, "-m", "federated_ids.federated.simulation", "--run-name", run_name, "--device", DEVICE] + args
        with open(out / "log.txt", "w", encoding="utf-8") as fh:
            fh.write(" ".join(cmd[1:]) + "\n")
            fh.flush()
            rc = subprocess.call(cmd, cwd=ROOT, stdout=fh, stderr=subprocess.STDOUT)
        print(f"{run_name}: exit {rc} in {time.time() - t:.0f}s", flush=True)
        if rc:
            return rc
    return 0


if __name__ == "__main__":
    sys.exit(main())
