"""Run the Flower app with the Deployment Engine as REAL separate processes on this machine:
one `flower-superlink` + N `flower-supernode` processes (one per client), then `flwr run`.

    python scripts/run_flower_deployment.py --n-clients 10 --data-dir D:/federated-ids-work/flower_data/category_iid_s0         --run-config "num-server-rounds=30 run-name='flower_category_iid_fedavg_s0'"

Client data must first be exported with `python -m federated_ids.federated.export_partitions`; every
SuperNode loads only its own client_<i>.npz from --data-dir.

* Flower state/config lives in --flwr-home (FLWR_HOME), not in the user's ~/.flwr.
* Insecure (no TLS) and loopback-only (127.0.0.1): a local demonstration, not a hardened deployment.
* Runtime dependency installation (`uv sync`) is disabled; the current environment is used as is.
* All process logs go to artifacts/runs/<run-name>/flower_logs/.
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "flower_app"


SHIM = ROOT / "scripts" / "azure" / "win_shim"
ENTRY = {"flower-superlink": ("flwr.superlink.cli", "flower_superlink"),
         "flower-supernode": ("flwr.supernode.cli", "flower_supernode"),
         "flwr": ("flwr.cli.app", "app")}


def exe(env_python: Path, name: str) -> list[str]:
    """Command for a Flower console script. On Windows it runs through python.exe, because Application
    Control on the dev laptop blocks the pip-generated launcher .exe files (see win_shim/sitecustomize.py)."""
    if os.name == "nt":
        mod, fn = ENTRY[name]
        return [str(env_python), "-c", f"import sys; sys.argv[0] = {name!r}; from {mod} import {fn}; {fn}()"]
    p = env_python.parent / name
    if not p.exists():
        raise SystemExit(f"{p} not found - is flwr installed in this environment?")
    return [str(p)]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--n-clients", type=int, default=10)
    ap.add_argument("--data-dir", required=True, help="folder written by federated_ids.federated.export_partitions")
    ap.add_argument("--run-config", default="", help="flwr --run-config overrides, e.g. \"seed=1 device='cpu'\"")
    ap.add_argument("--flwr-home", default="D:/federated-ids-work/flwr_home")
    ap.add_argument("--superlink-port", type=int, default=8000)
    ap.add_argument("--supernode-base-port", type=int, default=9094)
    ap.add_argument("--startup-wait", type=float, default=8.0)
    ap.add_argument("--tls-dir", default=None, help="folder with ca.crt/server.pem/server.key (scripts/azure/make_certs.py); "
                    "omitted = insecure (loopback-only testing)")
    a = ap.parse_args()

    m = re.search(r"run-name='([^']+)'", a.run_config)
    run_name = m.group(1) if m else "flower_category_iid_fedavg_s0"
    logs = ROOT / "artifacts" / "runs" / run_name / "flower_logs"
    logs.mkdir(parents=True, exist_ok=True)
    py = Path(sys.executable)
    home = Path(a.flwr_home)
    home.mkdir(parents=True, exist_ok=True)
    tls = Path(a.tls_dir) if a.tls_dir else None
    conn = f'root-certificates = "{(tls / "ca.crt").as_posix()}"\n' if tls else "insecure = true\n"
    (home / "config.toml").write_text(
        f'[superlink.local-deployment]\naddress = "127.0.0.1:{a.superlink_port}"\n' + conn, encoding="utf-8")
    link_sec = (["--ssl-ca-certfile", str(tls / "ca.crt"), "--ssl-certfile", str(tls / "server.pem"),
                 "--ssl-keyfile", str(tls / "server.key")] if tls else ["--insecure"])
    node_sec = ["--root-certificates", str(tls / "ca.crt")] if tls else ["--insecure"]
    # Flower's SuperLink/SuperNode spawn `flower-superexec` etc. by bare name, so the environment's
    # Scripts/bin directory must be on PATH even when the venv is not activated.
    env = {**os.environ, "FLWR_HOME": str(home), "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1",
           "PATH": str(py.parent) + os.pathsep + os.environ.get("PATH", ""),
           "PYTHONPATH": os.pathsep.join([str(APP)] + ([str(SHIM)] if os.name == "nt" else [])
                                         + [os.environ.get("PYTHONPATH", "")])}

    procs: list[subprocess.Popen] = []
    t0 = time.time()
    try:
        fh = open(logs / "superlink.log", "w", encoding="utf-8")
        procs.append(subprocess.Popen([*exe(py, "flower-superlink"), *link_sec, "--host", "127.0.0.1",
                                       "--port", str(a.superlink_port), "--disable-runtime-dependency-installation"],
                                      stdout=fh, stderr=subprocess.STDOUT, env=env, cwd=ROOT))
        time.sleep(a.startup_wait)
        for i in range(a.n_clients):
            fh = open(logs / f"supernode_{i}.log", "w", encoding="utf-8")
            procs.append(subprocess.Popen([*exe(py, "flower-supernode"), *node_sec,
                                           "--superlink", f"127.0.0.1:{a.superlink_port}",
                                           "--host", "127.0.0.1", "--port", str(a.supernode_base_port + i),
                                           "--node-config",
                                           f"partition-id={i} num-partitions={a.n_clients} data-dir='{Path(a.data_dir).as_posix()}'"],
                                          stdout=fh, stderr=subprocess.STDOUT, env=env, cwd=ROOT))
        time.sleep(a.startup_wait)
        dead = [p.args[0] for p in procs if p.poll() is not None]
        if dead:
            raise SystemExit(f"processes exited during startup: {dead}; see {logs}")
        print(f"started 1 SuperLink + {a.n_clients} SuperNodes (pids {[p.pid for p in procs]}); logs in {logs}", flush=True)
        cmd = [*exe(py, "flwr"), "run", str(APP), "local-deployment", "--stream"]
        rcfg = (f"server-data-dir='{Path(a.data_dir).as_posix()}' n-clients={a.n_clients} "
                f"out-dir='{(ROOT / 'artifacts' / 'runs').as_posix()}' " + a.run_config).strip()
        cmd += ["--run-config", rcfg]
        with open(logs / "flwr_run.log", "w", encoding="utf-8") as fh:
            rc = subprocess.call(cmd, stdout=fh, stderr=subprocess.STDOUT, env=env, cwd=ROOT)
        print(f"flwr run exit {rc} after {time.time() - t0:.0f}s", flush=True)
        ok = (ROOT / "artifacts" / "runs" / run_name / "metrics.json").exists()
        print("metrics.json written" if ok else "metrics.json NOT written - check flwr_run.log / superlink.log")
        return 0 if (rc == 0 and ok) else 1
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(timeout=15)
            except subprocess.TimeoutExpired:
                p.kill()


if __name__ == "__main__":
    sys.exit(main())
