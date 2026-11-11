"""The Windows launch helper starts Flower commands through python.exe instead of the blocked launcher .exe files."""
import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SHIM = ROOT / "scripts" / "azure" / "win_shim"
pytest.importorskip("flwr")


def _env():
    return {**os.environ, "PYTHONPATH": os.pathsep.join([str(SHIM), os.environ.get("PYTHONPATH", "")])}


@pytest.mark.parametrize("name", ["flower-superexec", "flwr-clientapp", "flwr-serverapp"])
def test_shim_runs_commands_flower_starts_by_name(name):
    code = (f"import subprocess, sys; p = subprocess.Popen([{name!r}, '--help'], stdout=subprocess.PIPE, "
            "stderr=subprocess.STDOUT); out = p.communicate(timeout=120)[0]; sys.stdout.buffer.write(out); "
            "sys.exit(p.returncode)")
    r = subprocess.run([sys.executable, "-c", code], env=_env(), capture_output=True, timeout=180)
    assert r.returncode == 0, r.stdout.decode(errors="replace")[-500:]
    assert b"usage" in r.stdout.lower()


@pytest.mark.parametrize("name", ["flower-superlink", "flower-supernode", "flwr"])
def test_deployment_script_launches_console_scripts(name):
    spec = importlib.util.spec_from_file_location("run_flower_deployment", ROOT / "scripts" / "run_flower_deployment.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    r = subprocess.run([*mod.exe(Path(sys.executable), name), "--help"], capture_output=True, timeout=180)
    assert r.returncode == 0, r.stdout.decode(errors="replace")[-500:]
    assert b"usage" in r.stdout.lower()
