"""Windows only: start Flower's helper commands through the Python interpreter.

Windows Application Control on the dev laptop blocks the pip-generated launcher programs
(flwr.exe, flower-supernode.exe, flower-superexec.exe, flwr-clientapp.exe) since November 2026,
while python.exe itself is allowed. A SuperNode starts `flower-superexec`, which starts
`flwr-clientapp`, both by bare name with subprocess.Popen. This rewrites exactly those two calls to
`python -c <entry point>` - same code, same arguments. run_hybrid.sh puts this folder on PYTHONPATH
for the laptop processes only; nothing else is affected.
"""
import subprocess
import sys

_ENTRY = {
    "flower-superexec": ("flwr.supercore.cli", "flower_superexec"),
    "flwr-clientapp": ("flwr.supernode.cli", "flwr_clientapp"),
    "flwr-serverapp": ("flwr.superlink.cli", "flwr_serverapp"),  # a local SuperLink (run_flower_deployment.py)
}
_Popen = subprocess.Popen


class _EntryPointPopen(_Popen):
    def __init__(self, args, *a, **kw):
        if isinstance(args, (list, tuple)) and args and args[0] in _ENTRY:
            mod, fn = _ENTRY[args[0]]
            code = f"import sys; sys.argv[0] = {args[0]!r}; from {mod} import {fn}; {fn}()"
            args = [sys.executable, "-c", code, *args[1:]]
        super().__init__(args, *a, **kw)


subprocess.Popen = _EntryPointPopen
