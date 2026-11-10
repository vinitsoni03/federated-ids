# Run log

Only commands that were actually executed, with real outcomes.

## 2026-10-03 - Session 1 (Milestones 0-1)
Environment: Linux sandbox (not your Windows machine), Python 3.12.3, 1 CPU, 3.9 GB RAM,
no GPU. CICIoT2023 not present; no real-data run has happened.

- Inspected uploaded handoff zip (5 markdown spec files). No pre-existing code.
- `python -m venv` + `pip install -e ".[dev]"` in a clean venv: pandas 3.0.6, numpy 2.5.3,
  pytest 9.1.1. `pytest -q`: **20 passed**.
- Second clean venv with pandas 2.2.3 / numpy 2.2.6: `pytest -q`: **20 passed**.
- Mutation check: temporarily broke the variance-merge formula and the -inf counter;
  the matching tests failed in each case; code restored; 18 tests (at that time) passed.
- Ran `python -m federated_ids.data.audit tests/fixtures --check-duplicates` (exit 0)
  and a `--sample-frac 0.5 --seed 1 --chunksize 10` run.
- Defects found in that real output and fixed: text label column was flagged as
  "unparseable_non_numeric"; continuous float columns were listed as label candidates.
  Regression tests added.

Not yet verified: behavior on real CICIoT2023 files (size, speed, memory, schema,
encoding); Windows PowerShell commands (written, not executed); `git` ignore behavior on your repo.

## 2026-10-04 - Session 2 (user's local machine; run by the user, output pasted to me)
The following was reported by the user from their Windows machine, not executed by me.
Command: `python -m federated_ids.data.audit data\raw\CICIoT2023 --max-rows 100000 --output-dir results\audit\ciciot_first100k`
Reported outcome (from the pasted audit_summary.txt): 309 files, 0 parse failures, 39 columns
identical in every file, 21,159,777 rows audited, 34 top-level folders. Many files were
truncated at 100,000 rows, so per-class totals are NOT known yet. No text column; no
label column. Flagged: Rate +inf (619 rows), Std and Variance missing (461 rows each),
IAT negative (2 rows). Consistency check done by me: the Protocol Type value counts in
that summary sum to exactly 21,159,777 = rows audited.

Sandbox session (mine): fixed label heuristic (D5a), added inventory tool (D9) and tests.
`pytest -q`: 28 passed (pandas 3.0.6 and pandas 2.2.3). Mutation check on the inventory
row counter: removing the no-trailing-newline correction made the edge-case test fail.
Inventory tool has NOT been run on the real data.
