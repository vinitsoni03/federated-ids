# Technical decisions

## D1. Audit streams files in chunks and never concatenates them
Full CICIoT2023 will not fit comfortably in RAM on a laptop. Per-column statistics are
mergeable (counts, Welford/Chan mean and variance, min/max, capped distinct-value counts),
so memory stays bounded by chunk size. Alternatives: load a sample with pandas only (loses
exact counts), or use Polars/DuckDB (extra dependency, not needed yet).

## D2. Three scan modes with explicit exactness flags
`full` (exact), `first_n_rows`, `random_fraction`. Every file report carries
`counts_exact_for_file`; the summary prints a mode banner. A file prefix can be biased if
files are ordered by time or class, so prefix mode is for quick looks only. Random mode
is seeded per (seed, file index, chunk index), so it is reproducible only for the same
`--chunksize`.

## D3. Audit reports; it does not clean
No value is dropped, stripped or replaced. Header names are kept verbatim (a leading
space in a name is flagged, not fixed). Decisions on inf/NaN/negative handling belong in
Milestone 2 and will be made after the real audit.

## D4. Invalid numeric values
Every column is passed through `pd.to_numeric(errors="coerce")`. Missing = NaN/empty.
"Non-numeric" = present but not a number (e.g. "abc"). Text such as "Infinity" parses to
+inf and is counted as inf. Non-numeric counts are not flagged for pure text columns.

## D5. Label-column candidates are a heuristic
Eligible: 2-100 distinct values and text-valued or integer-valued. Score: text +3,
label-like name (label/class/attack/target/category) +2, last column +1, no missing +1. Integer count columns and 0/1 flags can
still appear as low-ranked candidates. The human must confirm the target after viewing the
real schema; nothing downstream may hard-code a guess.

## D6. Duplicate detection is opt-in and per file
`--check-duplicates` hashes rows with `pandas.util.hash_pandas_object` (64-bit) and counts
repeats within one file's audited rows. It does not find cross-file duplicates (needed
later for train/test leakage checks) and may undercount if a column's inferred dtype
differs between chunks. In sampled modes it describes the sample only.

## D7. Dependencies
Only numpy and pandas (+ pytest for dev). `requirements.txt` is `-e .[dev]`; ranges live in
`pyproject.toml`. Torch/scikit-learn/Flower are deliberately not installed until needed.

## D8. Fixture
`tests/fixtures/mini_flows_{a,b}.csv`: 40 + 20 synthetic rows with generic flow-like
column names (not CICIoT2023 columns). Planted issues are listed in the `tests/test_audit.py`
docstring; test expectations come from that construction. The fixture says nothing about
the real dataset.

## D5a. Label heuristic revised after the first real audit (2026-10-04)
The local copy has no text column, and the old hint word "type" ranked the feature
`Protocol Type` (IP protocol numbers) as the top label candidate. "type" was removed from
the hints, and the report now prints a warning when no text-valued candidate exists.

## D9. Class label may live in the folder name, not in a column (UNCONFIRMED)
The local copy is laid out as one folder per class (34 folders = 33 attack types + Benign)
with `*.pcap.csv` files and no label column. This is a hypothesis about the layout, not a
decision. `data/inventory.py` reports exact rows per folder so we can see the class
distribution. Decision pending: how to derive labels, and how to split train/test so
rows from the same capture file do not appear on both sides (file-level or time-aware
splitting vs row-level splitting). Not decided until provenance and file structure are
confirmed.
