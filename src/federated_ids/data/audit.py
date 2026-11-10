"""Streaming CSV audit: schema, dtypes, missing/invalid values, label candidates.

The audit reads each file in chunks and never concatenates files. It does not
modify or clean data; it only reports what is there.

Exactness of counts is recorded per file:
  mode "full"           - every row audited; counts are exact for the file.
  mode "first_n_rows"   - only the first N rows; exact only if the file had <= N rows.
  mode "random_fraction"- seeded Bernoulli sample of rows; counts describe the sample.
The file is still scanned completely in this mode, so its total row count is exact.

Usage:
    python -m federated_ids.data.audit PATH [PATH ...] [--max-rows N | --sample-frac F]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

AUDIT_VERSION = "0.1.0"
DISTINCT_CAP = 1000  # stop tracking distinct values of a column beyond this many
MAX_LABEL_CLASSES = 100  # a label candidate may have at most this many classes
LABEL_NAME_HINTS = ("label", "class", "attack", "target", "category")


@dataclass
class ColumnStats:
    """Mergeable streaming statistics for one column."""

    name: str
    position: int
    rows: int = 0
    missing: int = 0
    dtypes: Counter = field(default_factory=Counter)  # dtype name -> number of chunks
    numeric_parseable: int = 0  # non-missing values readable as numbers (incl. +-inf)
    unparseable: int = 0  # non-missing values that are NOT numbers (e.g. "abc")
    pos_inf: int = 0
    neg_inf: int = 0
    negative: int = 0  # finite values < 0
    n_finite: int = 0
    mean: float = 0.0
    m2: float = 0.0  # sum of squared deviations (Welford/Chan)
    min: float | None = None
    max: float | None = None
    distinct: dict | None = field(default_factory=dict)  # value -> count; None if over cap

    def update(self, s: pd.Series) -> None:
        self.rows += len(s)
        self.dtypes[str(s.dtype)] += 1
        notna = s.notna().to_numpy()
        self.missing += int((~notna).sum())

        arr = pd.to_numeric(s, errors="coerce").to_numpy(dtype="float64", na_value=np.nan)
        is_nan = np.isnan(arr)
        self.numeric_parseable += int((~is_nan).sum())
        self.unparseable += int((notna & is_nan).sum())
        self.pos_inf += int(np.isposinf(arr).sum())
        self.neg_inf += int(np.isneginf(arr).sum())

        finite = arr[np.isfinite(arr)]
        if finite.size:
            self.negative += int((finite < 0).sum())
            mean = float(finite.mean())
            m2 = float(((finite - mean) ** 2).sum())
            self._merge_moments(finite.size, mean, m2)
            self._merge_range(float(finite.min()), float(finite.max()))

        if self.distinct is not None:
            vc = s.value_counts(dropna=True)
            if len(vc) > DISTINCT_CAP:
                self.distinct = None
            else:
                for k, v in vc.items():
                    self.distinct[k] = self.distinct.get(k, 0) + int(v)
                if len(self.distinct) > DISTINCT_CAP:
                    self.distinct = None

    def _merge_moments(self, n: int, mean: float, m2: float) -> None:
        total = self.n_finite + n
        delta = mean - self.mean
        self.m2 += m2 + delta * delta * self.n_finite * n / total
        self.mean += delta * n / total
        self.n_finite = total

    def _merge_range(self, lo: float, hi: float) -> None:
        self.min = lo if self.min is None else min(self.min, lo)
        self.max = hi if self.max is None else max(self.max, hi)

    def merge(self, other: ColumnStats) -> None:
        self.rows += other.rows
        self.missing += other.missing
        self.dtypes.update(other.dtypes)
        self.numeric_parseable += other.numeric_parseable
        self.unparseable += other.unparseable
        self.pos_inf += other.pos_inf
        self.neg_inf += other.neg_inf
        self.negative += other.negative
        if other.n_finite:
            self._merge_moments(other.n_finite, other.mean, other.m2)
            self._merge_range(other.min, other.max)
        if self.distinct is None or other.distinct is None:
            self.distinct = None
        else:
            for k, v in other.distinct.items():
                self.distinct[k] = self.distinct.get(k, 0) + v
            if len(self.distinct) > DISTINCT_CAP:
                self.distinct = None

    @property
    def kind(self) -> str:
        non_missing = self.rows - self.missing
        if non_missing == 0:
            return "empty"
        if self.numeric_parseable == 0:
            return "text"
        if self.unparseable > 0:
            return "mixed_numeric_and_text"
        text_dtype = any(not _is_numeric_dtype_name(d) for d in self.dtypes)
        return "numeric_stored_as_text" if text_dtype else "numeric"

    @property
    def is_constant(self) -> bool:
        return self.distinct is not None and len(self.distinct) == 1

    def to_dict(self) -> dict:
        std = float(np.sqrt(self.m2 / self.n_finite)) if self.n_finite else None
        return {
            "name": self.name,
            "position": self.position,
            "kind": self.kind,
            "dtypes_seen": dict(self.dtypes),
            "rows": self.rows,
            "missing": self.missing,
            "unparseable_non_numeric": self.unparseable,
            "pos_inf": self.pos_inf,
            "neg_inf": self.neg_inf,
            "negative_finite": self.negative,
            "n_finite": self.n_finite,
            "min": self.min,
            "max": self.max,
            "mean": self.mean if self.n_finite else None,
            "std_population": std,
            "n_distinct": None if self.distinct is None else len(self.distinct),
            "distinct_tracking_overflow": self.distinct is None,
            "is_constant": self.is_constant,
        }


def _is_numeric_dtype_name(name: str) -> bool:
    return name.startswith(("int", "uint", "float", "bool", "Int", "UInt", "Float"))


@dataclass
class AuditOptions:
    chunksize: int = 100_000
    max_rows: int | None = None
    sample_frac: float | None = None
    seed: int = 0
    check_duplicates: bool = False
    checksum: bool = False

    def __post_init__(self) -> None:
        if self.max_rows is not None and self.sample_frac is not None:
            raise ValueError("Use either max_rows or sample_frac, not both.")
        if self.max_rows is not None and self.max_rows <= 0:
            raise ValueError("max_rows must be positive.")
        if self.sample_frac is not None and not 0 < self.sample_frac <= 1:
            raise ValueError("sample_frac must be in (0, 1].")
        if self.chunksize <= 0:
            raise ValueError("chunksize must be positive.")

    @property
    def mode(self) -> str:
        if self.max_rows is not None:
            return "first_n_rows"
        if self.sample_frac is not None and self.sample_frac < 1:
            return "random_fraction"
        return "full"


def discover_csv_files(paths: list[str | Path]) -> list[Path]:
    """Expand files and directories (recursively) into a sorted, de-duplicated CSV list."""
    found: dict[Path, None] = {}
    for p in map(Path, paths):
        if p.is_dir():
            for f in sorted(p.rglob("*")):
                if f.is_file() and f.suffix.lower() == ".csv":
                    found[f] = None
        elif p.is_file():
            found[p] = None
        else:
            raise FileNotFoundError(f"Path does not exist: {p}")
    if not found:
        raise FileNotFoundError("No CSV files found in the given paths.")
    return list(found)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def audit_file(path: Path, file_index: int, opts: AuditOptions) -> tuple[dict, dict[str, ColumnStats]]:
    """Audit one CSV in chunks. Returns (file report, per-column stats)."""
    info: dict = {"path": str(path), "size_bytes": path.stat().st_size, "error": None}
    if opts.checksum:
        info["sha256"] = _sha256(path)

    stats: dict[str, ColumnStats] = {}
    header: list[str] = []
    rows_audited = 0
    rows_seen = 0
    truncated = False
    hashes: list[np.ndarray] = []

    try:
        with pd.read_csv(path, chunksize=opts.chunksize) as reader:
            for chunk_idx, chunk in enumerate(reader):
                if not header:
                    header = [str(c) for c in chunk.columns]
                    for pos, col in enumerate(chunk.columns):
                        stats[col] = ColumnStats(str(col), pos)
                rows_seen += len(chunk)

                if opts.max_rows is not None:
                    remaining = opts.max_rows - rows_audited
                    if remaining <= 0:  # another chunk exists beyond the limit
                        truncated = True
                        break
                    if len(chunk) > remaining:
                        chunk = chunk.iloc[:remaining]
                        truncated = True
                elif opts.mode == "random_fraction":
                    rng = np.random.default_rng([opts.seed, file_index, chunk_idx])
                    chunk = chunk[rng.random(len(chunk)) < opts.sample_frac]

                if len(chunk) == 0:
                    continue
                rows_audited += len(chunk)
                for col in chunk.columns:
                    stats[col].update(chunk[col])
                if opts.check_duplicates:
                    hashes.append(pd.util.hash_pandas_object(chunk, index=False).to_numpy())
    except (pd.errors.ParserError, pd.errors.EmptyDataError, UnicodeDecodeError) as exc:
        info["error"] = f"{type(exc).__name__}: {exc}"
        return info, {}

    exact = opts.mode == "full" or (opts.mode == "first_n_rows" and not truncated)
    info.update(
        {
            "scan_mode": opts.mode,
            "rows_audited": rows_audited,
            # Total rows are only known if we read to the end of the file.
            "rows_in_file": None if truncated else rows_seen,
            "truncated_by_max_rows": truncated,
            "counts_exact_for_file": exact,
            "n_columns": len(header),
            "columns": header,
        }
    )
    if opts.check_duplicates:
        allh = np.concatenate(hashes) if hashes else np.array([], dtype="uint64")
        info["duplicate_rows_within_audited_rows"] = int(len(allh) - len(np.unique(allh)))
    return info, stats


def _integer_valued(values) -> bool:
    try:
        return all(float(v).is_integer() for v in values)
    except (TypeError, ValueError):
        return False


def find_label_candidates(columns: list[ColumnStats]) -> list[dict]:
    """Rank columns that could be the class label, using content, not a fixed name.

    A column is eligible if it has 2..MAX_LABEL_CLASSES distinct values and is either
    text-valued or integer-valued (continuous floats and mixed columns are excluded). Score:
    +3 text-valued, +2 name contains a hint word, +1 last column, +1 no missing values.
    Low-cardinality numeric columns (e.g. 0/1 flags) are eligible but rank low.
    This is a heuristic; a human must confirm the target column.
    """
    last_pos = max((c.position for c in columns), default=-1)
    out = []
    for c in columns:
        if c.distinct is None or not 2 <= len(c.distinct) <= MAX_LABEL_CLASSES:
            continue
        if c.kind != "text" and not (c.kind in ("numeric", "numeric_stored_as_text") and _integer_valued(c.distinct)):
            continue
        score, reasons = 0, []
        if c.kind == "text":
            score += 3
            reasons.append("text-valued")
        lowered = c.name.strip().lower()
        if any(h in lowered for h in LABEL_NAME_HINTS):
            score += 2
            reasons.append("name contains a label-like word")
        if c.position == last_pos:
            score += 1
            reasons.append("last column")
        if c.missing == 0:
            score += 1
            reasons.append("no missing values")
        counts = sorted(c.distinct.items(), key=lambda kv: (-kv[1], str(kv[0])))
        out.append(
            {
                "column": c.name,
                "position": c.position,
                "score": score,
                "reasons": reasons,
                "n_classes": len(c.distinct),
                "value_counts": {str(k): int(v) for k, v in counts},
            }
        )
    out.sort(key=lambda d: (-d["score"], d["position"]))
    return out


def audit_paths(paths: list[str | Path], opts: AuditOptions | None = None) -> dict:
    """Audit CSV files/directories and return a JSON-serialisable report."""
    opts = opts or AuditOptions()
    files = discover_csv_files(paths)
    file_reports: list[dict] = []
    aggregate: dict[str, ColumnStats] = {}
    presence: Counter = Counter()
    ok_column_lists: list[tuple[str, ...]] = []

    for idx, f in enumerate(files):
        info, stats = audit_file(f, idx, opts)
        file_reports.append(info)
        if info["error"]:
            continue
        ok_column_lists.append(tuple(info["columns"]))
        for name, st in stats.items():
            presence[name] += 1
            if name in aggregate:
                aggregate[name].merge(st)
            else:
                agg = ColumnStats(name, st.position)  # position in the first file containing it
                agg.merge(st)
                aggregate[name] = agg

    ok = [r for r in file_reports if not r["error"]]
    cols = list(aggregate.values())

    exact_all = bool(ok) and all(r["counts_exact_for_file"] for r in ok)
    candidates = find_label_candidates(cols)
    schema_identical = len(set(ok_column_lists)) <= 1

    issues = []
    for c in cols:
        d = c.to_dict()
        flags = [
            k
            for k, v in (
                ("missing", d["missing"]),
                ("pos_inf", d["pos_inf"]),
                ("neg_inf", d["neg_inf"]),
                ("unparseable_non_numeric", d["unparseable_non_numeric"] if d["kind"] != "text" else 0),
                ("negative_finite", d["negative_finite"]),
            )
            if v
        ]
        if d["is_constant"]:
            flags.append("constant")
        if c.name != c.name.strip():
            flags.append("whitespace_in_name")
        if len(c.dtypes) > 1:
            flags.append("dtype_varies_across_chunks")
        if flags:
            issues.append({"column": c.name, "flags": flags})
    for name, n in presence.items():
        if n != len(ok):
            issues.append({"column": name, "flags": [f"present_in_{n}_of_{len(ok)}_files"]})

    return {
        "audit_version": AUDIT_VERSION,
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "environment": {
            "python": platform.python_version(),
            "pandas": pd.__version__,
            "numpy": np.__version__,
        },
        "options": {
            "mode": opts.mode,
            "max_rows_per_file": opts.max_rows,
            "sample_frac": opts.sample_frac,
            "seed": opts.seed,
            "chunksize": opts.chunksize,
            "check_duplicates": opts.check_duplicates,
        },
        "totals": {
            "files_found": len(files),
            "files_failed": len(files) - len(ok),
            "rows_audited": sum(r["rows_audited"] for r in ok),
            "all_counts_exact": exact_all,
            "schema_identical_across_files": schema_identical,
        },
        "files": file_reports,
        "columns": [c.to_dict() for c in cols],
        "issues": issues,
        "label_candidates": candidates,
        "label_warnings": (
            []
            if any("text-valued" in c["reasons"] for c in candidates)
            else [
                "No text-valued low-cardinality column found. The class label may be absent "
                "from the files (e.g. encoded in folder or file names). The numeric candidates "
                "below are probably ordinary features, not labels."
            ]
        ),
    }


def format_summary(report: dict, top_candidates: int = 3) -> str:
    t, o = report["totals"], report["options"]
    lines = ["DATASET AUDIT SUMMARY", "=" * 21]
    lines.append(f"Files: {t['files_found']} found, {t['files_failed']} failed to parse")
    lines.append(f"Rows audited: {t['rows_audited']:,}")
    if o["mode"] == "full":
        lines.append("Scan mode: full. Counts are EXACT.")
    elif o["mode"] == "first_n_rows":
        lines.append(
            f"Scan mode: FIRST {o['max_rows_per_file']:,} rows per file. Counts are exact only "
            "for files that were not truncated. A file prefix may be unrepresentative "
            "(files can be ordered by time or class)."
        )
    else:
        lines.append(
            f"Scan mode: RANDOM {o['sample_frac']:.1%} sample (seed {o['seed']}, chunksize "
            f"{o['chunksize']:,}). Counts describe the SAMPLE, not the full files."
        )
    lines.append(f"Schema identical across files: {t['schema_identical_across_files']}")
    lines += ["", "FILES"]
    for f in report["files"]:
        if f["error"]:
            lines.append(f"  {f['path']}: ERROR {f['error']}")
            continue
        total = "unknown (truncated)" if f["rows_in_file"] is None else f"{f['rows_in_file']:,}"
        extra = ""
        if "duplicate_rows_within_audited_rows" in f:
            extra = f", duplicate rows in audited rows: {f['duplicate_rows_within_audited_rows']:,}"
        lines.append(
            f"  {f['path']}: {f['n_columns']} cols, rows audited {f['rows_audited']:,}, "
            f"rows in file {total}, exact={f['counts_exact_for_file']}{extra}"
        )

    lines += ["", "COLUMNS (name | kind | missing | +inf | -inf | non-numeric | negative | min | max)"]
    for c in report["columns"]:
        mn = "-" if c["min"] is None else f"{c['min']:.6g}"
        mx = "-" if c["max"] is None else f"{c['max']:.6g}"
        lines.append(
            f"  {c['name']!r} | {c['kind']} | {c['missing']} | {c['pos_inf']} | {c['neg_inf']} | "
            f"{'-' if c['kind'] == 'text' else c['unparseable_non_numeric']} | "
            f"{c['negative_finite']} | {mn} | {mx}"
        )

    lines += ["", "FLAGGED ISSUES"]
    lines += [f"  {i['column']!r}: {', '.join(i['flags'])}" for i in report["issues"]] or ["  none"]

    lines += ["", "LABEL-COLUMN CANDIDATES (heuristic; confirm manually)"]
    lines += [f"  WARNING: {w}" for w in report.get("label_warnings", [])]
    if not report["label_candidates"]:
        lines.append("  none found")
    for cand in report["label_candidates"][:top_candidates]:
        lines.append(
            f"  {cand['column']!r} (position {cand['position']}, score {cand['score']}, "
            f"{cand['n_classes']} values; {', '.join(cand['reasons']) or 'no strong signals'})"
        )
        for value, n in list(cand["value_counts"].items())[:15]:
            lines.append(f"      {value}: {n:,}")
        if cand["n_classes"] > 15:
            lines.append(f"      ... {cand['n_classes'] - 15} more (see JSON)")
    return "\n".join(lines) + "\n"


def write_report(report: dict, output_dir: str | Path) -> tuple[Path, Path]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    json_path, txt_path = out / "audit_report.json", out / "audit_summary.txt"
    json_path.write_text(json.dumps(report, indent=2, allow_nan=False), encoding="utf-8")
    txt_path.write_text(format_summary(report), encoding="utf-8")
    return json_path, txt_path


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Audit CSV files without loading them all into memory.")
    p.add_argument("paths", nargs="+", help="CSV files and/or directories (searched recursively)")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--max-rows", type=int, help="audit only the first N rows of each file")
    g.add_argument("--sample-frac", type=float, help="audit a seeded random fraction of rows (0-1]")
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--chunksize", type=int, default=100_000)
    p.add_argument("--check-duplicates", action="store_true", help="count exact duplicate rows within each file")
    p.add_argument("--checksum", action="store_true", help="record SHA-256 of each file (slow on big files)")
    p.add_argument("--output-dir", default="results/audit")
    args = p.parse_args(argv)

    try:
        opts = AuditOptions(
            chunksize=args.chunksize,
            max_rows=args.max_rows,
            sample_frac=args.sample_frac,
            seed=args.seed,
            check_duplicates=args.check_duplicates,
            checksum=args.checksum,
        )
        report = audit_paths(args.paths, opts)
    except (ValueError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    json_path, txt_path = write_report(report, args.output_dir)
    print(format_summary(report))
    print(f"Wrote {json_path} and {txt_path}")
    return 1 if report["totals"]["files_failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
