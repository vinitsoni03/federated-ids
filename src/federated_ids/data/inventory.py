"""Exact per-folder row inventory for a directory tree of CSV files.

Purpose: when the class label is encoded in the folder name (as in the downloaded
CICIoT2023 layout), the number of rows per folder is the class distribution. This tool
counts data rows exactly without parsing the CSV, by counting newline bytes.

Assumptions (checked by tests, but not guaranteed for arbitrary CSVs): one record per
line, no quoted embedded newlines, no blank lines inside the file, one header line.
It also compares header lines across files. It reads files only; nothing is modified.

Usage:
    python -m federated_ids.data.inventory ROOT [--output-dir DIR]
Files directly under ROOT are grouped as "(root)"; others by their first subfolder.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT_GROUP = "(root)"


def count_data_rows(path: Path, block: int = 1 << 20) -> int:
    """Rows after the header line. Returns 0 for an empty file or header-only file."""
    newlines, last, size = 0, b"", 0
    with open(path, "rb") as fh:
        while chunk := fh.read(block):
            newlines += chunk.count(b"\n")
            last, size = chunk[-1:], size + len(chunk)
    if size == 0:
        return 0
    lines = newlines + (0 if last == b"\n" else 1)  # final line without trailing newline
    return max(lines - 1, 0)


def read_header(path: Path) -> str:
    with open(path, "rb") as fh:
        return fh.readline().decode("utf-8", errors="replace").rstrip("\r\n")


def build_inventory(root: str | Path) -> dict:
    root = Path(root)
    if not root.is_dir():
        raise FileNotFoundError(f"Not a directory: {root}")
    files = sorted(f for f in root.rglob("*") if f.is_file() and f.suffix.lower() == ".csv")
    if not files:
        raise FileNotFoundError(f"No CSV files under {root}")

    groups: dict[str, dict] = defaultdict(lambda: {"n_files": 0, "rows": 0, "bytes": 0, "files": []})
    headers: dict[str, list[str]] = defaultdict(list)
    for f in files:
        rel = f.relative_to(root)
        group = rel.parts[0] if len(rel.parts) > 1 else ROOT_GROUP
        rows = count_data_rows(f)
        g = groups[group]
        g["n_files"] += 1
        g["rows"] += rows
        g["bytes"] += f.stat().st_size
        g["files"].append({"file": rel.as_posix(), "rows": rows})
        headers[read_header(f)].append(rel.as_posix())

    total = sum(g["rows"] for g in groups.values())
    out_groups = {
        name: {**g, "share_of_total_rows": (g["rows"] / total if total else None)}
        for name, g in sorted(groups.items(), key=lambda kv: -kv[1]["rows"])
    }
    return {
        "root": str(root),
        "counting_method": "newline bytes minus header; exact under the assumptions in the module docstring",
        "n_files": len(files),
        "n_groups": len(out_groups),
        "total_rows": total,
        "headers_identical_across_files": len(headers) == 1,
        "distinct_headers": [{"n_files": len(v), "example_file": v[0], "header": h} for h, v in headers.items()],
        "groups": out_groups,
    }


def format_inventory(inv: dict) -> str:
    lines = [
        "ROW INVENTORY (exact counts)",
        f"Root: {inv['root']}",
        f"Files: {inv['n_files']}, groups: {inv['n_groups']}, total data rows: {inv['total_rows']:,}",
        f"Headers identical across files: {inv['headers_identical_across_files']}",
        "",
        f"{'group':40} {'files':>6} {'rows':>14} {'share':>8}",
    ]
    for name, g in inv["groups"].items():
        lines.append(f"{name:40} {g['n_files']:>6} {g['rows']:>14,} {g['share_of_total_rows']:>8.3%}")
    if not inv["headers_identical_across_files"]:
        lines += ["", "HEADER VARIANTS"]
        lines += [f"  {d['n_files']} files, e.g. {d['example_file']}: {d['header']}" for d in inv["distinct_headers"]]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Exact per-folder CSV row counts.")
    p.add_argument("root")
    p.add_argument("--output-dir", default="results/audit")
    args = p.parse_args(argv)
    try:
        inv = build_inventory(args.root)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "row_inventory.json").write_text(json.dumps(inv, indent=2, allow_nan=False), encoding="utf-8")
    text = format_inventory(inv)
    (out / "row_inventory.txt").write_text(text, encoding="utf-8")
    print(text)
    print(f"Wrote {out / 'row_inventory.json'} and {out / 'row_inventory.txt'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
