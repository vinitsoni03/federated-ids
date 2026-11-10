"""Tests for federated_ids.data.audit.

Expected values come from the issues planted in tests/fixtures (see the fixture
generation notes in docs/DECISIONS.md), not from the audit's own output.

Fixture A (40 data rows) planted: 1 missing flow_duration, pkt_rate +inf and -inf,
bytes_total = -1, avg_size "Infinity" and "abc", 1 missing traffic_class,
1 exact duplicate row. Fixture B (20 rows) planted: 1 exact duplicate row.
Header " idle_time" has a leading space; const_col is always 0.
Non-missing class counts across both files: Benign 26, DDoS 18, Mirai 9, Recon 6.
"""
import json
import shutil
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from federated_ids.data.audit import AuditOptions, audit_paths, discover_csv_files, format_summary, main

FIX = Path(__file__).parent / "fixtures"
A, B = FIX / "mini_flows_a.csv", FIX / "mini_flows_b.csv"


def col(report, name):
    return next(c for c in report["columns"] if c["name"] == name)


@pytest.fixture(scope="module")
def full_report():
    return audit_paths([FIX], AuditOptions(check_duplicates=True))


def test_directory_discovery_and_row_counts(full_report):
    assert [Path(f["path"]).name for f in full_report["files"]] == ["mini_flows_a.csv", "mini_flows_b.csv"]
    assert [f["rows_in_file"] for f in full_report["files"]] == [40, 20]
    assert full_report["totals"]["rows_audited"] == 60
    assert full_report["totals"]["all_counts_exact"] is True
    assert full_report["totals"]["schema_identical_across_files"] is True


def test_planted_invalid_values_are_counted_exactly(full_report):
    assert col(full_report, "flow_duration")["missing"] == 1
    pr = col(full_report, "pkt_rate")
    assert (pr["pos_inf"], pr["neg_inf"]) == (1, 1)
    assert col(full_report, "bytes_total")["negative_finite"] == 1
    avg = col(full_report, "avg_size")
    assert avg["kind"] == "mixed_numeric_and_text"
    assert avg["unparseable_non_numeric"] == 1  # "abc"
    assert avg["pos_inf"] == 1  # "Infinity" read as +inf
    assert col(full_report, "traffic_class")["missing"] == 1


def test_constant_and_whitespace_header_flagged(full_report):
    assert col(full_report, "const_col")["is_constant"]
    flags = {i["column"]: i["flags"] for i in full_report["issues"]}
    assert "constant" in flags["const_col"]
    assert "whitespace_in_name" in flags[" idle_time"]


def test_duplicates_counted_per_file(full_report):
    assert [f["duplicate_rows_within_audited_rows"] for f in full_report["files"]] == [1, 1]


def test_label_candidate_found_without_name_assumption(full_report):
    top = full_report["label_candidates"][0]
    assert top["column"] == "traffic_class"
    assert top["value_counts"] == {"Benign": 26, "DDoS": 18, "Mirai": 9, "Recon": 6}


def test_continuous_float_columns_are_not_label_candidates(full_report):
    names = [c["column"] for c in full_report["label_candidates"]]
    assert "pkt_rate" not in names and "avg_size" not in names
    assert "syn_flag" in names  # integer-valued 0/1 flag: eligible but ranked below the text label
    assert names.index("traffic_class") < names.index("syn_flag")


def test_text_column_not_flagged_as_unparseable(full_report):
    flags = {i["column"]: i["flags"] for i in full_report["issues"]}
    assert "unparseable_non_numeric" not in flags["traffic_class"]
    assert "unparseable_non_numeric" in flags["avg_size"]


def test_label_candidate_found_when_column_is_renamed(tmp_path):
    df = pd.concat([pd.read_csv(A), pd.read_csv(B)]).rename(columns={"traffic_class": "zq"})
    df.to_csv(tmp_path / "renamed.csv", index=False)
    top = audit_paths([tmp_path / "renamed.csv"])["label_candidates"][0]
    assert top["column"] == "zq"  # found via text-valued + low cardinality, not by name


def test_streaming_moments_match_pandas_across_chunks():
    """Chunked Welford/Chan merge must agree with a one-shot pandas computation."""
    rep = audit_paths([A, B], AuditOptions(chunksize=7))  # many small chunks
    whole = pd.concat([pd.read_csv(A), pd.read_csv(B)])["bytes_total"]
    whole = whole[np.isfinite(whole)]
    c = col(rep, "bytes_total")
    assert c["n_finite"] == len(whole)
    assert c["mean"] == pytest.approx(whole.mean())
    assert c["std_population"] == pytest.approx(whole.std(ddof=0))
    assert (c["min"], c["max"]) == (whole.min(), whole.max())


def test_chunksize_does_not_change_exact_counts():
    r1 = audit_paths([FIX], AuditOptions(chunksize=7))
    r2 = audit_paths([FIX], AuditOptions(chunksize=100_000))
    for name in ("pkt_rate", "avg_size", "flow_duration", "traffic_class"):
        a, b = col(r1, name), col(r2, name)
        for k in ("missing", "pos_inf", "neg_inf", "unparseable_non_numeric", "n_distinct"):
            assert a[k] == b[k], (name, k)
    assert r1["label_candidates"][0]["value_counts"] == r2["label_candidates"][0]["value_counts"]


def test_max_rows_truncation_flags():
    rep = audit_paths([A, B], AuditOptions(max_rows=25, chunksize=10))
    fa, fb = rep["files"]
    assert fa["rows_audited"] == 25 and fa["truncated_by_max_rows"] and fa["rows_in_file"] is None
    assert not fa["counts_exact_for_file"]
    # B has only 20 rows (< 25): fully read, so its counts remain exact
    assert fb["rows_audited"] == 20 and not fb["truncated_by_max_rows"] and fb["rows_in_file"] == 20
    assert fb["counts_exact_for_file"]
    assert rep["totals"]["all_counts_exact"] is False


def test_max_rows_equal_to_file_length_is_not_truncated():
    rep = audit_paths([B], AuditOptions(max_rows=20, chunksize=10))
    assert not rep["files"][0]["truncated_by_max_rows"]
    assert rep["files"][0]["counts_exact_for_file"]


def test_random_fraction_is_deterministic_and_labelled():
    o = dict(sample_frac=0.5, seed=3, chunksize=10)
    r1, r2 = audit_paths([FIX], AuditOptions(**o)), audit_paths([FIX], AuditOptions(**o))
    assert r1["totals"]["rows_audited"] == r2["totals"]["rows_audited"]
    assert r1["label_candidates"][0]["value_counts"] == r2["label_candidates"][0]["value_counts"]
    assert 0 < r1["totals"]["rows_audited"] < 60
    assert [f["rows_in_file"] for f in r1["files"]] == [40, 20]  # full scan, exact totals
    assert not r1["totals"]["all_counts_exact"]
    assert "SAMPLE" in format_summary(r1)


def test_schema_mismatch_between_files_is_reported(tmp_path):
    shutil.copy(A, tmp_path / "a.csv")
    pd.read_csv(B).assign(extra_col=1).to_csv(tmp_path / "b.csv", index=False)
    rep = audit_paths([tmp_path])
    assert rep["totals"]["schema_identical_across_files"] is False
    assert any("present_in_1_of_2_files" in f for i in rep["issues"] for f in i["flags"] if i["column"] == "extra_col")


def test_unparseable_file_reported_not_fatal(tmp_path):
    shutil.copy(A, tmp_path / "good.csv")
    (tmp_path / "empty.csv").write_text("")
    rep = audit_paths([tmp_path])
    assert rep["totals"]["files_failed"] == 1
    assert rep["totals"]["rows_audited"] == 40


def test_header_only_file(tmp_path):
    (tmp_path / "h.csv").write_text("a,b\n")
    rep = audit_paths([tmp_path / "h.csv"])
    assert rep["totals"]["rows_audited"] == 0
    assert rep["files"][0]["n_columns"] == 2


def test_invalid_options_and_missing_path():
    with pytest.raises(ValueError):
        AuditOptions(max_rows=5, sample_frac=0.5)
    with pytest.raises(ValueError):
        AuditOptions(sample_frac=1.5)
    with pytest.raises(FileNotFoundError):
        discover_csv_files(["does/not/exist"])


def test_cli_writes_valid_json_and_summary(tmp_path, capsys):
    code = main([str(FIX), "--output-dir", str(tmp_path / "out"), "--check-duplicates", "--checksum"])
    assert code == 0
    data = json.loads((tmp_path / "out" / "audit_report.json").read_text())
    assert data["totals"]["rows_audited"] == 60
    assert len(data["files"][0]["sha256"]) == 64
    assert "traffic_class" in (tmp_path / "out" / "audit_summary.txt").read_text()
    assert "EXACT" in capsys.readouterr().out


def test_cli_input_not_modified(tmp_path):
    before = A.read_bytes()
    main([str(A), "--output-dir", str(tmp_path)])
    assert A.read_bytes() == before


def test_cli_bad_path_returns_error_code(tmp_path, capsys):
    assert main(["nope.csv", "--output-dir", str(tmp_path)]) == 2


def test_all_numeric_files_get_no_label_warning_and_type_is_not_a_hint(tmp_path):
    """Regression: real data had no text column; 'Protocol Type' was ranked as the label."""
    pd.DataFrame({"Protocol Type": [6, 17, 1, 6] * 5, "Rate": np.linspace(0.5, 9.5, 20)}).to_csv(
        tmp_path / "n.csv", index=False
    )
    rep = audit_paths([tmp_path / "n.csv"])
    assert rep["label_warnings"], "expected a warning when no text-valued candidate exists"
    assert all("label-like word" not in c["reasons"] for c in rep["label_candidates"])
    assert "WARNING" in format_summary(rep)


def test_no_warning_when_text_label_exists(full_report):
    assert full_report["label_warnings"] == []
