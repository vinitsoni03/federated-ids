import shutil
from pathlib import Path

import pandas as pd

from federated_ids.data.inventory import ROOT_GROUP, build_inventory, count_data_rows, main

FIX = Path(__file__).parent / "fixtures"


def write(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def test_count_rows_edge_cases(tmp_path):
    assert count_data_rows(write(tmp_path / "a.csv", b"h\n1\n2\n3\n")) == 3
    assert count_data_rows(write(tmp_path / "b.csv", b"h\n1\n2\n3")) == 3  # no trailing newline
    assert count_data_rows(write(tmp_path / "c.csv", b"h\r\n1\r\n2\r\n")) == 2  # CRLF
    assert count_data_rows(write(tmp_path / "d.csv", b"h\n")) == 0  # header only
    assert count_data_rows(write(tmp_path / "e.csv", b"h")) == 0  # header, no newline
    assert count_data_rows(write(tmp_path / "f.csv", b"")) == 0  # empty file


def test_count_matches_pandas_on_fixtures():
    for f in FIX.glob("*.csv"):
        assert count_data_rows(f) == len(pd.read_csv(f))


def test_count_across_block_boundaries(tmp_path):
    p = write(tmp_path / "big.csv", b"h\n" + b"1\n" * 1000)
    assert count_data_rows(p, block=7) == 1000


def test_groups_by_first_subfolder(tmp_path):
    write(tmp_path / "Benign" / "b0.csv", b"x,y\n1,2\n3,4\n")
    write(tmp_path / "Benign" / "b1.csv", b"x,y\n1,2\n")
    write(tmp_path / "Attack" / "sub" / "a0.csv", b"x,y\n1,2\n2,3\n3,4\n4,5\n")
    write(tmp_path / "top.csv", b"x,y\n9,9\n")
    inv = build_inventory(tmp_path)
    assert inv["total_rows"] == 8
    assert {k: v["rows"] for k, v in inv["groups"].items()} == {"Attack": 4, "Benign": 3, ROOT_GROUP: 1}
    assert inv["groups"]["Benign"]["n_files"] == 2
    assert abs(inv["groups"]["Attack"]["share_of_total_rows"] - 0.5) < 1e-12
    assert inv["headers_identical_across_files"] is True


def test_header_mismatch_detected(tmp_path):
    write(tmp_path / "A" / "a.csv", b"x,y\n1,2\n")
    write(tmp_path / "B" / "b.csv", b"x,z\n1,2\n")
    inv = build_inventory(tmp_path)
    assert inv["headers_identical_across_files"] is False
    assert len(inv["distinct_headers"]) == 2


def test_cli_and_errors(tmp_path):
    shutil.copytree(FIX, tmp_path / "data" / "cls")
    assert main([str(tmp_path / "data"), "--output-dir", str(tmp_path / "out")]) == 0
    assert (tmp_path / "out" / "row_inventory.json").exists()
    assert main([str(tmp_path / "missing"), "--output-dir", str(tmp_path / "out")]) == 2
