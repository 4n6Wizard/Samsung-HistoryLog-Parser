"""Regression test for samsung_secure_folder_historylog_parser.

Runs standalone (no pytest required):

    python test_regression.py

It (1) builds a synthetic HistoryLog database, (2) runs the parser end to end,
(3) compares the generated CSV row-for-row against the shipped Example_Report.csv
golden file, and (4) adds focused unit checks for the two fixes applied in this
sandbox (single COUNT_RE evaluation; removal of the no-op comparable_datetime).
"""

from __future__ import annotations

import csv
import shutil
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import build_fixture_db
import samsung_secure_folder_historylog_parser as parser

GOLDEN_CSV = HERE / "Example_Report.csv"


def read_csv_rows(path: Path):
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def test_end_to_end_matches_golden_report():
    # NOTE: parse_database does not close its SQLite connection (the `with`
    # block only manages the transaction), so on Windows the db file stays
    # locked until the process exits. We therefore use mkdtemp + best-effort
    # rmtree instead of TemporaryDirectory's strict auto-cleanup.
    tmp_path = Path(tempfile.mkdtemp(prefix="ssf_regression_"))
    try:
        db_path = build_fixture_db.build(tmp_path / "fixture.db")
        result = parser.parse_database(
            db_path,
            tmp_path,
            report_name="regression",
            write_reports=True,
        )
        assert result.selected_table.name == "HistoryLog", (
            f"table identification picked {result.selected_table.name!r}"
        )

        produced = read_csv_rows(result.csv_path)
        golden = read_csv_rows(GOLDEN_CSV)

        assert len(produced) == len(golden), (
            f"row count {len(produced)} != golden {len(golden)}"
        )
        assert produced[0].keys() == golden[0].keys(), "CSV columns differ from golden"

        mismatches = []
        for i, (got, want) in enumerate(zip(produced, golden), start=1):
            for column in want:
                if got.get(column, "") != want[column]:
                    mismatches.append(
                        f"  Event row {i}, column {column!r}: "
                        f"got {got.get(column, '')!r} want {want[column]!r}"
                    )
        assert not mismatches, "CSV does not match golden report:\n" + "\n".join(mismatches)

        # HTML report is written and carries the report title.
        assert result.html_path.exists()
        html = result.html_path.read_text(encoding="utf-8")
        assert "Samsung Secure Folder HistoryLog Forensic Report" in html
    finally:
        shutil.rmtree(tmp_path, ignore_errors=True)


def _parse_one(message: str) -> parser.ParsedRecord:
    candidate = parser.TableCandidate(
        name="HistoryLog",
        sql="",
        row_count=1,
        columns=[],
        id_column=None,
        timestamp_column=None,
        tag_column=None,
        message_column="message",
    )

    class _Row(dict):
        def keys(self):  # ParsedRecord iterates row.keys()
            return super().keys()

    row = _Row({"message": message})
    return parser.parse_record(1, "HistoryLog", 1, row, candidate)


def test_count_without_app_bracket_is_extracted():
    # Fix #2: COUNT_RE fallback now evaluated once; still extracts the count
    # when no [app] bracket is present.
    record = _parse_one("[0 -> 150] Count : 9")
    assert record.requested_count == 9, record.requested_count


def test_request_with_app_bracket_still_wins():
    record = _parse_one("[0 -> 150] [Gallery] Count : 4")
    assert record.classification == "request"
    assert record.source_app == "Gallery"
    assert record.requested_count == 4


def test_comparable_datetime_indirection_removed():
    # Fix #3: the no-op pass-through is gone; sorting helpers use timestamp_sort directly.
    assert not hasattr(parser, "comparable_datetime")


def test_database_handle_released_after_parsing():
    # Fix #5: parse_database now closes its connection. On Windows, deleting an
    # open file raises PermissionError, so a clean unlink proves the lock is gone.
    tmp_path = Path(tempfile.mkdtemp(prefix="ssf_lock_"))
    try:
        db_path = build_fixture_db.build(tmp_path / "fixture.db")
        parser.parse_database(db_path, tmp_path, report_name="lockcheck", write_reports=False)
        db_path.unlink()  # raises PermissionError if the connection is still open
        assert not db_path.exists()
    finally:
        shutil.rmtree(tmp_path, ignore_errors=True)


def run() -> int:
    tests = [
        ("end-to-end CSV matches Example_Report.csv golden", test_end_to_end_matches_golden_report),
        ("count without [app] bracket is extracted (fix #2)", test_count_without_app_bracket_is_extracted),
        ("request with [app] bracket classified as request", test_request_with_app_bracket_still_wins),
        ("comparable_datetime no-op removed (fix #3)", test_comparable_datetime_indirection_removed),
        ("database handle released after parsing (fix #5)", test_database_handle_released_after_parsing),
    ]
    failures = 0
    for name, fn in tests:
        try:
            fn()
        except AssertionError as exc:
            failures += 1
            print(f"FAIL: {name}\n{exc}")
        except Exception as exc:  # noqa: BLE001 - surface any unexpected error
            failures += 1
            print(f"ERROR: {name}: {type(exc).__name__}: {exc}")
        else:
            print(f"PASS: {name}")
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(run())
