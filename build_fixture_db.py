"""Build a synthetic Samsung Secure Folder HistoryLog SQLite database.

The crafted rows reproduce, end to end, the eight events shown in the shipped
Example_Report.csv: five paired transfers (including derived paths, a
no-Total result, and a multi-path result), one unpaired request, one unpaired
result, and one paired transfer with blank timestamps. The message strings are
built to match the parser's structural regexes, not localized wording.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

# (id, timestamp, tag, message)
# id ordering matters only for the blank-timestamp event (req must precede res).
ROWS = [
    # Event 1 — paired, no path: Source/Transferred N/A.
    (1, "2025-01-01 08:00:00", "request", "[0 -> 150] [Gallery] Count : 1"),
    (2, "2025-01-01 08:00:03", "result", "[0 -> 150] [1] [Total : 1]"),
    # Event 2 — paired, result has a path but no Total -> Moved Count N/A; source derived.
    (3, "2025-01-01 08:01:00", "request", "[0 -> 150] [MyFiles] Count : 2"),
    (4, "2025-01-01 08:01:04", "result", "[0 -> 150] /storage/emulated/150/Download"),
    # Event 3 — paired with single derived path.
    (5, "2025-01-01 08:02:00", "request", "[0 -> 150] [Gallery] Count : 3"),
    (6, "2025-01-01 08:02:08", "result",
     "[0 -> 150] [3] [Total : 3]\n/storage/emulated/150/DCIM/Screenshots"),
    # Event 4 — paired, path with a space.
    (7, "2025-01-01 08:03:00", "request", "[0 -> 150] [MyFiles] Count : 4"),
    (8, "2025-01-01 08:03:02", "result",
     "[0 -> 150] [4] [Total : 4]\n/storage/emulated/150/My Folder"),
    # Event 5 — paired, two paths (newline-separated so PATH_RE yields two).
    (9, "2025-01-01 08:04:00", "request", "[0 -> 150] [MyFiles] Count : 5"),
    (10, "2025-01-01 08:04:05", "result",
     "[0 -> 150] [5] [Total : 5]\n/storage/emulated/150/Folder One"
     "\n/storage/emulated/150/Folder Two"),
    # Event 6 — unpaired request (direction [20 -> 150] has no matching result).
    (11, "2025-01-01 08:05:00", "request", "[20 -> 150] [Gallery] Count : 7"),
    # Event 7 — unpaired result (direction [30 -> 150] has no matching request).
    (12, "2025-01-01 08:06:00", "result", "[30 -> 150] [8] [Total : 8]"),
    # Event 8 — paired with blank timestamps (pairs by sequence + equal counts).
    (13, "", "request", "[10 -> 150] [MyFiles] Count : 6"),
    (14, "", "result", "[10 -> 150] [6] [Total : 6]"),
]


def build(db_path: Path) -> Path:
    db_path = Path(db_path)
    if db_path.exists():
        db_path.unlink()
    con = sqlite3.connect(str(db_path))
    try:
        # Decoy table to confirm structural table identification, not name matching.
        con.execute("CREATE TABLE app_settings (id INTEGER PRIMARY KEY, key TEXT, value TEXT)")
        con.executemany(
            "INSERT INTO app_settings (key, value) VALUES (?, ?)",
            [("theme", "dark"), ("locale", "en_US"), ("autolock", "60")],
        )
        con.execute(
            "CREATE TABLE HistoryLog ("
            "id INTEGER PRIMARY KEY, timestamp TEXT, tag TEXT, message TEXT)"
        )
        con.executemany(
            "INSERT INTO HistoryLog (id, timestamp, tag, message) VALUES (?, ?, ?, ?)",
            ROWS,
        )
        con.commit()
    finally:
        con.close()
    return db_path


if __name__ == "__main__":
    out = build(Path(__file__).resolve().parent / "fixture_historylog.db")
    print(f"Wrote fixture database: {out}")
