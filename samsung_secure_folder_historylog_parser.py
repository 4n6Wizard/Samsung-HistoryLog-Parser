#!/usr/bin/env python3
"""
Samsung Secure Folder HistoryLog forensic parser.

The parser identifies the likely history table by SQLite schema and structural
record patterns, then parses request/result rows without relying on localized
message wording.
"""

from __future__ import annotations

import argparse
import csv
import html
import json
import re
import shutil
import sqlite3
import stat
import sys
from contextlib import closing
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import quote


DISCLAIMER = (
    "This parser is provided to assist the digital forensic community. Results should "
    "be independently validated. The tool preserves original database values where "
    "possible and does not modify source evidence files."
)
WAL_SHM_WARNING = (
    "This database has SQLite WAL/SHM sidecar files. These files may contain recent "
    "transactions that are not fully checkpointed into the main database. For best "
    "forensic results, create a clean consolidated working copy before parsing. "
    "The working copy is checkpointed and saved without WAL/SHM sidecar files."
)
SIDECAR_DIALOG_TITLE = "Additional Database Files Found"
SIDECAR_DIALOG_MESSAGE = (
    "This database has related files that may contain additional transfer records.\n\n"
    "Would you like to create a clean working copy before processing?"
)
APP_VERSION = "1.1"
DEFAULT_REPORT_FILENAME = "SecureFolder_HistoryLog_Report.html"
STATUS_READY = "Ready | Source evidence files are not modified."
STATUS_NOT_A_DATABASE = "Selected file is not a SQLite database."
STATUS_DATABASE_SELECTED = "Database selected."
STATUS_PARSING = "Processing database..."
STATUS_SIDECARS_DETECTED = "Additional database files found."
STATUS_CONSOLIDATING = "Creating clean working copy..."
STATUS_SUCCESS = "Report saved successfully."
STATUS_CLEAN_COPY_SUCCESS = "Clean database loaded."
STATUS_CLEAN_COPY_PROCESSING = "Clean database loaded. Processing..."
STATUS_DATABASE_PROCESSED = "Database processed successfully."
STATUS_READY_TO_SAVE_REPORT = "Ready to save report."
STATUS_SELECTION_CANCELED = "Database selection canceled."
STATUS_OUTPUT_OPENED = "Output folder opened."
STATUS_OUTPUT_OPEN_FAILED = "Output folder could not be opened."
STATUS_SAVE_FAILED = "Report could not be saved."
CHOICE_CONSOLIDATE = "Recommended: Consolidate Copy and Parse"
CHOICE_PARSE_ORIGINAL = "Parse Original Only"
CHOICE_CANCEL = "Cancel"
CONSOLIDATED_MARKER_FILENAME = "CONSOLIDATED_WORKING_COPY.txt"
ALREADY_CONSOLIDATED_MESSAGE = "This database is already a consolidated working copy."
PATH_FIELD_NA = "N/A"
SOURCE_PATH_EXTRACTED_NOTE = "Source Path extracted from request message."
SOURCE_PATH_DERIVED_NOTE = (
    "Source Path derived from transferred path using source/destination profile IDs."
)
SOURCE_PATH_UNAVAILABLE_NOTE = "Source Path not available in HistoryLog data."

DIRECTION_RE = re.compile(r"\[(?P<src>\d+)\s*->\s*(?P<dst>\d+)\]")
REQUEST_RE = re.compile(
    r"\[\s*(?P<src>\d+)\s*->\s*(?P<dst>\d+)\s*\]\s*"
    r"\[(?P<app>[^\]\r\n]+)\]\s*"
    r"Count\s*:\s*(?P<count>\d+)\b",
    re.IGNORECASE,
)
COUNT_RE = re.compile(r"\bCount\s*:\s*(?P<count>\d+)\b", re.IGNORECASE)
TOTAL_RE = re.compile(r"\[\s*Total\s*:\s*(?P<total>\d+)\s*\]", re.IGNORECASE)
PATH_RE = re.compile(r"(?m)(/(?:storage/emulated|data|mnt)/[^\]\[\r\n\t\x00\"']*)")
LEADING_RESULT_COUNT_RE = re.compile(
    r"\]\s*\[\s*(?P<count>\d+)\b.*?\[\s*Total\s*:",
    re.IGNORECASE | re.DOTALL,
)
LEADING_BRACKET_COUNT_RE = re.compile(r"\]\s*\[\s*(?P<count>\d+)\b", re.DOTALL)

ID_NAME_HINTS = {"id", "_id", "rowid"}
TIMESTAMP_NAME_HINTS = (
    "timestamp",
    "time_stamp",
    "datetime",
    "date_time",
    "created",
    "modified",
    "time",
    "date",
)
TAG_NAME_HINTS = {"tag", "type", "event", "action", "status", "kind"}
MESSAGE_NAME_HINTS = {
    "message",
    "msg",
    "text",
    "body",
    "description",
    "detail",
    "details",
    "log",
    "content",
}


@dataclass
class ColumnInfo:
    cid: int
    name: str
    declared_type: str
    notnull: bool
    default_value: Any
    pk: int


@dataclass
class TableCandidate:
    name: str
    sql: str
    row_count: int
    columns: List[ColumnInfo]
    id_column: Optional[str] = None
    timestamp_column: Optional[str] = None
    tag_column: Optional[str] = None
    message_column: Optional[str] = None
    score: float = 0.0
    structural_rows: int = 0
    request_like_rows: int = 0
    result_like_rows: int = 0
    path_rows: int = 0
    notes: List[str] = field(default_factory=list)


@dataclass
class ParsedRecord:
    sequence: int
    table_name: str
    database_row_id: Optional[Any]
    id_value: Optional[Any]
    raw_values: Dict[str, Any]
    raw_timestamp: str
    timestamp_sort: Optional[datetime]
    tag: str
    raw_message: str
    classification: str
    raw_direction: str = ""
    source_profile_id: Optional[int] = None
    destination_profile_id: Optional[int] = None
    source_app: str = ""
    requested_count: Optional[int] = None
    result_total_count: Optional[int] = None
    result_moved_count: Optional[int] = None
    paths: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


@dataclass
class Event:
    event_id: int
    status: str
    request: Optional[ParsedRecord] = None
    result: Optional[ParsedRecord] = None
    unknown: Optional[ParsedRecord] = None
    warnings: List[str] = field(default_factory=list)
    source_path: str = PATH_FIELD_NA
    transferred_path: str = PATH_FIELD_NA
    source_path_note: str = SOURCE_PATH_UNAVAILABLE_NOTE

    def primary_record(self) -> ParsedRecord:
        record = self.request or self.result or self.unknown
        if record is None:
            raise ValueError("event has no record")
        return record


@dataclass
class ParseResult:
    database_path: Path
    output_dir: Path
    selected_table: TableCandidate
    candidates: List[TableCandidate]
    records: List[ParsedRecord]
    events: List[Event]
    warnings: List[str]
    csv_path: Path
    html_path: Path
    log_path: Optional[Path] = None
    original_database_path: Optional[Path] = None
    detected_sidecar_files: List[Path] = field(default_factory=list)
    user_choice: str = ""
    consolidation_performed: bool = False
    working_database_path: Optional[Path] = None
    checkpoint_result: str = "Not performed"


def quote_identifier(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def stringify(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return "0x" + value.hex()
    return str(value)


def json_safe(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"bytes_hex": value.hex()}
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def int_or_none(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def sqlite_readonly_uri(path: Path, immutable: bool = False) -> str:
    resolved = path.resolve()
    uri_path = resolved.as_posix()
    params = "mode=ro"
    if immutable:
        params += "&immutable=1"
    return "file:" + quote(uri_path, safe="/:") + "?" + params


def running_as_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def app_base_dir() -> Path:
    if running_as_frozen():
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def default_gui_output_dir() -> Path:
    documents = Path.home() / "Documents"
    if documents.exists():
        return documents
    return app_base_dir()


SQLITE_MAGIC = b"SQLite format 3\x00"


def is_sqlite_database(path: Path) -> bool:
    """Return True if the file begins with the 16-byte SQLite header.

    Detection is content-based, not extension-based, so a genuine HistoryLog
    file passes regardless of its name and a renamed non-database file fails.
    """
    try:
        with path.open("rb") as handle:
            return handle.read(16) == SQLITE_MAGIC
    except OSError:
        return False


def open_readonly_database(path: Path) -> sqlite3.Connection:
    errors: List[str] = []
    for immutable in (False, True):
        uri = sqlite_readonly_uri(path, immutable=immutable)
        try:
            con = sqlite3.connect(uri, uri=True)
            con.row_factory = sqlite3.Row
            con.execute("PRAGMA query_only = ON")
            return con
        except sqlite3.Error as exc:
            errors.append(f"{uri}: {exc}")
    raise RuntimeError(
        "Unable to open SQLite database in read-only mode. "
        + " | ".join(errors)
    )


def detect_sidecar_files(database_path: Path) -> List[Path]:
    sidecars = []
    for suffix in ("-wal", "-shm"):
        candidate = Path(str(database_path) + suffix)
        if candidate.exists():
            sidecars.append(candidate)
    return sidecars


def consolidated_marker_path(database_path: Path) -> Path:
    return database_path.parent / CONSOLIDATED_MARKER_FILENAME


def is_consolidated_working_copy(database_path: Path) -> bool:
    return database_path.exists() and consolidated_marker_path(database_path).exists()


def sidecar_for_suffix(sidecar_files: Sequence[Path], suffix: str) -> Optional[Path]:
    for sidecar in sidecar_files:
        if sidecar.name.endswith(suffix):
            return sidecar
    return None


def write_consolidated_marker(
    marker_path: Path,
    original_database_path: Path,
    working_database_path: Path,
    detected_sidecar_files: Sequence[Path],
) -> None:
    wal_file = sidecar_for_suffix(detected_sidecar_files, "-wal")
    shm_file = sidecar_for_suffix(detected_sidecar_files, "-shm")
    wal_detected = f"Yes - {wal_file}" if wal_file else "No"
    shm_detected = f"Yes - {shm_file}" if shm_file else "No"
    lines = [
        "CONSOLIDATED_WORKING_COPY",
        f"Original source database path: {original_database_path}",
        f"Clean database path: {working_database_path}",
        f"Consolidation timestamp: {datetime.now().isoformat(timespec='seconds')}",
        f"WAL detected: {wal_detected}",
        f"SHM detected: {shm_detected}",
        "",
    ]
    marker_path.write_text("\n".join(lines), encoding="utf-8")


def create_timestamped_output_folder(output_root: Path) -> Path:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = output_root / f"Consolidated_HistoryLog_{timestamp}"
    candidate = base
    counter = 2
    while candidate.exists():
        candidate = output_root / f"{base.name}_{counter}"
        counter += 1
    candidate.mkdir(parents=True, exist_ok=False)
    return candidate


def remove_copied_sidecars(database_path: Path) -> List[Path]:
    removed: List[Path] = []
    for suffix in ("-wal", "-shm"):
        sidecar = Path(str(database_path) + suffix)
        if sidecar.exists():
            sidecar.unlink()
            removed.append(sidecar)
    return removed


def make_copied_file_writable(path: Path) -> None:
    try:
        path.chmod(path.stat().st_mode | stat.S_IREAD | stat.S_IWRITE)
    except OSError as exc:
        raise RuntimeError(f"Unable to make copied working file writable: {path}: {exc}") from exc


def checkpoint_copied_database(database_path: Path) -> str:
    make_copied_file_writable(database_path)
    con = sqlite3.connect(str(database_path), uri=False)
    try:
        con.execute("PRAGMA query_only = OFF")
        con.execute("PRAGMA busy_timeout = 5000")
        row = con.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        journal_mode_row = con.execute("PRAGMA journal_mode=DELETE").fetchone()
        con.commit()
        if row is None:
            raise RuntimeError("Copied database WAL checkpoint returned no result.")
        values = tuple(row)
        if len(values) < 3:
            raise RuntimeError(f"Unexpected copied database WAL checkpoint result: {values}")
        busy, log_frames, checkpointed_frames = values[:3]
        if busy:
            raise RuntimeError(
                "Copied database WAL checkpoint was busy; clean consolidation was not completed."
            )
        journal_mode = journal_mode_row[0] if journal_mode_row else "unknown"
    finally:
        con.close()

    removed_sidecars = remove_copied_sidecars(database_path)
    remaining_sidecars = detect_sidecar_files(database_path)
    if remaining_sidecars:
        raise RuntimeError(
            "Clean consolidation failed; copied WAL/SHM files remain beside the working database: "
            + ", ".join(str(path) for path in remaining_sidecars)
        )

    removed_text = (
        ", ".join(path.name for path in removed_sidecars)
        if removed_sidecars
        else "None present after checkpoint"
    )
    return (
        "PRAGMA wal_checkpoint(TRUNCATE) on copied database => "
        f"busy={busy}, log_frames={log_frames}, checkpointed_frames={checkpointed_frames}; "
        f"PRAGMA journal_mode=DELETE => {journal_mode}; "
        f"removed copied sidecars => {removed_text}; "
        "clean working database verified"
    )


def consolidate_working_copy(
    original_database_path: Path,
    sidecar_files: Sequence[Path],
    output_root: Path,
) -> Tuple[Path, Path, List[Path], str]:
    output_root.mkdir(parents=True, exist_ok=True)
    consolidated_dir = create_timestamped_output_folder(output_root)
    working_database_path = consolidated_dir / original_database_path.name
    shutil.copy2(original_database_path, working_database_path)
    make_copied_file_writable(working_database_path)

    copied_sidecars: List[Path] = []
    for sidecar in sidecar_files:
        copied_sidecar = consolidated_dir / sidecar.name
        shutil.copy2(sidecar, copied_sidecar)
        make_copied_file_writable(copied_sidecar)
        copied_sidecars.append(copied_sidecar)

    checkpoint_result = checkpoint_copied_database(working_database_path)
    write_consolidated_marker(
        consolidated_marker_path(working_database_path),
        original_database_path,
        working_database_path,
        sidecar_files,
    )
    return consolidated_dir, working_database_path, copied_sidecars, checkpoint_result


def normalize_column_name(name: str) -> str:
    return re.sub(r"[^a-z0-9_]+", "", name.lower())


def table_columns(con: sqlite3.Connection, table_name: str) -> List[ColumnInfo]:
    rows = con.execute(f"PRAGMA table_info({quote_identifier(table_name)})").fetchall()
    return [
        ColumnInfo(
            cid=int(row["cid"]),
            name=str(row["name"]),
            declared_type=stringify(row["type"]),
            notnull=bool(row["notnull"]),
            default_value=row["dflt_value"],
            pk=int(row["pk"]),
        )
        for row in rows
    ]


def count_rows(con: sqlite3.Connection, table_name: str) -> int:
    qname = quote_identifier(table_name)
    try:
        return int(con.execute(f"SELECT COUNT(*) AS n FROM {qname}").fetchone()["n"])
    except sqlite3.Error:
        return 0


def fetch_sample_rows(
    con: sqlite3.Connection, table_name: str, limit: int = 250
) -> List[sqlite3.Row]:
    qname = quote_identifier(table_name)
    try:
        return list(con.execute(f"SELECT * FROM {qname} LIMIT ?", (limit,)))
    except sqlite3.Error:
        return []


def structural_hits(text: str) -> Dict[str, bool]:
    return {
        "direction": bool(DIRECTION_RE.search(text)),
        "request": bool(REQUEST_RE.search(text)),
        "count": bool(COUNT_RE.search(text)),
        "total": bool(TOTAL_RE.search(text)),
        "path": bool(PATH_RE.search(text)),
    }


def parse_timestamp_for_sort(value: Any) -> Optional[datetime]:
    raw = stringify(value).strip()
    if not raw:
        return None

    numeric_value: Optional[float] = None
    if isinstance(value, (int, float)):
        numeric_value = float(value)
    elif re.fullmatch(r"\d{10}(\.\d+)?|\d{13}", raw):
        numeric_value = float(raw)

    if numeric_value is not None:
        seconds = numeric_value / 1000 if numeric_value > 10_000_000_000 else numeric_value
        try:
            dt = datetime(1970, 1, 1) + timedelta(seconds=seconds)
        except (OverflowError, OSError, ValueError):
            dt = None
        if dt and 2000 <= dt.year <= 2100:
            return dt

    try:
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            return dt
        return None
    except ValueError:
        pass

    formats = (
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M:%S",
    )
    for fmt in formats:
        try:
            return datetime.strptime(raw, fmt)
        except ValueError:
            continue

    return None


def choose_id_column(columns: Sequence[ColumnInfo]) -> Optional[str]:
    pk_columns = sorted((col for col in columns if col.pk), key=lambda col: col.pk)
    if pk_columns:
        return pk_columns[0].name
    for col in columns:
        if normalize_column_name(col.name) in ID_NAME_HINTS:
            return col.name
    return None


def choose_timestamp_column(
    columns: Sequence[ColumnInfo], rows: Sequence[sqlite3.Row]
) -> Optional[str]:
    scored: List[Tuple[float, str]] = []
    for col in columns:
        name = col.name
        normalized = normalize_column_name(name)
        score = 0.0
        if any(hint in normalized for hint in TIMESTAMP_NAME_HINTS):
            score += 8
        parsed = 0
        non_empty = 0
        for row in rows[:50]:
            value = row[name]
            if stringify(value).strip():
                non_empty += 1
                dt = parse_timestamp_for_sort(value)
                if dt is not None:
                    parsed += 1
        if non_empty:
            score += min(10, parsed * 10 / non_empty)
        if score:
            scored.append((score, name))
    if not scored:
        return None
    scored.sort(key=lambda item: item[0], reverse=True)
    return scored[0][1]


def choose_message_column(
    columns: Sequence[ColumnInfo], rows: Sequence[sqlite3.Row]
) -> Tuple[Optional[str], Dict[str, int]]:
    best: Tuple[float, Optional[str], Dict[str, int]] = (0.0, None, {})
    for col in columns:
        name = col.name
        normalized = normalize_column_name(name)
        counts = {
            "direction": 0,
            "request": 0,
            "count": 0,
            "total": 0,
            "path": 0,
        }
        for row in rows:
            text = stringify(row[name])
            if not text:
                continue
            hits = structural_hits(text)
            for key, found in hits.items():
                counts[key] += int(found)
        score = (
            counts["direction"] * 5
            + counts["request"] * 7
            + counts["count"] * 3
            + counts["total"] * 5
            + counts["path"] * 4
        )
        if normalized in MESSAGE_NAME_HINTS:
            score += 10
        elif any(hint in normalized for hint in MESSAGE_NAME_HINTS):
            score += 5
        if score > best[0]:
            best = (score, name, counts)
    return best[1], best[2]


def choose_tag_column(
    columns: Sequence[ColumnInfo], rows: Sequence[sqlite3.Row], message_column: Optional[str]
) -> Optional[str]:
    scored: List[Tuple[float, str]] = []
    for col in columns:
        if col.name == message_column:
            continue
        normalized = normalize_column_name(col.name)
        score = 0.0
        if normalized in TAG_NAME_HINTS:
            score += 8
        elif any(hint in normalized for hint in TAG_NAME_HINTS):
            score += 4
        values = [stringify(row[col.name]).strip() for row in rows[:100]]
        values = [value for value in values if value]
        distinct = set(values)
        if values and len(distinct) <= max(10, len(values) // 2):
            score += 3
        if score:
            scored.append((score, col.name))
    if not scored:
        return None
    scored.sort(key=lambda item: item[0], reverse=True)
    return scored[0][1]


def inspect_table(con: sqlite3.Connection, name: str, sql: str) -> TableCandidate:
    columns = table_columns(con, name)
    row_count = count_rows(con, name)
    sample_rows = fetch_sample_rows(con, name)
    id_column = choose_id_column(columns)
    timestamp_column = choose_timestamp_column(columns, sample_rows)
    message_column, message_counts = choose_message_column(columns, sample_rows)
    tag_column = choose_tag_column(columns, sample_rows, message_column)

    score = 0.0
    notes: List[str] = []
    if row_count:
        score += 3
    if id_column:
        score += 4
    if timestamp_column:
        score += 8
    if tag_column:
        score += 4
    if message_column:
        score += 12
    score += message_counts.get("direction", 0) * 3
    score += message_counts.get("request", 0) * 4
    score += message_counts.get("total", 0) * 3
    score += message_counts.get("path", 0) * 2

    normalized_columns = {normalize_column_name(col.name) for col in columns}
    preferred_shape = {"id", "timestamp", "tag", "message"}
    if preferred_shape.issubset(normalized_columns):
        score += 15
        notes.append("schema contains id/timestamp/tag/message columns")
    if message_counts.get("direction", 0):
        notes.append("message-like column contains direction patterns")
    if message_counts.get("request", 0):
        notes.append("message-like column contains request patterns")
    if message_counts.get("total", 0) or message_counts.get("path", 0):
        notes.append("message-like column contains result patterns")
    if name.lower().startswith("sqlite_"):
        score -= 30
        notes.append("SQLite internal table deprioritized")

    return TableCandidate(
        name=name,
        sql=sql,
        row_count=row_count,
        columns=columns,
        id_column=id_column,
        timestamp_column=timestamp_column,
        tag_column=tag_column,
        message_column=message_column,
        score=score,
        structural_rows=message_counts.get("direction", 0),
        request_like_rows=message_counts.get("request", 0),
        result_like_rows=message_counts.get("total", 0),
        path_rows=message_counts.get("path", 0),
        notes=notes,
    )


def inspect_database(con: sqlite3.Connection) -> List[TableCandidate]:
    rows = con.execute(
        "SELECT name, sql FROM sqlite_master WHERE type = 'table' ORDER BY name"
    ).fetchall()
    candidates = [inspect_table(con, row["name"], stringify(row["sql"])) for row in rows]
    candidates.sort(key=lambda candidate: candidate.score, reverse=True)
    return candidates


def select_history_table(candidates: Sequence[TableCandidate]) -> TableCandidate:
    if not candidates:
        raise RuntimeError("No SQLite tables found.")
    selected = candidates[0]
    if not selected.message_column:
        raise RuntimeError("No table with a message-like structural column was found.")
    return selected


def fetch_all_rows(
    con: sqlite3.Connection, candidate: TableCandidate
) -> List[Tuple[Optional[Any], sqlite3.Row]]:
    qname = quote_identifier(candidate.name)
    order_column = candidate.id_column
    order_clause = f" ORDER BY {quote_identifier(order_column)}" if order_column else ""
    try:
        rows = con.execute(
            f"SELECT rowid AS __sqlite_rowid__, * FROM {qname}{order_clause}"
        ).fetchall()
        return [(row["__sqlite_rowid__"], row) for row in rows]
    except sqlite3.Error:
        rows = con.execute(f"SELECT * FROM {qname}{order_clause}").fetchall()
        return [(None, row) for row in rows]


def parse_record(
    sequence: int,
    table_name: str,
    database_row_id: Optional[Any],
    row: sqlite3.Row,
    candidate: TableCandidate,
) -> ParsedRecord:
    raw_values = {key: json_safe(row[key]) for key in row.keys() if key != "__sqlite_rowid__"}
    id_value = row[candidate.id_column] if candidate.id_column else database_row_id
    raw_timestamp_value = row[candidate.timestamp_column] if candidate.timestamp_column else ""
    raw_timestamp = stringify(raw_timestamp_value)
    timestamp_sort = parse_timestamp_for_sort(raw_timestamp_value)
    tag = stringify(row[candidate.tag_column]) if candidate.tag_column else ""
    message = stringify(row[candidate.message_column]) if candidate.message_column else ""

    warnings: List[str] = []
    direction_match = DIRECTION_RE.search(message)
    raw_direction = ""
    source_profile_id = None
    destination_profile_id = None
    if direction_match:
        raw_direction = direction_match.group(0)
        source_profile_id = int_or_none(direction_match.group("src"))
        destination_profile_id = int_or_none(direction_match.group("dst"))

    # Request rows observed so far expose the requested item count via the
    # structural "Count : n" token after the direction/app brackets. Do not
    # infer a request count from arbitrary numbers; without a verified
    # language-independent fallback, that would risk inventing evidence.
    request_match = REQUEST_RE.search(message)
    source_app = ""
    requested_count = None
    if request_match:
        source_app = request_match.group("app").strip()
        requested_count = int_or_none(request_match.group("count"))
    else:
        count_match = COUNT_RE.search(message)
        if count_match:
            requested_count = int_or_none(count_match.group("count"))

    total_match = TOTAL_RE.search(message)
    result_total_count = int_or_none(total_match.group("total")) if total_match else None
    paths = [path.strip() for path in PATH_RE.findall(message) if path.strip()]

    result_moved_count = None
    moved_match = LEADING_RESULT_COUNT_RE.search(message)
    if moved_match:
        result_moved_count = int_or_none(moved_match.group("count"))
    elif paths:
        moved_match = LEADING_BRACKET_COUNT_RE.search(message)
        if moved_match:
            result_moved_count = int_or_none(moved_match.group("count"))

    classification = "unknown"
    if direction_match and request_match and requested_count is not None:
        classification = "request"
    elif direction_match and (result_total_count is not None or paths):
        classification = "result"
    else:
        if not direction_match:
            warnings.append("no direction pattern found")
        if direction_match and requested_count is None and result_total_count is None and not paths:
            warnings.append("direction found but no request/result structural pattern")
        if direction_match and requested_count is not None and not source_app:
            warnings.append("count found without source app bracket")

    if (
        classification == "result"
        and result_moved_count is None
        and result_total_count is not None
    ):
        result_moved_count = result_total_count

    return ParsedRecord(
        sequence=sequence,
        table_name=table_name,
        database_row_id=database_row_id,
        id_value=json_safe(id_value),
        raw_values=raw_values,
        raw_timestamp=raw_timestamp,
        timestamp_sort=timestamp_sort,
        tag=tag,
        raw_message=message,
        classification=classification,
        raw_direction=raw_direction,
        source_profile_id=source_profile_id,
        destination_profile_id=destination_profile_id,
        source_app=source_app,
        requested_count=requested_count,
        result_total_count=result_total_count,
        result_moved_count=result_moved_count,
        paths=paths,
        warnings=warnings,
    )


def event_sort_key(event: Event) -> Tuple[int, str, int]:
    record = event.primary_record()
    dt = record.timestamp_sort
    if dt is None:
        return (1, "", record.sequence)
    return (0, dt.isoformat(), record.sequence)


def record_sort_key(record: ParsedRecord) -> Tuple[int, str, int]:
    dt = record.timestamp_sort
    if dt is None:
        return (1, "", record.sequence)
    return (0, dt.isoformat(), record.sequence)


def seconds_between(left: ParsedRecord, right: ParsedRecord) -> Optional[float]:
    left_dt = left.timestamp_sort
    right_dt = right.timestamp_sort
    if left_dt is None or right_dt is None:
        return None
    return (right_dt - left_dt).total_seconds()


def pairing_score(
    request: ParsedRecord,
    result: ParsedRecord,
    max_pair_seconds: int,
) -> Optional[float]:
    if request.raw_direction != result.raw_direction:
        return None
    delta = seconds_between(request, result)
    if delta is not None:
        if delta < 0 or delta > max_pair_seconds:
            return None
        score = max(0.0, max_pair_seconds - delta)
    else:
        if result.sequence < request.sequence:
            return None
        score = 1.0

    if request.requested_count is not None and result.result_total_count is not None:
        if request.requested_count == result.result_total_count:
            score += 500
        else:
            score -= min(200, abs(request.requested_count - result.result_total_count) * 5)
    if request.requested_count is not None and result.result_moved_count is not None:
        if request.requested_count == result.result_moved_count:
            score += 200
    score -= max(0, result.sequence - request.sequence) * 0.01
    return score


def pair_records(
    records: Sequence[ParsedRecord], max_pair_seconds: int = 30 * 60
) -> List[Event]:
    sorted_records = sorted(records, key=record_sort_key)
    events: List[Event] = []
    pending_requests: List[ParsedRecord] = []
    event_id = 1

    for record in sorted_records:
        if record.classification == "request":
            pending_requests.append(record)
            continue

        if record.classification == "result":
            best_index = None
            best_score = None
            for index, request in enumerate(pending_requests):
                score = pairing_score(request, record, max_pair_seconds)
                if score is None:
                    continue
                if best_score is None or score > best_score:
                    best_index = index
                    best_score = score
            if best_index is not None:
                request = pending_requests.pop(best_index)
                events.append(
                    Event(
                        event_id=event_id,
                        status="paired",
                        request=request,
                        result=record,
                    )
                )
            else:
                events.append(
                    Event(
                        event_id=event_id,
                        status="unpaired_result",
                        result=record,
                        warnings=["no prior matching request record found"],
                    )
                )
            event_id += 1
            continue

        events.append(
            Event(
                event_id=event_id,
                status="unknown",
                unknown=record,
                warnings=record.warnings or ["record did not match request/result patterns"],
            )
        )
        event_id += 1

    for request in pending_requests:
        events.append(
            Event(
                event_id=event_id,
                status="unpaired_request",
                request=request,
                warnings=["no later matching result record found"],
            )
        )
        event_id += 1

    events.sort(key=event_sort_key)
    for index, event in enumerate(events, start=1):
        event.event_id = index
    return events


def path_field_value(paths: Sequence[str]) -> str:
    return "\n".join(paths) if paths else PATH_FIELD_NA


def derive_source_paths_from_transferred_path(event: Event) -> List[str]:
    direction_record = event.request or event.result or event.unknown
    if direction_record is None:
        return []
    source_profile_id = direction_record.source_profile_id
    destination_profile_id = direction_record.destination_profile_id
    if source_profile_id is None or destination_profile_id is None:
        return []

    destination_prefix = f"/storage/emulated/{destination_profile_id}/"
    source_prefix = f"/storage/emulated/{source_profile_id}/"
    derived_paths: List[str] = []
    for transferred_path in event_result_paths(event):
        if transferred_path.startswith(destination_prefix):
            derived_paths.append(source_prefix + transferred_path[len(destination_prefix) :])
    return derived_paths


def assign_event_path_fields(events: Sequence[Event]) -> None:
    for event in events:
        request_paths = event_request_paths(event)
        result_paths = event_result_paths(event)
        event.transferred_path = path_field_value(result_paths)

        if request_paths:
            event.source_path = path_field_value(request_paths)
            event.source_path_note = SOURCE_PATH_EXTRACTED_NOTE
            continue

        derived_paths = derive_source_paths_from_transferred_path(event)
        if derived_paths:
            event.source_path = path_field_value(derived_paths)
            event.source_path_note = SOURCE_PATH_DERIVED_NOTE
            continue

        event.source_path = PATH_FIELD_NA
        event.source_path_note = SOURCE_PATH_UNAVAILABLE_NOTE


def parse_records(con: sqlite3.Connection, candidate: TableCandidate) -> List[ParsedRecord]:
    rows = fetch_all_rows(con, candidate)
    records: List[ParsedRecord] = []
    for sequence, (database_row_id, row) in enumerate(rows, start=1):
        records.append(parse_record(sequence, candidate.name, database_row_id, row, candidate))
    return records


def cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return "\n".join(stringify(item) for item in value)
    return stringify(value)


def event_request_paths(event: Event) -> List[str]:
    return list(event.request.paths) if event.request else []


def event_result_paths(event: Event) -> List[str]:
    return list(event.result.paths) if event.result else []


def event_all_path_evidence(event: Event) -> List[str]:
    paths: List[str] = []
    if event.request:
        paths.extend(event.request.paths)
    if event.result:
        paths.extend(event.result.paths)
    if event.unknown:
        paths.extend(event.unknown.paths)
    return paths


def path_evidence_cell(paths: Sequence[str]) -> str:
    return cell(list(paths)) if paths else "N/A"


def event_to_csv_row(event: Event) -> Dict[str, str]:
    request = event.request
    result = event.result
    unknown = event.unknown
    primary = event.primary_record()

    def count_value(value: Optional[int]) -> str:
        return str(value) if value is not None else PATH_FIELD_NA

    def note_value(value: str) -> str:
        return value if value else PATH_FIELD_NA

    status_text = "Paired Event"
    status_note = ""
    if event.status == "unpaired_request":
        status_text = "Unpaired Request"
        status_note = "A request record was found, but no matching result record was identified."
    elif event.status == "unpaired_result":
        status_text = "Unpaired Result"
        status_note = "A result record was found, but no matching request record was identified."
    elif event.status == "unknown":
        status_text = "Unknown Event"
        status_note = "This record did not match the expected request/result structure."

    return {
        "Event": str(event.event_id),
        "Event Type": "File Transfer",
        "Status": status_text,
        "Status Note": status_note or PATH_FIELD_NA,
        "Request Time": cell(request.raw_timestamp if request else PATH_FIELD_NA),
        "Result Time": cell(result.raw_timestamp if result else PATH_FIELD_NA),
        "Duration": report_event_duration(event),
        "Direction": cell(primary.raw_direction or report_direction_summary(primary)),
        "Source App": cell(request.source_app if request and request.source_app else PATH_FIELD_NA),
        "Requested Count": count_value(request.requested_count if request else None),
        "Moved Count": count_value(result.result_moved_count if result else None),
        "Source Path": cell(event.source_path or PATH_FIELD_NA),
        "Transferred Path": cell(event.transferred_path or PATH_FIELD_NA),
        "Source Path Note": note_value(event.source_path_note),
        "Warnings": "; ".join(report_event_warnings(event)) or PATH_FIELD_NA,
    }


CSV_FIELDS = [
    "Event",
    "Event Type",
    "Status",
    "Status Note",
    "Request Time",
    "Result Time",
    "Duration",
    "Source App",
    "Direction",
    "Requested Count",
    "Moved Count",
    "Source Path",
    "Transferred Path",
    "Source Path Note",
    "Warnings",
]


def write_csv(events: Sequence[Event], path: Path) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for event in events:
            writer.writerow(event_to_csv_row(event))


def html_escape(value: Any) -> str:
    return html.escape(cell(value), quote=True)


def report_path_values(value: str) -> List[str]:
    if not value or value == PATH_FIELD_NA:
        return []
    return [path for path in value.splitlines() if path]


def report_event_record(event: Event) -> ParsedRecord:
    return event.request or event.result or event.unknown or event.primary_record()


def report_event_duration(event: Event) -> str:
    if not event.request or not event.result:
        return PATH_FIELD_NA
    delta = seconds_between(event.request, event.result)
    if delta is None or delta < 0:
        return PATH_FIELD_NA
    if delta < 1:
        return "<1 sec"
    rounded = int(round(delta))
    if rounded < 60:
        return f"{rounded} sec"
    minutes, remaining_seconds = divmod(rounded, 60)
    return f"{minutes} min {remaining_seconds} sec"


def report_event_warnings(event: Event) -> List[str]:
    warnings = list(event.warnings)
    if event.request:
        warnings.extend(event.request.warnings)
    if event.result:
        warnings.extend(event.result.warnings)
    if event.unknown:
        warnings.extend(event.unknown.warnings)
    return list(dict.fromkeys(warnings))


def report_direction_summary(record: ParsedRecord) -> str:
    if record.source_profile_id is not None and record.destination_profile_id is not None:
        return f"{record.source_profile_id} \u2192 {record.destination_profile_id}"
    return record.raw_direction or PATH_FIELD_NA


def write_html_report(result: ParseResult, path: Path) -> None:
    total_events = len(result.events)
    complete_events = sum(1 for event in result.events if event.status == "paired")
    requested_items = sum(
        event.request.requested_count
        for event in result.events
        if event.request and event.request.requested_count is not None
    )
    moved_items = sum(
        event.result.result_moved_count
        for event in result.events
        if event.result and event.result.result_moved_count is not None
    )
    applications = sorted(
        {
            event.request.source_app
            for event in result.events
            if event.request and event.request.source_app
        },
        key=str.casefold,
    )
    applications_text = ", ".join(applications) if applications else PATH_FIELD_NA
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    request_times: List[Tuple[datetime, str]] = []
    latest_times: List[Tuple[datetime, str]] = []
    for event in result.events:
        if event.request:
            request_time = event.request.timestamp_sort
            if request_time is not None:
                request_times.append((request_time, event.request.raw_timestamp))
        latest_record = event.result or event.request or event.unknown
        if latest_record:
            latest_time = latest_record.timestamp_sort
            if latest_time is not None:
                latest_times.append((latest_time, latest_record.raw_timestamp))
    request_times.sort(key=lambda item: item[0])
    latest_times.sort(key=lambda item: item[0])
    earliest_event = request_times[0][1] if request_times else PATH_FIELD_NA
    latest_event = latest_times[-1][1] if latest_times else PATH_FIELD_NA
    date_range = (
        f"{earliest_event} \u2192 {latest_event}"
        if request_times and latest_times
        else PATH_FIELD_NA
    )

    def count_text(value: Optional[int]) -> str:
        return str(value) if value is not None else PATH_FIELD_NA

    def path_heading(label: str, paths: Sequence[str]) -> str:
        return f"{label}s ({len(paths)})" if len(paths) > 1 else label

    def render_plain_paths(paths: Sequence[str]) -> str:
        if not paths:
            return '<p class="empty-value">N/A</p>'
        return "".join(f'<p class="path-line">{html_escape(path)}</p>' for path in paths)

    event_nav_items: List[str] = []
    event_detail_sections: List[str] = []
    for index, event in enumerate(result.events):
        request = event.request
        result_record = event.result
        primary = report_event_record(event)
        source_paths = report_path_values(event.source_path)
        transferred_paths = report_path_values(event.transferred_path)
        requested_count = request.requested_count if request else None
        moved_count = result_record.result_moved_count if result_record else None
        source_app = request.source_app if request and request.source_app else PATH_FIELD_NA
        request_time = request.raw_timestamp if request else PATH_FIELD_NA
        result_time = result_record.raw_timestamp if result_record else PATH_FIELD_NA
        warning_items = report_event_warnings(event)
        warnings_html = ""
        if warning_items:
            warnings_html = (
                '<section class="detail-section warnings"><h3>Warnings</h3><ul>'
                + "".join(f"<li>{html_escape(warning)}</li>" for warning in warning_items)
                + "</ul></section>"
            )
        source_note_html = ""
        if event.source_path_note and event.source_path_note != PATH_FIELD_NA:
            source_note_html = (
                '<section class="detail-section">'
                '<h3>Source Path Note</h3>'
                f'<p>{html_escape(event.source_path_note)}</p>'
                '</section>'
        )
        active_class = " active" if index == 0 else ""
        event_nav_items.append(
            f"""
      <button type="button" class="event-list-item{active_class}" data-event-id="event-{event.event_id}">
        <span class="event-row-number">{event.event_id}</span>
        <span class="event-row-app">{html_escape(source_app)}</span>
        <span class="event-row-time">{html_escape(request_time)}</span>
      </button>"""
        )
        event_detail_sections.append(
            f"""
      <article id="event-{event.event_id}" class="event-detail{active_class}">
        <h2>Event {event.event_id}</h2>
        <section class="detail-section">
          <dl class="detail-grid">
            <div><dt>Request Time</dt><dd>{html_escape(request_time)}</dd></div>
            <div><dt>Result Time</dt><dd>{html_escape(result_time)}</dd></div>
            <div><dt>Duration</dt><dd>{html_escape(report_event_duration(event))}</dd></div>
            <div><dt>Application</dt><dd>{html_escape(source_app)}</dd></div>
            <div><dt>Direction</dt><dd>{html_escape(primary.raw_direction or report_direction_summary(primary))}</dd></div>
            <div><dt>Requested Count</dt><dd>{html_escape(count_text(requested_count))}</dd></div>
            <div><dt>Moved Count</dt><dd>{html_escape(count_text(moved_count))}</dd></div>
          </dl>
        </section>
        <section class="detail-section paths">
          <h3>{html_escape(path_heading("Source Path", source_paths))}</h3>
          {render_plain_paths(source_paths)}
        </section>
        <section class="detail-section paths">
          <h3>{html_escape(path_heading("Transferred Path", transferred_paths))}</h3>
          {render_plain_paths(transferred_paths)}
        </section>
        {source_note_html}
        {warnings_html}
        <section class="info-note">
          <h3>About Transferred Items</h3>
          <p>This database records folder-level transfers only. Individual file names are not available in Samsung Secure Folder HistoryLog.</p>
        </section>
      </article>"""
        )

    report_warnings_html = ""
    if result.warnings:
        report_warnings_html = (
            '<section class="summary-warnings"><h3>Report Warnings</h3><ul>'
            + "".join(f"<li>{html_escape(warning)}</li>" for warning in result.warnings)
            + "</ul></section>"
        )

    no_events_html = ""
    if not result.events:
        no_events_html = '<p class="empty-value">No transfer events were found.</p>'

    event_count_label = f"{total_events} event" if total_events == 1 else f"{total_events} events"

    document = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Samsung Secure Folder HistoryLog Forensic Report</title>
  <style>
    * {{
      box-sizing: border-box;
    }}
    body {{
      margin: 0;
      font-family: "Segoe UI", Arial, Helvetica, sans-serif;
      color: #1f2937;
      background: #f7f8fa;
      line-height: 1.5;
    }}
    .report-header {{
      background: #ffffff;
      border-bottom: 1px solid #d9dee7;
      padding: 24px 32px 20px;
    }}
    h1 {{
      margin: 0 0 14px;
      color: #111827;
      font-size: 25px;
      font-weight: 650;
      letter-spacing: -0.01em;
    }}
    h2, h3, h4 {{
      margin-top: 0;
    }}
    .header-meta {{
      margin-top: 12px;
      color: #667085;
      font-size: 12px;
      overflow-wrap: anywhere;
    }}
    .summary-strip {{
      display: flex;
      flex-wrap: wrap;
      gap: 18px 32px;
      margin: 0;
      padding: 0;
    }}
    .summary-strip div {{
      min-width: 130px;
    }}
    .summary-strip dt {{
      color: #667085;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: .04em;
      text-transform: uppercase;
    }}
    .summary-strip dd {{
      margin: 3px 0 0;
      color: #111827;
      font-size: 15px;
      font-weight: 650;
      overflow-wrap: anywhere;
    }}
    .viewer {{
      display: grid;
      grid-template-columns: minmax(260px, 25%) minmax(0, 1fr);
      min-height: calc(100vh - 112px);
    }}
    .left-panel {{
      border-right: 1px solid #d5dbe5;
      background: #fff;
      overflow-y: auto;
      padding: 18px 16px;
    }}
    .right-panel {{
      overflow-y: auto;
      padding: 34px 42px 54px;
    }}
    .nav-header {{
      margin-bottom: 14px;
    }}
    .nav-header h2 {{
      margin: 0 0 2px;
      color: #111827;
      font-size: 16px;
    }}
    .event-count {{
      margin: 0;
      color: #667085;
      font-size: 13px;
    }}
    .summary-warnings {{
      margin-top: 14px;
      padding: 12px 0 0;
      border-top: 1px solid #e5e7eb;
      color: #7f1d1d;
      font-size: 13px;
    }}
    .summary-warnings h3 {{
      margin-bottom: 6px;
      font-size: 14px;
    }}
    .summary-warnings ul {{
      margin: 0;
      padding-left: 18px;
    }}
    .event-list-item {{
      display: grid;
      grid-template-columns: 36px minmax(68px, 1fr) minmax(120px, 1.6fr);
      gap: 8px;
      align-items: baseline;
      width: 100%;
      margin: 0;
      padding: 9px 4px;
      text-align: left;
      color: #1f2937;
      background: #fff;
      border: 0;
      border-bottom: 1px solid #eef1f5;
      cursor: pointer;
    }}
    .event-list-item:hover,
    .event-list-item:focus {{
      background: #f8fafc;
      outline: none;
    }}
    .event-list-item.active {{
      background: #eef2f7;
    }}
    .event-row-number {{
      color: #111827;
      font-weight: 700;
    }}
    .event-row-app {{
      color: #111827;
      font-weight: 600;
      overflow-wrap: anywhere;
    }}
    .event-row-time {{
      color: #667085;
      font-size: 15px;
    }}
    .show-more-events {{
      display: none;
      width: 100%;
      margin-top: 12px;
      padding: 9px 10px;
      color: #1f2937;
      background: #fff;
      border: 1px solid #cfd6e1;
      border-radius: 6px;
      font-size: 13px;
      cursor: pointer;
    }}
    .show-more-events.visible {{
      display: block;
    }}
    .show-more-events:hover,
    .show-more-events:focus {{
      border-color: #475569;
      outline: none;
    }}
    .event-detail {{
      display: none;
      max-width: 980px;
      padding: 0;
    }}
    .event-detail.active {{
      display: block;
    }}
    .event-detail h2 {{
      margin-bottom: 24px;
      padding-bottom: 13px;
      border-bottom: 1px solid #d9dee7;
      font-size: 26px;
      color: #111827;
    }}
    .detail-section {{
      padding: 0 0 24px;
      margin-bottom: 24px;
      border-bottom: 1px solid #e5e7eb;
    }}
    .detail-grid {{
      display: grid;
      grid-template-columns: repeat(2, minmax(220px, 1fr));
      gap: 16px 38px;
      margin: 0;
    }}
    .detail-grid dt {{
      color: #5b6678;
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
    }}
    .detail-grid dd {{
      margin: 3px 0 0;
      color: #111827;
      font-weight: 620;
      overflow-wrap: anywhere;
    }}
    .detail-section h3 {{
      margin-bottom: 10px;
      color: #111827;
      font-size: 17px;
    }}
    .detail-section p {{
      margin: 0 0 8px;
      overflow-wrap: anywhere;
    }}
    .path-line {{
      font-family: Consolas, "Courier New", monospace;
      font-size: 13px;
      line-height: 1.55;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      word-break: break-word;
    }}
    .empty-value {{
      margin: 0;
      color: #6b7280;
      font-style: italic;
    }}
    .warnings {{
      color: #7f1d1d;
    }}
    .warnings ul {{
      margin: 0;
      padding-left: 20px;
    }}
    .info-note {{
      max-width: 980px;
      margin-top: 30px;
      padding: 14px 16px;
      color: #475569;
      background: #f8fafc;
      border-left: 3px solid #94a3b8;
      font-size: 13px;
    }}
    .info-note h3 {{
      margin: 0 0 5px;
      color: #334155;
      font-size: 14px;
    }}
    .info-note p {{
      margin: 0;
    }}
    .noscript {{
      margin: 0 0 16px;
      padding: 10px 12px;
      color: #7c2d12;
      background: #fff7ed;
      border: 1px solid #fed7aa;
      border-radius: 6px;
    }}
    @media print {{
      body {{ background: #fff; }}
      .report-header {{ padding: 0 0 18px; border-bottom: 1px solid #bbb; }}
      .viewer {{ display: block; }}
      .left-panel {{ display: none; }}
      .right-panel {{ padding: 0; }}
      .event-detail {{ display: block; max-width: none; margin-bottom: 32px; break-inside: avoid; }}
      .event-detail h2 {{ break-after: avoid; }}
      .path-line {{ white-space: pre-wrap; overflow-wrap: anywhere; }}
      .show-more-events {{ display: none; }}
    }}
    @media (max-width: 900px) {{
      .viewer {{ grid-template-columns: 1fr; }}
      .left-panel {{ border-right: 0; border-bottom: 1px solid #d5dbe5; }}
      .right-panel {{ padding: 20px; }}
      .detail-grid {{ grid-template-columns: 1fr; }}
    }}
  </style>
  <noscript>
    <style>
      .event-detail {{
        display: block;
        margin-bottom: 28px;
      }}
    </style>
  </noscript>
</head>
<body>
<header class="report-header">
  <h1>Samsung Secure Folder HistoryLog Forensic Report</h1>
  <dl class="summary-strip">
    <div><dt>Total Events</dt><dd>{total_events}</dd></div>
    <div><dt>Requested Items</dt><dd>{requested_items}</dd></div>
    <div><dt>Moved Items</dt><dd>{moved_items}</dd></div>
    <div><dt>Date Range</dt><dd>{html_escape(date_range)}</dd></div>
    <div><dt>Applications Observed</dt><dd>{html_escape(applications_text)}</dd></div>
    <div><dt>Report Generated</dt><dd>{html_escape(generated_at)}</dd></div>
  </dl>
  <div class="header-meta">Database: {html_escape(str(result.database_path))}</div>
</header>
<main class="viewer">
  <aside class="left-panel">
    <section class="nav-header">
      <h2>Events</h2>
      <p class="event-count">{html_escape(event_count_label)}</p>
      {report_warnings_html}
    </section>
    <section class="events-list">
      {no_events_html}
      <div id="event-list">
        {''.join(event_nav_items)}
      </div>
      <button type="button" class="show-more-events" id="show-more-events">Show More Events</button>
    </section>
  </aside>
  <section class="right-panel">
    <noscript><p class="noscript">JavaScript is disabled. All event details are shown below for review.</p></noscript>
    {''.join(event_detail_sections)}
  </section>
</main>
<script>
  (function () {{
    var buttons = document.querySelectorAll('.event-list-item');
    var details = document.querySelectorAll('.event-detail');
    var showMore = document.getElementById('show-more-events');
    var visibleLimit = 80;
    var batchSize = 80;
    function selectEvent(id) {{
      buttons.forEach(function (button) {{
        button.classList.toggle('active', button.getAttribute('data-event-id') === id);
      }});
      details.forEach(function (detail) {{
        detail.classList.toggle('active', detail.id === id);
      }});
    }}
    function refreshList() {{
      buttons.forEach(function (button) {{
        button.hidden = true;
      }});
      Array.prototype.slice.call(buttons, 0, visibleLimit).forEach(function (button) {{
        button.hidden = false;
      }});
      if (showMore) {{
        showMore.classList.toggle('visible', buttons.length > visibleLimit);
      }}
      var activeVisible = Array.prototype.some.call(buttons, function (button) {{
        return button.classList.contains('active') && !button.hidden;
      }});
      if (!activeVisible && buttons.length) {{
        selectEvent(buttons[0].getAttribute('data-event-id'));
      }}
    }}
    buttons.forEach(function (button) {{
      button.addEventListener('click', function () {{
        selectEvent(button.getAttribute('data-event-id'));
      }});
    }});
    if (showMore) {{
      showMore.addEventListener('click', function () {{
        visibleLimit += batchSize;
        refreshList();
      }});
    }}
    if (buttons.length) {{
      selectEvent(buttons[0].getAttribute('data-event-id'));
    }}
    refreshList();
  }}());
</script>
</body>
</html>
"""
    path.write_text(document, encoding="utf-8")


def safe_output_stem(path: Path) -> str:
    stem = re.sub(r'[<>:"/\\|?*\x00-\x1f]+', "_", path.stem).strip(" ._")
    return stem or "historylog"


def safe_report_name(value: str, database_path: Path) -> str:
    requested_name = Path(value.strip()).stem if value.strip() else database_path.stem
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]+', "_", requested_name).strip(" ._")
    return name or safe_output_stem(database_path)


def parse_database(
    database_path: Path,
    output_dir: Path,
    max_pair_seconds: int = 30 * 60,
    original_database_path: Optional[Path] = None,
    detected_sidecar_files: Optional[Sequence[Path]] = None,
    user_choice: str = "",
    consolidation_performed: bool = False,
    checkpoint_result: str = "Not performed",
    log_path: Optional[Path] = None,
    report_name: str = "",
    write_reports: bool = True,
) -> ParseResult:
    database_path = database_path.resolve()
    output_dir = output_dir.resolve()
    original_database_path = (
        original_database_path.resolve() if original_database_path else database_path
    )
    detected_sidecar_files = [path.resolve() for path in (detected_sidecar_files or [])]
    if write_reports:
        output_dir.mkdir(parents=True, exist_ok=True)
    warnings: List[str] = []

    with closing(open_readonly_database(database_path)) as con:
        candidates = inspect_database(con)
        selected = select_history_table(candidates)
        if selected.score <= 0:
            warnings.append("selected table has a low structural score")
        records = parse_records(con, selected)
        events = pair_records(records, max_pair_seconds=max_pair_seconds)
        assign_event_path_fields(events)

    unknown_count = sum(1 for record in records if record.classification == "unknown")
    if unknown_count:
        warnings.append(f"{unknown_count} raw record(s) could not be classified structurally")
    unpaired_count = sum(1 for event in events if event.status.startswith("unpaired"))
    if unpaired_count:
        warnings.append(f"{unpaired_count} request/result record(s) remained unpaired")

    stem = safe_report_name(report_name, database_path)
    csv_path = output_dir / f"{stem}.csv"
    html_path = output_dir / f"{stem}.html"
    result = ParseResult(
        database_path=database_path,
        output_dir=output_dir,
        selected_table=selected,
        candidates=list(candidates),
        records=records,
        events=events,
        warnings=warnings,
        csv_path=csv_path,
        html_path=html_path,
        log_path=log_path,
        original_database_path=original_database_path,
        detected_sidecar_files=list(detected_sidecar_files),
        user_choice=user_choice,
        consolidation_performed=consolidation_performed,
        working_database_path=database_path,
        checkpoint_result=checkpoint_result,
    )
    if write_reports:
        write_csv(events, csv_path)
        write_html_report(result, html_path)
    return result


def process_database_workflow(
    database_path: Path,
    output_dir: Path,
    user_choice: str = CHOICE_PARSE_ORIGINAL,
    max_pair_seconds: int = 30 * 60,
    sidecar_files: Optional[Sequence[Path]] = None,
    report_name: str = "",
    write_reports: bool = True,
) -> ParseResult:
    original_database_path = database_path.resolve()
    output_dir = output_dir.resolve()
    already_consolidated = is_consolidated_working_copy(original_database_path)
    detected_sidecars = (
        []
        if already_consolidated
        else [
            path.resolve()
            for path in (
                sidecar_files
                if sidecar_files is not None
                else detect_sidecar_files(database_path)
            )
        ]
    )
    workflow_choice = ALREADY_CONSOLIDATED_MESSAGE if already_consolidated else user_choice

    if user_choice == CHOICE_CANCEL:
        raise RuntimeError("Processing canceled by user.")

    working_database_path = original_database_path
    parse_output_dir = output_dir
    consolidation_performed = False
    checkpoint_result = "Not performed"

    if not already_consolidated and user_choice == CHOICE_CONSOLIDATE:
        (
            consolidated_dir,
            working_database_path,
            _copied_sidecars,
            checkpoint_result,
        ) = consolidate_working_copy(
            original_database_path,
            detected_sidecars,
            output_dir,
        )
        parse_output_dir = consolidated_dir
        consolidation_performed = True

    return parse_database(
        working_database_path,
        parse_output_dir,
        max_pair_seconds=max_pair_seconds,
        original_database_path=original_database_path,
        detected_sidecar_files=detected_sidecars,
        user_choice=workflow_choice,
        consolidation_performed=consolidation_performed,
        checkpoint_result=checkpoint_result,
        report_name=report_name,
        write_reports=write_reports,
    )


def event_detail_text(event: Event) -> str:
    request = event.request
    result = event.result
    primary = event.primary_record()
    duration = PATH_FIELD_NA
    if request and result:
        delta = seconds_between(request, result)
        if delta is not None and delta >= 0:
            if delta < 1:
                duration = "<1 sec"
            else:
                rounded = int(round(delta))
                if rounded < 60:
                    duration = f"{rounded} sec"
                else:
                    minutes, remaining_seconds = divmod(rounded, 60)
                    duration = f"{minutes} min {remaining_seconds} sec"

    warnings: List[str] = list(event.warnings)
    if request:
        warnings.extend(request.warnings)
    if result:
        warnings.extend(result.warnings)
    if event.unknown:
        warnings.extend(event.unknown.warnings)
    unique_warnings = list(dict.fromkeys(warnings))

    status_text = "Paired Event"
    status_note = ""
    if event.status == "unpaired_request":
        status_text = "Unpaired Request"
        status_note = "A request record was found, but no matching result record was identified."
    elif event.status == "unpaired_result":
        status_text = "Unpaired Result"
        status_note = "A result record was found, but no matching request record was identified."
    elif event.status == "unknown":
        status_text = "Unknown Event"
        status_note = "This record did not match the expected request/result structure."

    lines = [
        "Selected Event",
        "",
        "Event: File Transfer",
        f"Status: {status_text}",
    ]
    if status_note:
        lines.extend(["", status_note])
    lines.extend(
        [
        "",
        "Timeline",
        f"Request Time: {cell(request.raw_timestamp if request else '') or PATH_FIELD_NA}",
        f"Result Time: {cell(result.raw_timestamp if result else '') or PATH_FIELD_NA}",
        f"Duration: {duration}",
        "",
        "Transfer Details",
        f"Source App: {cell(request.source_app if request else '') or PATH_FIELD_NA}",
        f"Direction: {cell(primary.raw_direction) or PATH_FIELD_NA}",
        f"Requested Count: {cell(request.requested_count if request else '') or PATH_FIELD_NA}",
        f"Moved Count: {cell(result.result_moved_count if result else '') or PATH_FIELD_NA}",
        "",
        "Source Path",
        event.source_path or PATH_FIELD_NA,
        "",
        "Transferred Path",
        event.transferred_path or PATH_FIELD_NA,
        ]
    )
    if event.source_path_note and event.source_path_note != PATH_FIELD_NA:
        lines.extend(["", "Source Path Note", event.source_path_note])

    if unique_warnings:
        lines.extend(["", "Warnings"])
        lines.extend(unique_warnings)
    return "\n".join(lines)


def launch_gui() -> int:
    try:
        from PySide6.QtCore import Qt, QUrl
        from PySide6.QtGui import QAction, QDesktopServices
        from PySide6.QtWidgets import (
            QAbstractItemView,
            QApplication,
            QFileDialog,
            QHeaderView,
            QMainWindow,
            QMenu,
            QMessageBox,
            QPlainTextEdit,
            QSizePolicy,
            QSplitter,
            QTableWidget,
            QTableWidgetItem,
            QVBoxLayout,
            QWidget,
        )
    except ImportError as exc:
        print(
            "PySide6 is required for GUI mode. Run with a database path for CLI mode, "
            f"or install PySide6. Import error: {exc}",
            file=sys.stderr,
        )
        return 2

    SORT_ROLE = Qt.ItemDataRole.UserRole.value
    ROW_INDEX_ROLE = SORT_ROLE + 1
    TABLE_COLUMNS = [
        "Event",
        "Request Time",
        "Result Time",
        "Direction",
        "Source App",
        "Source Path",
        "Requested Count",
        "Duration",
        "Moved Count",
        "Transferred Path",
    ]
    COLUMN_EVENT = 0
    COLUMN_SOURCE_PATH = 5
    COLUMN_TRANSFERRED_PATH = 9

    # Fixed per-column widths sized to the header label / typical field, NOT to
    # the longest cell value. Long values (especially file paths) are elided and
    # shown in full via the cell tooltip and the details panel on selection.
    COLUMN_WIDTHS = [
        60,   # Event
        150,  # Request Time
        150,  # Result Time
        90,   # Direction
        120,  # Source App
        240,  # Source Path
        120,  # Requested Count
        90,   # Duration
        100,  # Moved Count
        240,  # Transferred Path
    ]

    class SortableTableWidgetItem(QTableWidgetItem):
        def __lt__(self, other: QTableWidgetItem) -> bool:
            left = self.data(SORT_ROLE)
            right = other.data(SORT_ROLE)
            if left is not None and right is not None:
                return left < right
            if left is not None:
                return True
            if right is not None:
                return False
            return self.text().casefold() < other.text().casefold()

    class MainWindow(QMainWindow):
        def __init__(self) -> None:
            super().__init__()
            self.setWindowTitle("Samsung Secure Folder HistoryLog Parser")
            self.resize(1250, 820)
            self.result: Optional[ParseResult] = None
            self.events: List[Event] = []
            self.detected_sidecars: List[Path] = []
            self.selected_database_is_consolidated = False
            self.active_database_path: Optional[Path] = None
            self.last_output_dir = default_gui_output_dir()
            self.last_report_path: Optional[Path] = None

            file_menu = self.menuBar().addMenu("File")
            self.open_database_action = QAction("Open Database...", self)
            self.open_database_action.triggered.connect(self.choose_database)
            self.save_report_action = QAction("Save Report...", self)
            self.save_report_action.setEnabled(False)
            self.save_report_action.triggered.connect(self.save_report)
            self.open_output_action = QAction("Open Output Folder", self)
            self.open_output_action.setEnabled(False)
            self.open_output_action.triggered.connect(self.open_output_folder)
            self.reset_action = QAction("Close Database", self)
            self.reset_action.triggered.connect(self.reset_form)
            self.exit_action = QAction("Exit", self)
            self.exit_action.triggered.connect(self.close)
            file_menu.addAction(self.open_database_action)
            file_menu.addAction(self.save_report_action)
            file_menu.addAction(self.open_output_action)
            file_menu.addSeparator()
            file_menu.addAction(self.reset_action)
            file_menu.addSeparator()
            file_menu.addAction(self.exit_action)

            help_menu = self.menuBar().addMenu("Help")
            about_action = QAction("About", self)
            about_action.triggered.connect(self.show_about_dialog)
            help_menu.addAction(about_action)

            root = QWidget()
            self.setCentralWidget(root)
            layout = QVBoxLayout(root)

            self.statusBar().showMessage(STATUS_READY)

            splitter = QSplitter(Qt.Vertical)
            splitter.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
            layout.addWidget(splitter, 1)

            self.table = QTableWidget(0, len(TABLE_COLUMNS))
            self.table.setHorizontalHeaderLabels(list(TABLE_COLUMNS))
            # Column widths come from COLUMN_WIDTHS, never from cell content.
            # Interactive mode lets the examiner drag to resize but never
            # auto-fits a column to its longest value.
            header = self.table.horizontalHeader()
            header.setSectionResizeMode(QHeaderView.Interactive)
            header.setSectionsMovable(True)
            header.setMinimumSectionSize(48)
            header.setDefaultSectionSize(110)
            for column, width in enumerate(COLUMN_WIDTHS):
                self.table.setColumnWidth(column, width)
            # Transferred Path stretches to consume any leftover width so no
            # empty band is painted to the right of the table. It benefits most
            # from extra room; every other column keeps its fixed width and the
            # columns after it stay pinned to the right edge.
            header.setStretchLastSection(False)
            header.setSectionResizeMode(COLUMN_TRANSFERRED_PATH, QHeaderView.Stretch)
            # Lock row height so a long value can never grow a row.
            vheader = self.table.verticalHeader()
            vheader.setSectionResizeMode(QHeaderView.Fixed)
            vheader.setDefaultSectionSize(24)
            vheader.setMinimumSectionSize(24)
            self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
            self.table.setSelectionMode(QAbstractItemView.SingleSelection)
            self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
            self.table.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
            self.table.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
            self.table.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
            self.table.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
            self.table.setWordWrap(False)
            self.table.setTextElideMode(Qt.ElideRight)
            self.table.setFocusPolicy(Qt.StrongFocus)
            self.table.setSortingEnabled(True)
            self.table.setContextMenuPolicy(Qt.CustomContextMenu)
            self.table.itemSelectionChanged.connect(self.update_detail_panel)
            self.table.customContextMenuRequested.connect(self.show_table_context_menu)
            self.table.cellDoubleClicked.connect(self.focus_detail_from_table)
            splitter.addWidget(self.table)

            self.detail = QPlainTextEdit()
            self.detail.setReadOnly(True)
            self.detail.setLineWrapMode(QPlainTextEdit.WidgetWidth)
            splitter.addWidget(self.detail)
            splitter.setSizes([750, 250])

        def set_status(self, message: str) -> None:
            self.statusBar().showMessage(message)

        def show_about_dialog(self) -> None:
            QMessageBox.information(
                self,
                "About",
                "Samsung Secure Folder HistoryLog Forensic Parser\n\n"
                f"Version {APP_VERSION}\n\n"
                "This parser is provided to assist the digital forensic community.\n\n"
                "Results should be independently validated.\n\n"
                "Source evidence files are not modified.",
            )

        def choose_database(self) -> None:
            path, _ = QFileDialog.getOpenFileName(
                self,
                "Select file to analyze",
                "",
                "All files (*.*);;SQLite databases (*.db *.sqlite *.sqlite3)",
            )
            if path:
                self.handle_database_selection(Path(path))

        def update_action_states(self) -> None:
            self.save_report_action.setEnabled(self.result is not None)
            self.open_output_action.setEnabled(
                self.last_report_path is not None and self.last_report_path.exists()
            )

        def clear_current_results(self) -> None:
            self.result = None
            self.events = []
            self.table.setRowCount(0)
            self.detail.clear()
            self.last_report_path = None
            self.update_action_states()

        def clear_database_selection(self, status_message: str = STATUS_READY) -> None:
            self.active_database_path = None
            self.detected_sidecars = []
            self.selected_database_is_consolidated = False
            self.clear_current_results()
            self.set_status(status_message)

        def set_active_database(
            self,
            database_path: Path,
            status_message: str = STATUS_READY,
        ) -> None:
            self.active_database_path = database_path
            self.selected_database_is_consolidated = is_consolidated_working_copy(
                database_path
            )
            self.detected_sidecars = (
                []
                if self.selected_database_is_consolidated
                else detect_sidecar_files(database_path)
            )
            self.clear_current_results()
            self.set_status(status_message)

        def show_sidecar_dialog(self, database_path: Path, sidecars: Sequence[Path]) -> bool:
            dialog = QMessageBox(self)
            dialog.setIcon(QMessageBox.Warning)
            dialog.setWindowTitle(SIDECAR_DIALOG_TITLE)
            dialog.setText(SIDECAR_DIALOG_MESSAGE)
            create_button = dialog.addButton("Create Clean Copy", QMessageBox.AcceptRole)
            cancel_button = dialog.addButton("Cancel", QMessageBox.RejectRole)
            dialog.setDefaultButton(create_button)
            dialog.setEscapeButton(cancel_button)
            dialog.exec()
            return dialog.clickedButton() == create_button

        def create_clean_copy_from_selection(
            self,
            source_database_path: Path,
            sidecars: Sequence[Path],
        ) -> Optional[Path]:
            selected_output = QFileDialog.getExistingDirectory(
                self,
                "Select folder to save clean database copy",
                str(self.last_output_dir),
            )
            if not selected_output:
                return None

            output_root = Path(selected_output).resolve()
            self.last_output_dir = output_root
            source_database_path = source_database_path.resolve()
            detected_sidecars = [path.resolve() for path in sidecars]
            self.open_database_action.setEnabled(False)
            self.save_report_action.setEnabled(False)
            self.reset_action.setEnabled(False)
            self.open_output_action.setEnabled(False)
            self.set_status(STATUS_CONSOLIDATING)
            QApplication.processEvents()
            try:
                (
                    consolidated_dir,
                    working_database_path,
                    _copied_sidecars,
                    _checkpoint_result,
                ) = consolidate_working_copy(
                    source_database_path,
                    detected_sidecars,
                    output_root,
                )
            except Exception:
                QMessageBox.critical(
                    self,
                    "Clean Copy Could Not Be Created",
                    "The clean working copy could not be created. "
                    "Please choose another folder and try again.",
                )
                self.set_status(STATUS_READY)
                return None
            finally:
                self.open_database_action.setEnabled(True)
                self.reset_action.setEnabled(True)
                self.update_action_states()

            self.last_output_dir = consolidated_dir
            self.set_active_database(working_database_path, STATUS_CLEAN_COPY_SUCCESS)
            QMessageBox.information(
                self,
                "Database Ready",
                "A clean working copy was created and loaded successfully.\n\n"
                "Original files were not modified.",
            )
            self.set_status(STATUS_CLEAN_COPY_SUCCESS)
            return working_database_path

        def handle_database_selection(self, database_path: Path) -> None:
            database_path = database_path.resolve()
            if not database_path.exists():
                QMessageBox.warning(self, "Missing database", "Select an existing database file.")
                self.clear_database_selection()
                return

            if not is_sqlite_database(database_path):
                QMessageBox.warning(
                    self,
                    "Not a SQLite Database",
                    "The selected file is not a valid SQLite database.\n\n"
                    "Samsung Secure Folder HistoryLog data is stored in a SQLite "
                    "database. Please select a valid database file.\n\n"
                    "The selected file was not modified.",
                )
                self.clear_database_selection(STATUS_NOT_A_DATABASE)
                return

            if is_consolidated_working_copy(database_path):
                self.set_active_database(database_path, STATUS_DATABASE_SELECTED)
                self.process_active_database(STATUS_PARSING)
                return

            sidecars = detect_sidecar_files(database_path)
            if not sidecars:
                self.set_active_database(database_path, STATUS_DATABASE_SELECTED)
                self.process_active_database(STATUS_PARSING)
                return

            self.set_status(STATUS_SIDECARS_DETECTED)
            if not self.show_sidecar_dialog(database_path, sidecars):
                self.clear_database_selection(STATUS_SELECTION_CANCELED)
                return

            clean_database_path = self.create_clean_copy_from_selection(database_path, sidecars)
            if clean_database_path is None:
                self.clear_database_selection(STATUS_SELECTION_CANCELED)
                return
            self.process_active_database(STATUS_CLEAN_COPY_PROCESSING)

        def open_output_folder(self) -> None:
            if self.last_report_path is None:
                return
            opened = QDesktopServices.openUrl(
                QUrl.fromLocalFile(str(self.last_report_path.parent))
            )
            if not opened:
                QMessageBox.warning(
                    self,
                    "Output Folder Could Not Be Opened",
                    "The output folder could not be opened. "
                    "Please open it manually from the saved report location.",
                )
                self.set_status(STATUS_OUTPUT_OPEN_FAILED)
                return
            self.set_status(STATUS_OUTPUT_OPENED)

        def reset_form(self) -> None:
            self.active_database_path = None
            self.last_output_dir = default_gui_output_dir()
            self.last_report_path = None
            self.result = None
            self.events = []
            self.detected_sidecars = []
            self.selected_database_is_consolidated = False
            self.table.setRowCount(0)
            self.detail.clear()
            self.update_action_states()
            self.set_status(STATUS_READY)

        def process_active_database(self, status_message: str = STATUS_PARSING) -> None:
            if self.active_database_path is None:
                QMessageBox.warning(self, "Missing database", "Select an existing database file.")
                return
            db_path = self.active_database_path
            self.selected_database_is_consolidated = is_consolidated_working_copy(db_path)
            self.detected_sidecars = (
                []
                if self.selected_database_is_consolidated
                else detect_sidecar_files(db_path)
            )
            if self.detected_sidecars:
                self.handle_database_selection(db_path)
                return

            user_choice = CHOICE_PARSE_ORIGINAL
            self.open_database_action.setEnabled(False)
            self.save_report_action.setEnabled(False)
            self.reset_action.setEnabled(False)
            self.open_output_action.setEnabled(False)
            self.set_status(status_message)
            QApplication.processEvents()
            try:
                self.result = process_database_workflow(
                    db_path,
                    self.last_output_dir,
                    user_choice=user_choice,
                    sidecar_files=self.detected_sidecars,
                    report_name=safe_output_stem(db_path),
                    write_reports=False,
                )
            except Exception as exc:
                QMessageBox.critical(self, "Parser error", str(exc))
                self.set_status(STATUS_READY)
                return
            finally:
                self.open_database_action.setEnabled(True)
                self.reset_action.setEnabled(True)
                self.update_action_states()
            self.events = list(self.result.events)
            self.populate_table()
            self.last_report_path = None
            self.update_action_states()
            self.set_status(STATUS_DATABASE_PROCESSED)
            QApplication.processEvents()
            self.set_status(STATUS_READY_TO_SAVE_REPORT)

        def save_report(self) -> None:
            if self.result is None:
                QMessageBox.warning(self, "No processed database", "Open a database first.")
                return
            suggested_path = self.last_report_path or (
                self.last_output_dir / DEFAULT_REPORT_FILENAME
            )
            selected_report, _ = QFileDialog.getSaveFileName(
                self,
                "Save Report",
                str(suggested_path),
                "HTML report (*.html);;All files (*.*)",
            )
            if not selected_report:
                return
            html_path = Path(selected_report).resolve()
            if html_path.suffix.lower() != ".html":
                html_path = html_path.with_suffix(".html")
            csv_path = html_path.with_suffix(".csv")

            previous_output_dir = self.result.output_dir
            previous_html_path = self.result.html_path
            previous_csv_path = self.result.csv_path
            try:
                html_path.parent.mkdir(parents=True, exist_ok=True)
                self.result.output_dir = html_path.parent
                self.result.html_path = html_path
                self.result.csv_path = csv_path
                write_csv(self.result.events, csv_path)
                write_html_report(self.result, html_path)
            except Exception as exc:
                self.result.output_dir = previous_output_dir
                self.result.html_path = previous_html_path
                self.result.csv_path = previous_csv_path
                QMessageBox.critical(
                    self,
                    "Report Could Not Be Saved",
                    "The report could not be saved. "
                    "Please choose another location and try again.\n\n"
                    f"Details: {exc}",
                )
                self.set_status(STATUS_SAVE_FAILED)
                self.update_action_states()
                return

            self.last_output_dir = html_path.parent
            self.last_report_path = html_path
            self.update_action_states()
            self.set_status(STATUS_SUCCESS)

        def event_duration_seconds(self, event: Event) -> Optional[float]:
            if not event.request or not event.result:
                return None
            request_time = event.request.timestamp_sort or parse_timestamp_for_sort(
                event.request.raw_timestamp
            )
            result_time = event.result.timestamp_sort or parse_timestamp_for_sort(
                event.result.raw_timestamp
            )
            if request_time is None or result_time is None:
                return None
            duration = (result_time - request_time).total_seconds()
            if duration < 0:
                return None
            return duration

        def format_duration(self, seconds: Optional[float]) -> str:
            if seconds is None:
                return ""
            if seconds < 1:
                return "<1 sec"
            rounded = int(round(seconds))
            if rounded < 60:
                return f"{rounded} sec"
            minutes, remaining_seconds = divmod(rounded, 60)
            return f"{minutes} min {remaining_seconds} sec"

        def display_path_field(self, value: str) -> str:
            return (value or PATH_FIELD_NA).replace("\n", " | ")

        def make_table_item(
            self,
            value: Any,
            row_index: int,
            sort_value: Optional[Any] = None,
        ) -> QTableWidgetItem:
            item = SortableTableWidgetItem(cell(value))
            item.setData(SORT_ROLE, sort_value)
            item.setData(ROW_INDEX_ROLE, row_index)
            item.setToolTip(cell(value))
            return item

        def populate_table(self) -> None:
            self.table.setSortingEnabled(False)
            self.table.setRowCount(len(self.events))
            for row_index, event in enumerate(self.events):
                request = event.request
                result = event.result
                primary = event.primary_record()
                duration_seconds = self.event_duration_seconds(event)
                values = [
                    (event.event_id, event.event_id),
                    (request.raw_timestamp if request else "", request.timestamp_sort if request else None),
                    (result.raw_timestamp if result else "", result.timestamp_sort if result else None),
                    (primary.raw_direction, None),
                    (request.source_app if request else "", None),
                    (self.display_path_field(event.source_path), None),
                    (
                        request.requested_count if request else "",
                        request.requested_count if request and request.requested_count is not None else None,
                    ),
                    (self.format_duration(duration_seconds), duration_seconds),
                    (
                        result.result_moved_count if result and result.result_moved_count is not None else "",
                        result.result_moved_count if result and result.result_moved_count is not None else None,
                    ),
                    (self.display_path_field(event.transferred_path), None),
                ]
                for column, (value, sort_value) in enumerate(values):
                    item = self.make_table_item(value, row_index, sort_value)
                    if column == COLUMN_SOURCE_PATH:
                        item.setToolTip(event.source_path or PATH_FIELD_NA)
                    elif column == COLUMN_TRANSFERRED_PATH:
                        item.setToolTip(event.transferred_path or PATH_FIELD_NA)
                    self.table.setItem(row_index, column, item)
            self.table.setSortingEnabled(True)
            if self.events:
                self.table.selectRow(0)

        def table_row_values(self, row: int) -> List[str]:
            values: List[str] = []
            for column in range(len(TABLE_COLUMNS)):
                item = self.table.item(row, column)
                values.append(item.text() if item else "")
            return values

        def selected_table_rows(self) -> List[int]:
            rows = sorted({index.row() for index in self.table.selectedIndexes()})
            current_row = self.table.currentRow()
            if not rows and current_row >= 0:
                rows = [current_row]
            return rows

        def table_headers(self) -> List[str]:
            headers: List[str] = []
            for column in range(len(TABLE_COLUMNS)):
                item = self.table.horizontalHeaderItem(column)
                headers.append(item.text() if item else "")
            return headers

        def copy_to_clipboard(self, text: str) -> None:
            QApplication.clipboard().setText(text)

        def copy_current_cell(self) -> None:
            item = self.table.currentItem()
            if item:
                self.copy_to_clipboard(item.text())

        def copy_row(self, row: int) -> None:
            if row < 0:
                return
            text = "\t".join(self.table_headers()) + "\n" + "\t".join(
                self.table_row_values(row)
            )
            self.copy_to_clipboard(text)

        def copy_selected_rows(self) -> None:
            rows = self.selected_table_rows()
            if not rows:
                return
            lines = ["\t".join(self.table_headers())]
            lines.extend("\t".join(self.table_row_values(row)) for row in rows)
            self.copy_to_clipboard("\n".join(lines))

        def event_index_for_table_row(self, row: int) -> Optional[int]:
            if row < 0:
                return None
            item = self.table.item(row, COLUMN_EVENT)
            if item is None:
                return None
            row_index = item.data(ROW_INDEX_ROLE)
            return int(row_index) if row_index is not None else None

        def copy_event_path_field(self, field_name: str) -> None:
            rows = self.selected_table_rows()
            values: List[str] = []
            for row in rows:
                event_index = self.event_index_for_table_row(row)
                if event_index is None:
                    continue
                value = getattr(self.events[event_index], field_name, PATH_FIELD_NA)
                values.append(value or PATH_FIELD_NA)
            self.copy_to_clipboard("\n".join(values))

        def show_table_context_menu(self, position) -> None:
            index = self.table.indexAt(position)
            if index.isValid():
                selected_rows = set(self.selected_table_rows())
                if index.row() not in selected_rows:
                    self.table.selectRow(index.row())
                self.table.setCurrentCell(index.row(), index.column())

            menu = QMenu(self)
            copy_cell_action = menu.addAction("Copy Cell")
            copy_row_action = menu.addAction("Copy Row")
            copy_selected_rows_action = menu.addAction("Copy Selected Rows")
            menu.addSeparator()
            copy_source_path_action = menu.addAction("Copy Source Path")
            copy_transferred_path_action = menu.addAction("Copy Transferred Path")

            current_row = self.table.currentRow()
            selected = menu.exec(self.table.viewport().mapToGlobal(position))
            if selected == copy_cell_action:
                self.copy_current_cell()
            elif selected == copy_row_action:
                self.copy_row(current_row)
            elif selected == copy_selected_rows_action:
                self.copy_selected_rows()
            elif selected == copy_source_path_action:
                self.copy_event_path_field("source_path")
            elif selected == copy_transferred_path_action:
                self.copy_event_path_field("transferred_path")

        def focus_detail_from_table(self, row: int, _column: int) -> None:
            self.table.selectRow(row)
            self.update_detail_panel()
            self.detail.setFocus(Qt.MouseFocusReason)

        def update_detail_panel(self) -> None:
            items = self.table.selectedItems()
            row_index = None
            if items:
                row_index = items[0].data(ROW_INDEX_ROLE)
            else:
                current_row = self.table.currentRow()
                if current_row >= 0:
                    row_index = self.event_index_for_table_row(current_row)
            if row_index is None:
                return
            self.detail.setPlainText(event_detail_text(self.events[int(row_index)]))

    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    return app.exec()


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Parse Samsung Secure Folder HistoryLog SQLite databases using schema "
            "and structural record patterns, not localized message language."
        )
    )
    parser.add_argument(
        "database",
        nargs="?",
        help="Path to the HistoryLog SQLite database. If omitted, GUI mode starts.",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        default=".",
        help="Folder for the HTML report and CSV export.",
    )
    parser.add_argument(
        "--report-name",
        default="",
        help="Base file name used for both the HTML report and CSV export.",
    )
    parser.add_argument(
        "--max-pair-seconds",
        type=int,
        default=30 * 60,
        help="Maximum time gap for request/result pairing when timestamps parse safely.",
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Start the PySide6 GUI even if other arguments are present.",
    )
    parser.add_argument(
        "--consolidate-copy",
        action="store_true",
        help=(
            "Create a timestamped working-copy folder, copy the database and any "
            "matching WAL/SHM sidecars, checkpoint the copied database, then parse it."
        ),
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    if args.gui or not args.database:
        return launch_gui()

    database_path = Path(args.database)
    if not database_path.exists():
        print(f"Error: file not found: '{database_path}'", file=sys.stderr)
        return 2
    if not is_sqlite_database(database_path):
        print(
            f"Error: '{database_path}' is not a valid SQLite database. "
            "The specified file was not modified.",
            file=sys.stderr,
        )
        return 2
    output_dir = Path(args.output_dir)
    already_consolidated = is_consolidated_working_copy(database_path)
    sidecars = [] if already_consolidated else detect_sidecar_files(database_path)
    user_choice = CHOICE_CONSOLIDATE if args.consolidate_copy else CHOICE_PARSE_ORIGINAL
    if already_consolidated:
        print(ALREADY_CONSOLIDATED_MESSAGE)
    elif sidecars and not args.consolidate_copy:
        print(WAL_SHM_WARNING)
        print("CLI mode will parse the original database read-only unless --consolidate-copy is used.")
    result = process_database_workflow(
        database_path,
        output_dir,
        user_choice=user_choice,
        max_pair_seconds=args.max_pair_seconds,
        sidecar_files=sidecars,
        report_name=args.report_name,
    )
    paired = sum(1 for event in result.events if event.status == "paired")
    unpaired = sum(1 for event in result.events if event.status.startswith("unpaired"))
    unknown = sum(1 for event in result.events if event.status == "unknown")

    print(f"Selected table: {result.selected_table.name}")
    print(f"Records scanned: {len(result.records)}")
    print(f"Events: {len(result.events)} (paired={paired}, unpaired={unpaired}, unknown={unknown})")
    print(f"CSV: {result.csv_path}")
    print(f"HTML: {result.html_path}")
    if result.warnings:
        print("Warnings:")
        for warning in result.warnings:
            print(f"  - {warning}")
    return 0


if __name__ == "__main__":
    if running_as_frozen():
        import multiprocessing

        multiprocessing.freeze_support()
    raise SystemExit(main())
