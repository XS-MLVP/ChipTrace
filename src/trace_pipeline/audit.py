from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

from .model import validate_envelope


def audit_root(
    root: Path,
    *,
    ledger_path: Path | None = None,
    verify_payloads: bool = True,
) -> dict[str, Any]:
    root = Path(root).resolve()
    database = Path(ledger_path).resolve() if ledger_path else root / "state" / "capture-ledger.sqlite"
    if not database.exists() and ledger_path is None:
        # Compatibility with the repository's initial layout.
        database = root / "capture-ledger.sqlite"
    conn = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    failures: list[str] = []
    checked_records = 0
    checked_bytes = 0
    try:
        integrity = str(conn.execute("PRAGMA integrity_check").fetchone()[0])
        foreign_rows = len(conn.execute("PRAGMA foreign_key_check").fetchall())
        segments = conn.execute("SELECT * FROM segments ORDER BY segment_id").fetchall()
        for segment in segments:
            path = root / str(segment["path"])
            if not path.is_file():
                failures.append(f"missing_segment:{segment['segment_id']}:{path}")
                continue
            actual_size = path.stat().st_size
            if actual_size != int(segment["bytes"]):
                failures.append(f"segment_size:{segment['segment_id']}:{actual_size}!={segment['bytes']}")
            if segment["state"] in {"sealed", "archived"}:
                digest = _file_sha256(path)
                if digest != segment["sha256"]:
                    failures.append(f"segment_sha256:{segment['segment_id']}")
            rows = conn.execute(
                "SELECT capture_id,raw_sha256,offset,length FROM captures WHERE segment_id=? ORDER BY offset,capture_id",
                (segment["segment_id"],),
            ).fetchall()
            if len(rows) != int(segment["records"]):
                failures.append(f"segment_records:{segment['segment_id']}:{len(rows)}!={segment['records']}")
            expected_offset = 0
            for row in rows:
                if int(row["offset"]) != expected_offset:
                    failures.append(
                        f"segment_gap:{segment['segment_id']}:{expected_offset}!={row['offset']}"
                    )
                expected_offset = int(row["offset"]) + int(row["length"])
            if expected_offset != actual_size:
                failures.append(
                    f"segment_tail:{segment['segment_id']}:{expected_offset}!={actual_size}"
                )
            if not verify_payloads:
                continue
            with path.open("rb") as handle:
                for row in rows:
                    handle.seek(int(row["offset"]))
                    line = handle.read(int(row["length"]))
                    checked_records += 1
                    checked_bytes += len(line)
                    if len(line) != int(row["length"]) or not line.endswith(b"\n"):
                        failures.append(f"locator:{row['capture_id']}")
                        continue
                    raw = line[:-1]
                    if hashlib.sha256(raw).hexdigest() != row["raw_sha256"]:
                        failures.append(f"payload_sha256:{row['capture_id']}")
                        continue
                    try:
                        value = json.loads(raw, parse_constant=_reject_json_constant)
                        validate_envelope(value)
                    except (ValueError, TypeError, json.JSONDecodeError):
                        failures.append(f"payload_json:{row['capture_id']}")
                        continue
                    if value.get("captureId") != row["capture_id"]:
                        failures.append(f"payload_identity:{row['capture_id']}")
        duplicate_capture_ids = int(conn.execute(
            "SELECT count(*) FROM (SELECT capture_id FROM captures GROUP BY capture_id HAVING count(*)>1)"
        ).fetchone()[0])
        attempts = {str(row[0]): int(row[1]) for row in conn.execute(
            "SELECT state,count(*) FROM capture_attempts GROUP BY state"
        )}
        captures = int(conn.execute("SELECT count(*) FROM captures").fetchone()[0])
        orphan_captures = int(conn.execute(
            "SELECT count(*) FROM captures c WHERE NOT EXISTS (SELECT 1 FROM capture_attempts a WHERE a.capture_id=c.capture_id AND a.state IN ('accepted','recovered'))"
        ).fetchone()[0])
        if duplicate_capture_ids:
            failures.append(f"duplicate_capture_ids:{duplicate_capture_ids}")
        if orphan_captures:
            failures.append(f"captures_without_commit_attempt:{orphan_captures}")
        return {
            "ok": integrity == "ok" and foreign_rows == 0 and not failures,
            "integrity_check": integrity,
            "foreign_key_rows": foreign_rows,
            "captures": captures,
            "segments": len(segments),
            "attempt_states": attempts,
            "checked_records": checked_records,
            "checked_bytes": checked_bytes,
            "failures": failures[:100],
            "failure_count": len(failures),
        }
    finally:
        conn.close()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")
