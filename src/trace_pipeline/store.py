from __future__ import annotations

import hashlib
import json
import os
import queue
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .model import (
    CAPTURE_ENVELOPE_SCHEMA_VERSION,
    SUPPORTED_RECORD_VERSIONS,
    canonical_envelope,
    envelope_metadata,
    utc_now,
    validate_envelope,
)


LEDGER_SCHEMA_VERSION = "capture-ledger-v1"


class StoreError(RuntimeError):
    pass


class RecoveryError(StoreError):
    pass


@dataclass(frozen=True)
class StoreConfig:
    root: Path
    state_root: Path | None = None
    segment_max_bytes: int = 512 * 1024 * 1024
    queue_max_items: int = 2048
    batch_records: int = 64
    batch_wait_ms: int = 25
    segment_max_age_seconds: int = 3600
    fsync_each_batch: bool = True
    max_envelope_bytes: int = 1024 * 1024 * 1024
    sqlite_journal_mode: str = "WAL"


@dataclass(frozen=True)
class CaptureResult:
    capture_id: str
    state: str
    duplicate: bool
    segment_id: int | None = None
    offset: int | None = None
    length: int | None = None
    raw_sha256: str | None = None


@dataclass
class _Task:
    value: dict[str, Any]
    raw: bytes
    digest: str
    done: threading.Event
    result: CaptureResult | None = None
    error: BaseException | None = None


SCHEMA = """
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS schema_migrations (
  version TEXT PRIMARY KEY,
  applied_at TEXT NOT NULL
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS segments (
  segment_id INTEGER PRIMARY KEY,
  path TEXT NOT NULL UNIQUE,
  state TEXT NOT NULL CHECK (state IN ('open','sealed','archived','quarantined')),
  created_at TEXT NOT NULL,
  sealed_at TEXT,
  bytes INTEGER NOT NULL DEFAULT 0,
  records INTEGER NOT NULL DEFAULT 0,
  sha256 TEXT,
  last_offset INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS captures (
  capture_id TEXT PRIMARY KEY,
  raw_sha256 TEXT NOT NULL,
  segment_id INTEGER NOT NULL,
  offset INTEGER NOT NULL,
  length INTEGER NOT NULL,
  received_at TEXT,
  started_at TEXT,
  finished_at TEXT,
  model TEXT,
  inbound_path TEXT,
  proxied_path TEXT,
  api_key_fingerprint TEXT,
  response_status INTEGER,
  request_truncated INTEGER NOT NULL DEFAULT 0,
  response_truncated INTEGER NOT NULL DEFAULT 0,
  capture_error TEXT,
  stream INTEGER NOT NULL DEFAULT 0,
  imported_at TEXT NOT NULL,
  source TEXT NOT NULL DEFAULT 'capture_http',
  FOREIGN KEY(segment_id) REFERENCES segments(segment_id)
);
CREATE INDEX IF NOT EXISTS captures_hash_idx ON captures(raw_sha256);
CREATE INDEX IF NOT EXISTS captures_time_idx ON captures(received_at,capture_id);
CREATE TABLE IF NOT EXISTS capture_attempts (
  attempt_id INTEGER PRIMARY KEY,
  capture_id TEXT,
  raw_sha256 TEXT,
  state TEXT NOT NULL,
  reason TEXT,
  received_at TEXT NOT NULL,
  committed_at TEXT,
  segment_id INTEGER,
  FOREIGN KEY(segment_id) REFERENCES segments(segment_id)
);
CREATE INDEX IF NOT EXISTS attempts_capture_idx ON capture_attempts(capture_id,attempt_id);
CREATE TABLE IF NOT EXISTS audit_events (
  event_id INTEGER PRIMARY KEY,
  event_type TEXT NOT NULL,
  detail_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);
"""


class CaptureStore:
    """Single-writer, durable, idempotent capture store.

    The HTTP side only enqueues validated envelopes. One writer owns both the
    append file descriptor and the SQLite connection, so NFS never sees
    concurrent SQLite writers. A batch is durable before its waiters receive a
    successful result.
    """

    def __init__(self, config: StoreConfig):
        self.config = config
        self.root = Path(config.root).resolve()
        self.segments_dir = self.root / "segments"
        self.state_dir = Path(config.state_root).resolve() if config.state_root else self.root / "state"
        self.db_path = self.state_dir / "capture-ledger.sqlite"
        self.segments_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.root, 0o700)
        os.chmod(self.state_dir, 0o700)
        journal_mode = config.sqlite_journal_mode.upper()
        if journal_mode not in {"WAL", "DELETE"}:
            raise ValueError("sqlite_journal_mode must be WAL or DELETE")
        filesystem_type = _filesystem_type(self.state_dir)
        if journal_mode == "WAL" and filesystem_type in {"nfs", "nfs4", "cifs", "smbfs"}:
            raise StoreError(
                f"SQLite WAL state cannot be placed on {filesystem_type}; "
                "set state_root to a local persistent filesystem or use DELETE journal mode"
            )
        self._lock = threading.RLock()
        self._stats_lock = threading.Lock()
        self._queue: queue.Queue[_Task | None] = queue.Queue(maxsize=config.queue_max_items)
        self._stop = threading.Event()
        self._ready = False
        self._fatal: BaseException | None = None
        self._active_segment_id: int | None = None
        self._active_handle: Any = None
        self._active_bytes = 0
        self._active_records = 0
        self._active_started_monotonic = time.monotonic()
        self._last_error: str | None = None
        self._stats = {
            "submitted": 0,
            "accepted": 0,
            "duplicates": 0,
            "recovered": 0,
            "rejected": 0,
            "failed": 0,
            "sealed": 0,
        }
        self._conn = sqlite3.connect(
            self.db_path,
            timeout=30,
            check_same_thread=False,
            isolation_level=None,
        )
        active_journal = str(self._conn.execute(f"PRAGMA journal_mode={journal_mode}").fetchone()[0]).upper()
        if active_journal != journal_mode:
            self._conn.close()
            raise StoreError(f"SQLite journal mode is {active_journal}, expected {journal_mode}")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute("PRAGMA busy_timeout=30000")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA temp_store=MEMORY")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT NOT NULL) WITHOUT ROWID"
        )
        current_ledger = self._meta_value("ledger_schema_version")
        legacy_version = self._meta_value("schema_version")
        if current_ledger is not None and current_ledger != LEDGER_SCHEMA_VERSION:
            self._conn.close()
            raise StoreError(
                f"unsupported ledger schema {current_ledger!r}; expected {LEDGER_SCHEMA_VERSION!r}"
            )
        if current_ledger is None and legacy_version is not None and legacy_version not in SUPPORTED_RECORD_VERSIONS:
            self._conn.close()
            raise StoreError(f"cannot migrate unknown legacy ledger schema {legacy_version!r}")
        self._conn.executescript(SCHEMA)
        self._conn.execute(
            "INSERT INTO meta(key,value) VALUES('ledger_schema_version',?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (LEDGER_SCHEMA_VERSION,),
        )
        self._conn.execute(
            "INSERT INTO meta(key,value) VALUES('capture_envelope_schema_version',?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (CAPTURE_ENVELOPE_SCHEMA_VERSION,),
        )
        self._conn.execute(
            "INSERT INTO schema_migrations(version,applied_at) VALUES(?,?) ON CONFLICT(version) DO NOTHING",
            (LEDGER_SCHEMA_VERSION, utc_now()),
        )
        self._conn.execute(
            "INSERT INTO meta(key,value) VALUES('created_at',?) ON CONFLICT(key) DO NOTHING",
            (utc_now(),),
        )
        self._conn.commit()
        try:
            self._recover()
            self._open_active_segment()
            self._ready = True
        except BaseException as exc:
            self._fatal = exc
            self._last_error = str(exc)
            self._conn.close()
            raise
        self._thread = threading.Thread(target=self._writer_loop, name="trace-capture-writer", daemon=True)
        self._thread.start()

    def _meta_value(self, key: str) -> str | None:
        row = self._conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return str(row[0]) if row is not None else None

    @property
    def ready(self) -> bool:
        return self._ready and self._fatal is None

    def submit(self, value: dict[str, Any], timeout: float | None = 30.0) -> CaptureResult:
        if not self.ready:
            raise StoreError(f"capture store is not ready: {self._last_error or 'starting'}")
        validate_envelope(value)
        raw, digest = canonical_envelope(value)
        if len(raw) > self.config.max_envelope_bytes:
            raise ValueError(f"capture envelope exceeds {self.config.max_envelope_bytes} bytes")
        return self._submit_task(value, raw, digest, timeout)

    def submit_raw(
        self,
        raw: bytes,
        *,
        value: dict[str, Any] | None = None,
        timeout: float | None = 30.0,
    ) -> CaptureResult:
        if not self.ready:
            raise StoreError(f"capture store is not ready: {self._last_error or 'starting'}")
        if len(raw) > self.config.max_envelope_bytes:
            raise ValueError(f"capture envelope exceeds {self.config.max_envelope_bytes} bytes")
        if value is None:
            value = json.loads(raw)
        validate_envelope(value)
        normalized = raw.strip()
        # The spool format is NDJSON. The current relay emits one compact JSON
        # object; pretty-printed compatibility clients are canonicalized once.
        if b"\n" in normalized or b"\r" in normalized:
            normalized, digest = canonical_envelope(value)
        else:
            digest = hashlib.sha256(normalized).hexdigest()
        return self._submit_task(value, normalized, digest, timeout)

    def _submit_task(
        self,
        value: dict[str, Any],
        raw: bytes,
        digest: str,
        timeout: float | None,
    ) -> CaptureResult:
        task = _Task(value=value, raw=raw, digest=digest, done=threading.Event())
        with self._stats_lock:
            self._stats["submitted"] += 1
        try:
            self._queue.put(task, timeout=timeout)
        except queue.Full as exc:
            with self._stats_lock:
                self._stats["failed"] += 1
            raise StoreError("capture queue is full") from exc
        if not task.done.wait(timeout):
            raise TimeoutError("capture durability acknowledgement timed out")
        if task.error is not None:
            raise task.error
        assert task.result is not None
        return task.result

    def close(self, timeout: float = 30.0) -> None:
        if not getattr(self, "_thread", None):
            self._conn.close()
            return
        self._ready = False
        self._stop.set()
        self._queue.put(None, timeout=timeout)
        self._thread.join(timeout=timeout)
        if self._thread.is_alive():
            raise TimeoutError("capture writer did not stop")
        with self._lock:
            self._seal_active()
            self._conn.commit()
            self._conn.close()

    def record_rejection(
        self,
        reason: str,
        *,
        capture_id: str | None = None,
        raw_sha256: str | None = None,
    ) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO capture_attempts(capture_id,raw_sha256,state,reason,received_at) "
                "VALUES(?,?,?,?,?)",
                (capture_id, raw_sha256, "rejected", reason[:300], utc_now()),
            )
            with self._stats_lock:
                self._stats["rejected"] += 1

    def health(self) -> dict[str, Any]:
        with self._lock:
            segments = self._conn.execute("SELECT state,count(*),coalesce(sum(bytes),0) FROM segments GROUP BY state").fetchall()
            counts = {str(row[0]): {"count": int(row[1]), "bytes": int(row[2])} for row in segments}
            captures = int(self._conn.execute("SELECT count(*) FROM captures").fetchone()[0])
            attempts = int(self._conn.execute("SELECT count(*) FROM capture_attempts").fetchone()[0])
            attempt_states = {
                str(row[0]): int(row[1])
                for row in self._conn.execute("SELECT state,count(*) FROM capture_attempts GROUP BY state")
            }
            with self._stats_lock:
                stats = dict(self._stats)
            return {
                "ok": self.ready,
                "ready": self.ready,
                "schema_version": LEDGER_SCHEMA_VERSION,
                "ledger_schema_version": LEDGER_SCHEMA_VERSION,
                "capture_envelope_schema_version": CAPTURE_ENVELOPE_SCHEMA_VERSION,
                "db": str(self.db_path),
                "data_root": str(self.root),
                "state_root": str(self.state_dir),
                "sqlite_journal_mode": self.config.sqlite_journal_mode.upper(),
                "queue_depth": self._queue.qsize(),
                "queue_capacity": self.config.queue_max_items,
                "captures": captures,
                "attempts": attempts,
                "attempt_states": attempt_states,
                "segments": counts,
                "active_segment_id": self._active_segment_id,
                "last_error": self._last_error,
                "stats": stats,
            }

    def audit(self) -> dict[str, Any]:
        with self._lock:
            integrity = str(self._conn.execute("PRAGMA integrity_check").fetchone()[0])
            foreign = len(self._conn.execute("PRAGMA foreign_key_check").fetchall())
            bad_offsets = int(self._conn.execute(
                "SELECT count(*) FROM captures c JOIN segments s USING(segment_id) "
                "WHERE c.offset < 0 OR c.length <= 0 OR c.offset+c.length > s.bytes"
            ).fetchone()[0])
            duplicate_ids = int(self._conn.execute(
                "SELECT count(*) FROM (SELECT capture_id FROM captures GROUP BY capture_id HAVING count(*) > 1)"
            ).fetchone()[0])
            uncovered_segments = 0
            for segment_id, segment_bytes in self._conn.execute(
                "SELECT segment_id,bytes FROM segments"
            ):
                expected_offset = 0
                for offset, length in self._conn.execute(
                    "SELECT offset,length FROM captures WHERE segment_id=? ORDER BY offset,capture_id",
                    (segment_id,),
                ):
                    if int(offset) != expected_offset:
                        uncovered_segments += 1
                        break
                    expected_offset += int(length)
                else:
                    if expected_offset != int(segment_bytes):
                        uncovered_segments += 1
            return {
                "ok": (
                    integrity == "ok"
                    and foreign == 0
                    and bad_offsets == 0
                    and duplicate_ids == 0
                    and uncovered_segments == 0
                ),
                "integrity_check": integrity,
                "foreign_key_rows": foreign,
                "bad_offsets": bad_offsets,
                "duplicate_capture_ids": duplicate_ids,
                "uncovered_segments": uncovered_segments,
                "health": self.health(),
            }

    def _writer_loop(self) -> None:
        while True:
            batch: list[_Task] = []
            try:
                try:
                    first = self._queue.get(timeout=1.0)
                except queue.Empty:
                    self._rotate_due_to_age()
                    continue
                if first is None:
                    break
                batch = [first]
                deadline = time.monotonic() + self.config.batch_wait_ms / 1000
                while len(batch) < self.config.batch_records:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    try:
                        item = self._queue.get(timeout=remaining)
                    except queue.Empty:
                        break
                    if item is None:
                        self._queue.put(None)
                        break
                    batch.append(item)
                self._commit_batch(batch)
            except BaseException as exc:
                self._fatal = exc
                self._last_error = str(exc)
                with self._stats_lock:
                    self._stats["failed"] += 1
                # A failed batch is explicitly acknowledged as failed; the
                # caller can retry with the same captureId and the audit trail
                # remains visible in capture_attempts.
                for task in batch:
                    task.error = StoreError(str(exc))
                    task.done.set()
                while True:
                    try:
                        queued = self._queue.get_nowait()
                    except queue.Empty:
                        break
                    if queued is not None:
                        queued.error = StoreError(str(exc))
                        queued.done.set()
                break

    def _commit_batch(self, batch: list[_Task]) -> None:
        with self._lock:
            pending: list[tuple[_Task, int, int, int]] = []
            staged: dict[str, tuple[str, int, int, int]] = {}
            for task in batch:
                capture_id = str(task.value["captureId"])
                existing = staged.get(capture_id)
                if existing is None:
                    existing = self._conn.execute(
                        "SELECT raw_sha256,segment_id,offset,length FROM captures WHERE capture_id=?",
                        (capture_id,),
                    ).fetchone()
                if existing is not None:
                    state = "duplicate" if str(existing[0]) == task.digest else "conflict"
                    self._conn.execute(
                        "INSERT INTO capture_attempts(capture_id,raw_sha256,state,reason,received_at,committed_at,segment_id) VALUES(?,?,?,?,?,?,?)",
                        (capture_id, task.digest, state, "same_capture_id_different_payload" if state == "conflict" else "already_committed", utc_now(), utc_now(), int(existing[1])),
                    )
                    if state == "duplicate":
                        task.result = CaptureResult(capture_id, state, True, int(existing[1]), int(existing[2]), int(existing[3]), task.digest)
                        with self._stats_lock:
                            self._stats["duplicates"] += 1
                    else:
                        task.error = StoreError("captureId was reused with a different payload")
                        with self._stats_lock:
                            self._stats["failed"] += 1
                    continue
                if self._active_bytes + len(task.raw) + 1 > self.config.segment_max_bytes and self._active_records:
                    self._seal_active()
                    self._open_active_segment()
                line = task.raw + b"\n"
                offset = self._active_bytes
                segment_id = self._active_segment_id
                assert segment_id is not None
                self._active_handle.write(line)
                self._active_bytes += len(line)
                self._active_records += 1
                pending.append((task, segment_id, offset, len(line)))
                staged[capture_id] = (task.digest, segment_id, offset, len(line))
            if pending:
                self._active_handle.flush()
                if self.config.fsync_each_batch:
                    os.fsync(self._active_handle.fileno())
            now = utc_now()
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                for task, segment_id, offset, length in pending:
                    meta = envelope_metadata(task.value)
                    self._conn.execute(
                        "INSERT INTO captures(capture_id,raw_sha256,segment_id,offset,length,received_at,started_at,finished_at,model,inbound_path,proxied_path,api_key_fingerprint,response_status,request_truncated,response_truncated,capture_error,stream,imported_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (task.value["captureId"], task.digest, segment_id, offset, length, meta["received_at"], meta["started_at"], meta["finished_at"], meta["model"], meta["inbound_path"], meta["proxied_path"], _text_or_none(meta["api_key_fingerprint"]), _int_or_none(meta["response_status"]), int(meta["request_truncated"]), int(meta["response_truncated"]), _text_or_none(meta["capture_error"]), int(meta["stream"]), now),
                    )
                    self._conn.execute(
                        "INSERT INTO capture_attempts(capture_id,raw_sha256,state,reason,received_at,committed_at,segment_id) VALUES(?,?,?,?,?,?,?)",
                        (task.value["captureId"], task.digest, "accepted", None, now, now, segment_id),
                    )
                    task.result = CaptureResult(task.value["captureId"], "accepted", False, segment_id, offset, length, task.digest)
                self._conn.execute("UPDATE segments SET bytes=?,records=?,last_offset=? WHERE segment_id=?", (self._active_bytes, self._active_records, self._active_bytes, self._active_segment_id))
                self._conn.commit()
                with self._stats_lock:
                    self._stats["accepted"] += len(pending)
            except BaseException:
                self._conn.rollback()
                raise
            for task in batch:
                if task.result is None and task.error is None:
                    task.error = StoreError("capture was not committed")
                task.done.set()

    def _recover(self) -> None:
        files = sorted(self.segments_dir.glob("segment-*.open.ndjson")) + sorted(self.segments_dir.glob("segment-*.sealed.ndjson"))
        for path in files:
            is_open = path.name.endswith(".open.ndjson")
            segment_id = _segment_id(path)
            if segment_id is None:
                raise RecoveryError(f"invalid segment filename: {path.name}")
            size_before = path.stat().st_size
            relative_path = str(path.relative_to(self.root))
            existing_segment = self._conn.execute(
                "SELECT path,state,bytes,records,sha256 FROM segments WHERE segment_id=?",
                (segment_id,),
            ).fetchone()
            indexed = self._conn.execute(
                "SELECT count(*) FROM captures WHERE segment_id=?",
                (segment_id,),
            ).fetchone()[0]
            if (
                not is_open
                and existing_segment is not None
                and str(existing_segment[0]) == relative_path
                and str(existing_segment[1]) in {"sealed", "archived"}
                and int(existing_segment[2]) == size_before
                and int(existing_segment[3]) == int(indexed)
                and _segment_locators_cover(self._conn, segment_id, size_before)
                and existing_segment[4]
            ):
                continue
            valid_end = 0
            records = 0
            with path.open("rb") as handle:
                while True:
                    offset = handle.tell()
                    line = handle.readline()
                    if not line:
                        break
                    if not line.endswith(b"\n"):
                        if is_open:
                            break
                        raise RecoveryError(f"sealed segment has incomplete tail: {path}")
                    try:
                        value = json.loads(line, parse_constant=_reject_json_constant)
                        validate_envelope(value)
                    except (ValueError, TypeError, json.JSONDecodeError) as exc:
                        raise RecoveryError(f"invalid record at {path}:{offset}: {exc}") from exc
                    # A line written by this store is canonical. Older or
                    # compatible clients may differ in key order; index the
                    # actual bytes hash so replay remains lossless.
                    actual_digest = hashlib.sha256(line[:-1]).hexdigest()
                    self._reconcile_record(value, actual_digest, segment_id, offset, len(line), "recovered")
                    valid_end = offset + len(line)
                    records += 1
            if is_open and valid_end < size_before:
                with path.open("r+b") as handle:
                    handle.truncate(valid_end)
                    handle.flush()
                    os.fsync(handle.fileno())
                self._record_event("open_tail_truncated", {"path": str(path), "bytes": size_before - valid_end})
            digest = _file_sha256(path)
            state = "open" if is_open else "sealed"
            self._conn.execute(
                "INSERT INTO segments(segment_id,path,state,created_at,sealed_at,bytes,records,sha256,last_offset) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(segment_id) DO UPDATE SET path=excluded.path,state=excluded.state,sealed_at=excluded.sealed_at,bytes=excluded.bytes,records=excluded.records,sha256=excluded.sha256,last_offset=excluded.last_offset",
                (segment_id, relative_path, state, utc_now(), None if is_open else utc_now(), path.stat().st_size, records, None if is_open else digest, path.stat().st_size),
            )
        missing = [
            str(row[1])
            for row in self._conn.execute(
                "SELECT segment_id,path FROM segments WHERE state IN ('open','sealed','archived')"
            )
            if not (self.root / str(row[1])).is_file()
        ]
        if missing:
            raise RecoveryError(f"ledger references missing segments: {missing[:10]}")
        self._conn.commit()

    def _reconcile_record(self, value: dict[str, Any], digest: str, segment_id: int, offset: int, length: int, source: str) -> None:
        capture_id = str(value["captureId"])
        existing = self._conn.execute(
            "SELECT raw_sha256,segment_id,offset,length FROM captures WHERE capture_id=?",
            (capture_id,),
        ).fetchone()
        if existing is not None:
            if str(existing[0]) != digest:
                raise RecoveryError(f"captureId conflict during recovery: {capture_id}")
            if (int(existing[1]), int(existing[2]), int(existing[3])) != (segment_id, offset, length):
                raise RecoveryError(f"duplicate physical capture during recovery: {capture_id}")
            return
        self._conn.execute("INSERT OR IGNORE INTO segments(segment_id,path,state,created_at,bytes,records,last_offset) VALUES(?,?,?,?,0,0,0)", (segment_id, f"segments/segment-{segment_id:08d}.sealed.ndjson", "sealed", utc_now()))
        meta = envelope_metadata(value)
        self._conn.execute(
            "INSERT INTO captures(capture_id,raw_sha256,segment_id,offset,length,received_at,started_at,finished_at,model,inbound_path,proxied_path,api_key_fingerprint,response_status,request_truncated,response_truncated,capture_error,stream,imported_at,source) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (capture_id, digest, segment_id, offset, length, meta["received_at"], meta["started_at"], meta["finished_at"], meta["model"], meta["inbound_path"], meta["proxied_path"], _text_or_none(meta["api_key_fingerprint"]), _int_or_none(meta["response_status"]), int(meta["request_truncated"]), int(meta["response_truncated"]), _text_or_none(meta["capture_error"]), int(meta["stream"]), utc_now(), source),
        )
        self._conn.execute("INSERT INTO capture_attempts(capture_id,raw_sha256,state,reason,received_at,committed_at,segment_id) VALUES(?,?,?,?,?,?,?)", (capture_id, digest, source, "startup_recovery", utc_now(), utc_now(), segment_id))
        with self._stats_lock:
            self._stats["recovered"] += 1

    def _open_active_segment(self) -> None:
        rows = self._conn.execute("SELECT segment_id,path,bytes,records FROM segments WHERE state='open' ORDER BY segment_id").fetchall()
        if len(rows) > 1:
            # Older open segments are safe to close after recovery; only the
            # newest file may receive future writes.
            for row in rows[:-1]:
                self._seal_path(int(row[0]), self.root / str(row[1]))
            rows = rows[-1:]
        if rows:
            segment_id, rel, bytes_count, records = rows[0]
            path = self.root / str(rel)
        else:
            segment_id = int(self._conn.execute("SELECT coalesce(max(segment_id),0)+1 FROM segments").fetchone()[0])
            path = self.segments_dir / f"segment-{segment_id:08d}.open.ndjson"
            path.touch(mode=0o600, exist_ok=True)
            _fsync_directory(path.parent)
            self._conn.execute("INSERT INTO segments(segment_id,path,state,created_at) VALUES(?,?,?,?)", (segment_id, str(path.relative_to(self.root)), "open", utc_now()))
            self._conn.commit()
            bytes_count, records = 0, 0
        self._active_segment_id = int(segment_id)
        self._active_handle = path.open("ab", buffering=0)
        self._active_bytes = int(bytes_count)
        self._active_records = int(records)
        self._active_started_monotonic = time.monotonic()

    def _seal_path(self, segment_id: int, path: Path) -> None:
        if not path.exists():
            raise RecoveryError(f"open segment missing: {path}")
        self._conn.execute("UPDATE segments SET state='sealed',sealed_at=?,sha256=?,bytes=?,last_offset=? WHERE segment_id=?", (utc_now(), _file_sha256(path), path.stat().st_size, path.stat().st_size, segment_id))
        sealed = path.with_name(path.name.replace(".open.ndjson", ".sealed.ndjson"))
        if path != sealed:
            os.replace(path, sealed)
            _fsync_directory(sealed.parent)
            self._conn.execute("UPDATE segments SET path=? WHERE segment_id=?", (str(sealed.relative_to(self.root)), segment_id))

    def _seal_active(self) -> None:
        if self._active_handle is None or self._active_segment_id is None:
            return
        self._active_handle.flush()
        os.fsync(self._active_handle.fileno())
        self._active_handle.close()
        path = self.root / str(self._conn.execute("SELECT path FROM segments WHERE segment_id=?", (self._active_segment_id,)).fetchone()[0])
        if self._active_records == 0:
            path.unlink(missing_ok=True)
            self._conn.execute("DELETE FROM segments WHERE segment_id=?", (self._active_segment_id,))
            self._conn.commit()
            _fsync_directory(path.parent)
            self._active_handle = None
            self._active_segment_id = None
            self._active_bytes = 0
            self._active_records = 0
            return
        self._conn.execute(
            "UPDATE segments SET bytes=?,records=?,last_offset=? WHERE segment_id=?",
            (
                self._active_bytes,
                self._active_records,
                self._active_bytes,
                self._active_segment_id,
            ),
        )
        self._seal_path(self._active_segment_id, path)
        self._conn.commit()
        with self._stats_lock:
            self._stats["sealed"] += 1
        self._active_handle = None
        self._active_segment_id = None
        self._active_bytes = 0
        self._active_records = 0

    def _rotate_due_to_age(self) -> None:
        max_age = self.config.segment_max_age_seconds
        if max_age <= 0 or not self._active_records:
            return
        if time.monotonic() - self._active_started_monotonic < max_age:
            return
        with self._lock:
            self._seal_active()
            self._open_active_segment()

    def _record_event(self, event_type: str, detail: dict[str, Any]) -> None:
        self._conn.execute("INSERT INTO audit_events(event_type,detail_json,created_at) VALUES(?,?,?)", (event_type, json.dumps(detail, sort_keys=True), utc_now()))


def _segment_id(path: Path) -> int | None:
    try:
        return int(path.name.split("-")[1].split(".")[0])
    except (IndexError, ValueError):
        return None


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _text_or_none(value: Any) -> str | None:
    return str(value) if value is not None else None


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _filesystem_type(path: Path) -> str | None:
    """Return the longest matching mount type on Linux, if available."""
    resolved = str(path.resolve())
    best: tuple[int, str] | None = None
    try:
        with Path("/proc/self/mounts").open("r", encoding="utf-8") as handle:
            for line in handle:
                fields = line.split()
                if len(fields) < 3:
                    continue
                mount = fields[1].replace("\\040", " ").replace("\\011", "\t").replace("\\134", "\\")
                try:
                    matches = os.path.commonpath((resolved, mount)) == mount
                except ValueError:
                    matches = False
                if matches and (best is None or len(mount) > best[0]):
                    best = (len(mount), fields[2].lower())
    except OSError:
        return None
    return best[1] if best else None


def _segment_locators_cover(conn: sqlite3.Connection, segment_id: int, size: int) -> bool:
    expected_offset = 0
    for offset, length in conn.execute(
        "SELECT offset,length FROM captures WHERE segment_id=? ORDER BY offset,capture_id",
        (segment_id,),
    ):
        if int(offset) != expected_offset or int(length) <= 0:
            return False
        expected_offset += int(length)
    return expected_offset == int(size)


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")
