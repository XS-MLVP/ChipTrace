from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
import time
from pathlib import Path
from typing import Any, Sequence

from .compression import ChunkCompressor, validate_compression
from .model import utc_now


EXPORT_FORMAT = "router-v2-training-raw-sqlite-v1"
RAW_CHUNK_BYTES = 4 * 1024 * 1024
COMPRESSION_BATCH_BYTES = 64 * 1024 * 1024
EXPORT_SCHEMA = """
PRAGMA foreign_keys=ON;
CREATE TABLE dataset_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE source_segments(
  segment_id INTEGER PRIMARY KEY,path TEXT NOT NULL,bytes INTEGER NOT NULL,
  records INTEGER NOT NULL,sha256 TEXT NOT NULL
);
CREATE TABLE interactions(
  record_id INTEGER PRIMARY KEY,capture_id TEXT NOT NULL UNIQUE,event_ts TEXT,
  received_at TEXT,started_at TEXT,finished_at TEXT,model TEXT,
  api_key_fingerprint TEXT,response_status INTEGER,raw_bytes INTEGER NOT NULL,
  stored_bytes INTEGER NOT NULL,raw_sha256 TEXT NOT NULL,segment_id INTEGER NOT NULL,
  source_offset INTEGER NOT NULL,source_length INTEGER NOT NULL,metadata_json TEXT NOT NULL,
  FOREIGN KEY(segment_id) REFERENCES source_segments(segment_id)
);
CREATE TABLE interaction_chunks(
  record_id INTEGER NOT NULL,chunk_index INTEGER NOT NULL,codec TEXT NOT NULL,
  raw_bytes INTEGER NOT NULL,stored_bytes INTEGER NOT NULL,payload BLOB NOT NULL,
  PRIMARY KEY(record_id,chunk_index),
  FOREIGN KEY(record_id) REFERENCES interactions(record_id)
) WITHOUT ROWID;
CREATE TABLE validation_results(
  check_name TEXT PRIMARY KEY,status TEXT NOT NULL,observed TEXT NOT NULL,expected TEXT
) WITHOUT ROWID;
CREATE INDEX interactions_timeline_idx ON interactions(event_ts,record_id);
CREATE INDEX interactions_model_idx ON interactions(model,event_ts);
"""


def export_sealed(
    root: Path,
    output: Path,
    *,
    ledger_path: Path | None = None,
    compression_codec: str = "zlib",
    compression_level: int = 1,
    compression_workers: int = 1,
    compression_batch_bytes: int = COMPRESSION_BATCH_BYTES,
    raw_chunk_bytes: int = RAW_CHUNK_BYTES,
    staging_sync: str = "fast",
    segment_ids: Sequence[int] | None = None,
    replace: bool = False,
) -> dict[str, Any]:
    root = Path(root).resolve()
    output = Path(output).resolve()
    compression_codec, compression_level = validate_compression(
        compression_codec,
        compression_level,
    )
    if compression_workers <= 0:
        raise ValueError("compression_workers must be positive")
    if compression_batch_bytes <= 0:
        raise ValueError("compression_batch_bytes must be positive")
    if raw_chunk_bytes <= 0:
        raise ValueError("raw_chunk_bytes must be positive")
    if staging_sync not in {"fast", "full"}:
        raise ValueError("staging_sync must be 'fast' or 'full'")
    selected_segment_ids = (
        tuple(sorted({int(value) for value in segment_ids}))
        if segment_ids is not None
        else None
    )
    if selected_segment_ids is not None and not selected_segment_ids:
        raise ValueError("segment_ids cannot be empty")
    segment_filter = ""
    segment_parameters: tuple[str, ...] = ()
    if selected_segment_ids is not None:
        segment_filter = (
            " AND segment_id IN "
            "(SELECT CAST(value AS INTEGER) FROM json_each(?))"
        )
        segment_parameters = (json.dumps(selected_segment_ids),)
    if output.exists() and not replace:
        raise FileExistsError(f"output exists: {output}")
    database = Path(ledger_path).resolve() if ledger_path else root / "state" / "capture-ledger.sqlite"
    if not database.exists() and ledger_path is None:
        database = root / "capture-ledger.sqlite"
    if output == database:
        raise ValueError("export output cannot overwrite the capture ledger")
    source_db = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    source_db.row_factory = sqlite3.Row
    source_db.execute("PRAGMA query_only=ON")
    source_db.execute("BEGIN")
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = output.with_name(f".{output.name}.{os.getpid()}.tmp")
    staging.unlink(missing_ok=True)
    out = sqlite3.connect(staging)
    os.chmod(staging, 0o600)
    count = 0
    total_raw = 0
    total_stored = 0
    compression_batches = 0
    compression_wait_seconds = 0.0
    segments: list[sqlite3.Row] = []
    published = False
    started_monotonic = time.monotonic()
    try:
        segments = source_db.execute(
            "SELECT segment_id,path,bytes,records,sha256 FROM segments "
            f"WHERE state IN ('sealed','archived'){segment_filter} ORDER BY segment_id",
            segment_parameters,
        ).fetchall()
        if not segments:
            raise RuntimeError("no sealed segments are available")
        if selected_segment_ids is not None and len(segments) != len(selected_segment_ids):
            found = {int(row["segment_id"]) for row in segments}
            missing = sorted(set(selected_segment_ids) - found)
            raise RuntimeError(f"selected sealed segments are unavailable: {missing}")
        source_paths = {(root / str(row["path"])).resolve() for row in segments}
        if output in source_paths:
            raise ValueError("export output cannot overwrite a source segment")
        out.execute("PRAGMA page_size=65536")
        if staging_sync == "fast":
            out.execute("PRAGMA journal_mode=OFF")
            out.execute("PRAGMA synchronous=OFF")
            out.execute("PRAGMA locking_mode=EXCLUSIVE")
            out.execute("PRAGMA temp_store=MEMORY")
        else:
            out.execute("PRAGMA journal_mode=DELETE")
            out.execute("PRAGMA synchronous=FULL")
        out.executescript(EXPORT_SCHEMA)
        compression_label = f"{compression_codec}-{compression_level}"
        meta = {
            "format": EXPORT_FORMAT,
            "created_at_utc": utc_now(),
            "source_root": str(root),
            "compression": compression_label,
            "compression_workers": str(compression_workers),
            "compression_batch_bytes": str(compression_batch_bytes),
            "staging_sync": staging_sync,
            "source_segment_selection": (
                "all-sealed" if selected_segment_ids is None else "explicit-segment-ids"
            ),
            "raw_chunk_bytes": str(raw_chunk_bytes),
            "sensitive_raw_data": "true",
            "semantic_reward_available": "false",
        }
        out.executemany("INSERT INTO dataset_meta VALUES(?,?)", meta.items())
        for row in segments:
            if not row["sha256"]:
                raise RuntimeError(f"segment {row['segment_id']} is missing a sealed checksum")
            out.execute("INSERT INTO source_segments VALUES(?,?,?,?,?)", tuple(row))
        capture_filter = ""
        if selected_segment_ids is not None:
            capture_filter = (
                " AND s.segment_id IN "
                "(SELECT CAST(value AS INTEGER) FROM json_each(?))"
            )
        captures = source_db.execute(
            "SELECT c.*,s.path AS segment_path FROM captures c JOIN segments s USING(segment_id) "
            f"WHERE s.state IN ('sealed','archived'){capture_filter} "
            "ORDER BY c.segment_id,c.offset,c.capture_id",
            segment_parameters,
        )
        handles: dict[int, Any] = {}
        segment_digests: dict[int, Any] = {}
        segment_offsets: dict[int, int] = {}
        segment_records: dict[int, int] = {}
        segment_stats: dict[int, tuple[int, int, int]] = {}
        pending_chunks: list[tuple[int, int, bytes]] = []
        pending_raw_bytes = 0
        completed_records: list[int] = []
        stored_by_record: dict[int, int] = {}
        compressor = ChunkCompressor(
            compression_codec,
            compression_level,
            compression_workers,
        )

        def flush_compression_batch() -> None:
            nonlocal pending_raw_bytes, total_stored
            nonlocal compression_batches, compression_wait_seconds
            if pending_chunks:
                batch_started = time.monotonic()
                payloads = compressor.compress_batch([item[2] for item in pending_chunks])
                compression_wait_seconds += time.monotonic() - batch_started
                compression_batches += 1
                chunk_rows = []
                for (record_id, chunk_index, chunk), payload in zip(
                    pending_chunks,
                    payloads,
                    strict=True,
                ):
                    stored = len(payload)
                    chunk_rows.append(
                        (
                            record_id,
                            chunk_index,
                            compression_label,
                            len(chunk),
                            stored,
                            sqlite3.Binary(payload),
                        )
                    )
                    stored_by_record[record_id] = stored_by_record.get(record_id, 0) + stored
                    total_stored += stored
                out.executemany(
                    "INSERT INTO interaction_chunks VALUES(?,?,?,?,?,?)",
                    chunk_rows,
                )
                pending_chunks.clear()
                pending_raw_bytes = 0
            if completed_records:
                out.executemany(
                    "UPDATE interactions SET stored_bytes=? WHERE record_id=?",
                    [
                        (stored_by_record.pop(record_id), record_id)
                        for record_id in completed_records
                    ],
                )
                completed_records.clear()

        try:
            for row in captures:
                segment_id = int(row["segment_id"])
                handle = handles.get(segment_id)
                if handle is None:
                    source_path = root / str(row["segment_path"])
                    stat = source_path.stat()
                    handle = source_path.open("rb")
                    handles[segment_id] = handle
                    segment_digests[segment_id] = hashlib.sha256()
                    segment_offsets[segment_id] = 0
                    segment_records[segment_id] = 0
                    segment_stats[segment_id] = (stat.st_ino, stat.st_size, stat.st_mtime_ns)
                if int(row["offset"]) != segment_offsets[segment_id]:
                    raise RuntimeError(f"source segment has an unindexed gap before {row['capture_id']}")
                handle.seek(segment_offsets[segment_id])
                raw_bytes = int(row["length"]) - 1
                if raw_bytes <= 0:
                    raise RuntimeError(f"invalid source length for {row['capture_id']}")
                cursor = out.execute(
                    "INSERT INTO interactions(capture_id,event_ts,received_at,started_at,finished_at,model,api_key_fingerprint,response_status,raw_bytes,stored_bytes,raw_sha256,segment_id,source_offset,source_length,metadata_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (row["capture_id"], row["started_at"] or row["received_at"], row["received_at"], row["started_at"], row["finished_at"], row["model"], row["api_key_fingerprint"], row["response_status"], raw_bytes, 0, row["raw_sha256"], segment_id, row["offset"], row["length"], json.dumps({"source":"trace-training-pipeline","inbound_path":row["inbound_path"],"proxied_path":row["proxied_path"]}, separators=(",", ":"), sort_keys=True)),
                )
                record_id = int(cursor.lastrowid)
                digest = hashlib.sha256()
                remaining = raw_bytes
                chunk_index = 0
                while remaining:
                    chunk = handle.read(min(remaining, raw_chunk_bytes))
                    if not chunk:
                        raise RuntimeError(f"source locator mismatch for {row['capture_id']}")
                    digest.update(chunk)
                    segment_digests[segment_id].update(chunk)
                    pending_chunks.append((record_id, chunk_index, chunk))
                    pending_raw_bytes += len(chunk)
                    remaining -= len(chunk)
                    chunk_index += 1
                    if pending_raw_bytes >= compression_batch_bytes:
                        flush_compression_batch()
                newline = handle.read(1)
                if newline != b"\n":
                    raise RuntimeError(f"source locator mismatch for {row['capture_id']}")
                segment_digests[segment_id].update(newline)
                segment_offsets[segment_id] += int(row["length"])
                segment_records[segment_id] += 1
                if digest.hexdigest() != row["raw_sha256"]:
                    raise RuntimeError(f"source hash mismatch for {row['capture_id']}")
                completed_records.append(record_id)
                count += 1
                total_raw += raw_bytes
                if count % 1000 == 0:
                    flush_compression_batch()
                    out.commit()
            flush_compression_batch()
            if stored_by_record:
                raise RuntimeError("compressed record accounting did not close")
            for segment in segments:
                segment_id = int(segment["segment_id"])
                if segment_offsets.get(segment_id, 0) != int(segment["bytes"]):
                    raise RuntimeError(f"source segment {segment_id} is not fully indexed")
                if segment_records.get(segment_id, 0) != int(segment["records"]):
                    raise RuntimeError(f"source segment {segment_id} record count mismatch")
                if segment_stats[segment_id][1] != int(segment["bytes"]):
                    raise RuntimeError(f"source segment {segment_id} file size mismatch")
                if segment_digests[segment_id].hexdigest() != str(segment["sha256"]):
                    raise RuntimeError(f"source segment {segment_id} checksum mismatch")
                source_path = root / str(segment["path"])
                stat = source_path.stat()
                if (stat.st_ino, stat.st_size, stat.st_mtime_ns) != segment_stats[segment_id]:
                    raise RuntimeError(f"source segment {segment_id} changed during export")
        finally:
            compressor.close()
            for handle in handles.values():
                handle.close()
        expected = int(
            source_db.execute(
                "SELECT count(*) FROM captures c JOIN segments s USING(segment_id) "
                f"WHERE s.state IN ('sealed','archived'){capture_filter}",
                segment_parameters,
            ).fetchone()[0]
        )
        checks = {
            "record_count": (count, expected),
            "duplicate_capture_ids": (
                int(out.execute("SELECT count(*) FROM (SELECT capture_id FROM interactions GROUP BY capture_id HAVING count(*)>1)").fetchone()[0]),
                0,
            ),
            "foreign_key_rows": (len(out.execute("PRAGMA foreign_key_check").fetchall()), 0),
            "chunk_raw_bytes": (
                int(out.execute("SELECT coalesce(sum(raw_bytes),0) FROM interaction_chunks").fetchone()[0]),
                total_raw,
            ),
            "chunk_stored_bytes": (
                int(out.execute("SELECT coalesce(sum(stored_bytes),0) FROM interaction_chunks").fetchone()[0]),
                total_stored,
            ),
            "interaction_raw_bytes": (
                int(out.execute("SELECT coalesce(sum(raw_bytes),0) FROM interactions").fetchone()[0]),
                total_raw,
            ),
            "interaction_stored_bytes": (
                int(out.execute("SELECT coalesce(sum(stored_bytes),0) FROM interactions").fetchone()[0]),
                total_stored,
            ),
            "invalid_chunk_sequences": (
                int(out.execute(
                    "SELECT count(*) FROM (SELECT record_id,count(*) AS n,max(chunk_index) AS m "
                    "FROM interaction_chunks GROUP BY record_id HAVING min(chunk_index)!=0 OR m+1!=n)"
                ).fetchone()[0]),
                0,
            ),
        }
        for name, (observed, wanted) in checks.items():
            out.execute("INSERT INTO validation_results VALUES(?,?,?,?)", (name, "pass" if observed == wanted else "fail", str(observed), str(wanted)))
        out.commit()
        integrity = str(out.execute("PRAGMA integrity_check").fetchone()[0])
        out.execute("INSERT INTO validation_results VALUES(?,?,?,?)", ("sqlite_integrity_check", "pass" if integrity == "ok" else "fail", integrity, "ok"))
        out.commit()
        if any(row[0] == "fail" for row in out.execute("SELECT status FROM validation_results")):
            raise RuntimeError("export validation failed")
        out.close()
        source_db.close()
        _fsync_file(staging)
        _publish_file(staging, output, replace=replace)
        _fsync_directory(output.parent)
        published = True
    finally:
        try:
            source_db.close()
        finally:
            out.close()
        if not published:
            staging.unlink(missing_ok=True)
    checksum = _file_sha256(output)
    elapsed = time.monotonic() - started_monotonic
    return {
        "output": str(output),
        "output_bytes": output.stat().st_size,
        "sha256": checksum,
        "records": count,
        "raw_bytes": total_raw,
        "stored_bytes": total_stored,
        "raw_chunk_bytes": raw_chunk_bytes,
        "compression": f"{compression_codec}-{compression_level}",
        "compression_workers": compression_workers,
        "compression_batch_bytes": compression_batch_bytes,
        "compression_batches": compression_batches,
        "compression_wait_seconds": round(compression_wait_seconds, 6),
        "compression_raw_mib_per_second": round(
            total_raw / compression_wait_seconds / 1024 / 1024,
            3,
        ) if compression_wait_seconds else None,
        "staging_sync": staging_sync,
        "elapsed_seconds": round(elapsed, 6),
        "raw_mib_per_second": round(total_raw / elapsed / 1024 / 1024, 3),
        "stored_mib_per_second": round(total_stored / elapsed / 1024 / 1024, 3),
        "compression_ratio": round(total_raw / total_stored, 6) if total_stored else None,
        "segments": len(segments),
        "segment_ids": [int(row["segment_id"]) for row in segments],
    }


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _fsync_file(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _publish_file(staging: Path, output: Path, *, replace: bool) -> None:
    if replace:
        os.replace(staging, output)
        return
    os.link(staging, output)
    staging.unlink()
