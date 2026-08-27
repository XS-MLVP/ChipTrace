from __future__ import annotations

import gzip
import hashlib
import json
import os
import shutil
import sqlite3
import tarfile
import tempfile
import urllib.parse
from pathlib import Path
from typing import Any, Sequence

from .exporter import EXPORT_FORMAT, EXPORT_SCHEMA
from .model import utc_now
from .trajectory import (
    CATALOG_SCHEMA_VERSION,
    QUALITY_POLICY_VERSION,
    body_value,
    build_trajectory_catalog,
    iter_raw_records,
    record_and_context,
    validate_raw_shard,
)


RELEASE_FORMAT = "agent-complete-session-release-v2"
RELEASE_SCHEMA_VERSION = "complete-session-release-v1"
DEFAULT_TARGET_PART_BYTES = 10 * 1024 * 1024 * 1024
PLANNER_SCHEMA = """
CREATE TABLE records(
  capture_id TEXT PRIMARY KEY,raw_sha256 TEXT NOT NULL,source_index INTEGER NOT NULL,
  source_record_id INTEGER NOT NULL,session_id TEXT NOT NULL,model TEXT,event_ts TEXT,
  raw_bytes INTEGER NOT NULL,stored_bytes INTEGER NOT NULL
) WITHOUT ROWID;
CREATE TABLE sessions(
  session_id TEXT PRIMARY KEY,records INTEGER NOT NULL,raw_bytes INTEGER NOT NULL,
  stored_bytes INTEGER NOT NULL,estimated_release_bytes INTEGER NOT NULL,
  first_event_utc TEXT,last_event_utc TEXT,selected INTEGER NOT NULL DEFAULT 0,
  part_id INTEGER,oversized INTEGER NOT NULL DEFAULT 0
) WITHOUT ROWID;
CREATE INDEX records_source_idx ON records(source_index,source_record_id);
CREATE INDEX records_session_idx ON records(session_id,event_ts,capture_id);
CREATE INDEX sessions_part_idx ON sessions(part_id,first_event_utc,session_id);
"""


def build_session_release(
    inputs: Sequence[Path],
    output: Path,
    *,
    model_exact: str,
    target_part_bytes: int = DEFAULT_TARGET_PART_BYTES,
    release_id: str | None = None,
) -> dict[str, Any]:
    paths = [Path(path).resolve() for path in inputs]
    if not paths:
        raise ValueError("at least one raw SQLite input is required")
    if not model_exact:
        raise ValueError("model_exact is required")
    if int(target_part_bytes) <= 0:
        raise ValueError("target_part_bytes must be positive")
    if len(set(paths)) != len(paths):
        raise ValueError("raw SQLite input paths must be unique")
    if len({path.name for path in paths}) != len(paths):
        raise ValueError("raw SQLite input file names must be unique")
    for path in paths:
        if not path.is_file():
            raise FileNotFoundError(path)
        validate_raw_shard(path)
    input_stats = {path: _stat_identity(path) for path in paths}

    output = Path(output).resolve()
    if output.exists():
        raise FileExistsError(f"release directory exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    planner_path = staging / ".session-release-planner.sqlite"
    planner = sqlite3.connect(planner_path)
    planner.execute("PRAGMA journal_mode=DELETE")
    planner.execute("PRAGMA synchronous=NORMAL")
    planner.executescript(PLANNER_SCHEMA)
    published = False
    duplicate_records = 0
    scanned_records = 0
    try:
        for source_index, path in enumerate(paths, start=1):
            for raw_record in iter_raw_records(path, source_index):
                scanned_records += 1
                value, _context, session_id, _turn_key = record_and_context(raw_record)
                request = body_value(value.get("requestBody"))
                body_model = (
                    request.get("model")
                    if isinstance(request, dict) and isinstance(request.get("model"), str)
                    else None
                )
                if raw_record.model is not None and body_model is not None and raw_record.model != body_model:
                    raise RuntimeError(f"model index mismatch for capture {raw_record.capture_id}")
                record_model = body_model or raw_record.model
                existing = planner.execute(
                    "SELECT raw_sha256 FROM records WHERE capture_id=?",
                    (raw_record.capture_id,),
                ).fetchone()
                if existing is not None:
                    if str(existing[0]) != raw_record.raw_sha256:
                        raise RuntimeError(
                            f"captureId conflict across raw inputs: {raw_record.capture_id}"
                        )
                    duplicate_records += 1
                    continue
                planner.execute(
                    "INSERT INTO records VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        raw_record.capture_id,
                        raw_record.raw_sha256,
                        source_index,
                        raw_record.record_id,
                        session_id,
                        record_model,
                        raw_record.event_ts,
                        raw_record.raw_bytes,
                        raw_record.stored_bytes,
                    ),
                )
                # The estimate covers compressed payload plus SQLite row/index
                # overhead. Exact file size is reported after publication.
                estimate = raw_record.stored_bytes + 2048
                planner.execute(
                    """
                    INSERT INTO sessions(
                      session_id,records,raw_bytes,stored_bytes,estimated_release_bytes,
                      first_event_utc,last_event_utc,selected
                    ) VALUES(?,1,?,?,?,?,?,?)
                    ON CONFLICT(session_id) DO UPDATE SET
                      records=records+1,
                      raw_bytes=raw_bytes+excluded.raw_bytes,
                      stored_bytes=stored_bytes+excluded.stored_bytes,
                      estimated_release_bytes=estimated_release_bytes+excluded.estimated_release_bytes,
                      first_event_utc=CASE
                        WHEN first_event_utc IS NULL THEN excluded.first_event_utc
                        WHEN excluded.first_event_utc IS NULL THEN first_event_utc
                        ELSE min(first_event_utc,excluded.first_event_utc) END,
                      last_event_utc=CASE
                        WHEN last_event_utc IS NULL THEN excluded.last_event_utc
                        WHEN excluded.last_event_utc IS NULL THEN last_event_utc
                        ELSE max(last_event_utc,excluded.last_event_utc) END,
                      selected=max(selected,excluded.selected)
                    """,
                    (
                        session_id,
                        raw_record.raw_bytes,
                        raw_record.stored_bytes,
                        estimate,
                        raw_record.event_ts,
                        raw_record.event_ts,
                        int(record_model == model_exact),
                    ),
                )
                if scanned_records % 1000 == 0:
                    planner.commit()
        planner.commit()
        _assert_inputs_unchanged(input_stats)
        selected_sessions = int(
            planner.execute("SELECT count(*) FROM sessions WHERE selected=1").fetchone()[0]
        )
        if selected_sessions == 0:
            raise RuntimeError(f"no sessions contain model {model_exact!r}")
        part_count, oversized_sessions = _assign_parts(planner, int(target_part_bytes))
        planner.commit()

        safe_model = _safe_name(model_exact)
        part_paths: list[Path] = []
        part_summaries: list[dict[str, Any]] = []
        for part_id in range(1, part_count + 1):
            part_path = staging / f"{safe_model}-part-{part_id:03d}.sqlite"
            summary = _build_raw_part(
                planner,
                paths,
                part_path,
                part_id=part_id,
                release_id=release_id or output.name,
                model_exact=model_exact,
                target_part_bytes=int(target_part_bytes),
            )
            part_paths.append(part_path)
            part_summaries.append(summary)
            _assert_inputs_unchanged(input_stats)

        catalog_path = staging / "session-catalog.sqlite"
        catalog = build_trajectory_catalog(
            part_paths,
            catalog_path,
            model_exact=model_exact,
            projection_mode="complete-thread",
        )
        _assert_inputs_unchanged(input_stats)
        manifest = _build_manifest(
            planner,
            paths,
            output_name=output.name,
            release_id=release_id or output.name,
            model_exact=model_exact,
            target_part_bytes=int(target_part_bytes),
            scanned_records=scanned_records,
            duplicate_records=duplicate_records,
            oversized_sessions=oversized_sessions,
            part_summaries=part_summaries,
            catalog_path=catalog_path,
            catalog=catalog,
        )
        manifest_path = staging / "manifest.json"
        manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.chmod(manifest_path, 0o600)
        checksummed = [*part_paths, catalog_path, manifest_path]
        sums_path = staging / "SHA256SUMS"
        sums_path.write_text(
            "".join(f"{_file_sha256(path)}  {path.name}\n" for path in checksummed),
            encoding="ascii",
        )
        os.chmod(sums_path, 0o600)
        _verify_release(staging, manifest)
        _verify_sha256s(staging, sums_path)
        planner.close()
        planner_path.unlink()
        for path in checksummed + [sums_path]:
            _fsync_file(path)
        _fsync_directory(staging)
        os.rename(staging, output)
        _fsync_directory(output.parent)
        published = True
        return {
            "ok": True,
            "output": str(output),
            "release_id": manifest["release_id"],
            "records": manifest["records"],
            "sessions": manifest["sessions"],
            "parts": len(part_summaries),
            "release_bytes": sum(path.stat().st_size for path in output.iterdir()),
            "duplicate_records_omitted": duplicate_records,
            "oversized_sessions": len(oversized_sessions),
            "session_completeness_score_average": manifest["session_quality"]["average"],
            "validation_status": manifest["validation_status"],
        }
    finally:
        planner.close()
        if not published:
            shutil.rmtree(staging, ignore_errors=True)


def verify_session_release(root: Path, *, require_pass: bool = False) -> dict[str, Any]:
    """Verify an already published complete-session release read-only.

    This is the recipient-side counterpart to ``build_session_release``. It
    checks the manifest, SHA256SUMS, every SQLite file's integrity/foreign-key
    state, and the catalog/part conservation counts without modifying files.
    """
    root = Path(root).resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"release directory does not exist: {root}")
    manifest_path = root / "manifest.json"
    sums_path = root / "SHA256SUMS"
    if not manifest_path.is_file() or not sums_path.is_file():
        raise RuntimeError("release must contain manifest.json and SHA256SUMS")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"invalid release manifest: {exc}") from exc
    if not isinstance(manifest, dict):
        raise RuntimeError("release manifest must be a JSON object")
    if manifest.get("schema_version") != RELEASE_SCHEMA_VERSION:
        raise RuntimeError(
            f"unsupported release schema {manifest.get('schema_version')!r}; "
            f"expected {RELEASE_SCHEMA_VERSION!r}"
        )
    if manifest.get("session_atomic") is not True or manifest.get("session_split_count") != 0:
        raise RuntimeError("release is not marked as session-atomic")
    parts = manifest.get("parts")
    catalog = manifest.get("catalog")
    if not isinstance(parts, list) or not isinstance(catalog, dict):
        raise RuntimeError("release manifest has invalid parts or catalog entries")
    part_names = []
    for part in parts:
        if not isinstance(part, dict) or not isinstance(part.get("file"), str):
            raise RuntimeError("release manifest contains an invalid part entry")
        part_names.append(part["file"])
    if len(set(part_names)) != len(part_names):
        raise RuntimeError("release manifest contains duplicate part files")
    catalog_name = catalog.get("file")
    if not isinstance(catalog_name, str):
        raise RuntimeError("release manifest has no catalog file")
    if catalog_name in {"manifest.json", "SHA256SUMS"} or catalog_name in part_names:
        raise RuntimeError("release manifest file names overlap")
    expected_names = {"manifest.json", catalog_name, *part_names}
    actual_files = {path.name for path in root.iterdir() if path.is_file()}
    expected_files = expected_names | {"SHA256SUMS"}
    if actual_files != expected_files:
        missing = sorted(expected_files - actual_files)
        unexpected = sorted(actual_files - expected_files)
        raise RuntimeError(f"release file set mismatch: missing={missing}, unexpected={unexpected}")
    _verify_sha256s(root, sums_path, expected_names=expected_names)
    _verify_release(root, manifest)
    validation_status = str(manifest.get("validation_status", ""))
    if require_pass and validation_status != "pass":
        raise RuntimeError(f"release validation status is {validation_status!r}, not 'pass'")
    with sqlite3.connect(f"file:{root / catalog_name}?mode=ro", uri=True) as conn:
        integrity = str(conn.execute("PRAGMA integrity_check").fetchone()[0])
        foreign = len(conn.execute("PRAGMA foreign_key_check").fetchall())
        catalog_status = conn.execute(
            "SELECT value FROM dataset_meta WHERE key='validation_status'"
        ).fetchone()
    catalog_validation_status = None
    if catalog_status is not None:
        try:
            catalog_validation_status = json.loads(str(catalog_status[0]))
        except (TypeError, ValueError):
            catalog_validation_status = str(catalog_status[0])
    if catalog_validation_status != validation_status:
        raise RuntimeError("manifest and catalog validation statuses differ")
    return {
        "ok": True,
        "release": str(root),
        "release_id": manifest.get("release_id"),
        "schema_version": manifest["schema_version"],
        "validation_status": validation_status,
        "catalog_validation_status": catalog_validation_status,
        "records": int(manifest.get("records", 0)),
        "sessions": int(manifest.get("sessions", 0)),
        "parts": len(parts),
        "integrity_check": integrity,
        "foreign_key_rows": foreign,
        "sha256_entries": len(expected_names),
    }


def archive_session_release(
    release: Path,
    output: Path,
    *,
    require_pass: bool = False,
    replace: bool = False,
) -> dict[str, Any]:
    """Create a deterministic UTF-8 ``tar.gz`` from a verified release."""
    release = Path(release).resolve()
    output = Path(output).resolve()
    verification = verify_session_release(release, require_pass=require_pass)
    if output.parent == release or release in output.parents:
        raise ValueError("archive output cannot be inside the release directory")
    if output.exists() and not replace:
        raise FileExistsError(f"archive exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = output.with_name(f".{output.name}.{os.getpid()}.tmp")
    staging.unlink(missing_ok=True)
    root_name = release.name
    try:
        with staging.open("wb") as raw_handle:
            with gzip.GzipFile(fileobj=raw_handle, mode="wb", mtime=0) as gzip_handle:
                with tarfile.open(fileobj=gzip_handle, mode="w", format=tarfile.PAX_FORMAT) as archive:
                    for path in sorted(release.rglob("*")):
                        if path.is_dir():
                            continue
                        if path.is_symlink() or not path.is_file():
                            raise RuntimeError(f"release contains a non-regular file: {path}")
                        relative = Path(root_name) / path.relative_to(release)
                        info = archive.gettarinfo(str(path), arcname=relative.as_posix())
                        info.uid = 0
                        info.gid = 0
                        info.uname = ""
                        info.gname = ""
                        info.mtime = 0
                        with path.open("rb") as handle:
                            archive.addfile(info, handle)
            raw_handle.flush()
            os.fsync(raw_handle.fileno())
        if replace:
            os.replace(staging, output)
        else:
            os.link(staging, output)
            staging.unlink()
        os.chmod(output, 0o600)
        _fsync_directory(output.parent)
    finally:
        staging.unlink(missing_ok=True)
    return {
        "ok": True,
        "archive": str(output),
        "bytes": output.stat().st_size,
        "sha256": _file_sha256(output),
        "release": verification,
    }


def _assign_parts(conn: sqlite3.Connection, target_bytes: int) -> tuple[int, list[str]]:
    part_id = 1
    part_bytes = 0
    oversized: list[str] = []
    rows = conn.execute(
        "SELECT session_id,estimated_release_bytes FROM sessions WHERE selected=1 "
        "ORDER BY coalesce(first_event_utc,''),session_id"
    ).fetchall()
    for session_id, estimate in rows:
        estimate = int(estimate)
        if part_bytes and part_bytes + estimate > target_bytes:
            part_id += 1
            part_bytes = 0
        is_oversized = estimate > target_bytes
        conn.execute(
            "UPDATE sessions SET part_id=?,oversized=? WHERE session_id=?",
            (part_id, int(is_oversized), session_id),
        )
        if is_oversized:
            oversized.append(str(session_id))
        part_bytes += estimate
        if is_oversized:
            part_id += 1
            part_bytes = 0
    if part_bytes == 0:
        part_id -= 1
    return max(part_id, 1), oversized


def _build_raw_part(
    planner: sqlite3.Connection,
    inputs: Sequence[Path],
    output: Path,
    *,
    part_id: int,
    release_id: str,
    model_exact: str,
    target_part_bytes: int,
) -> dict[str, Any]:
    out = sqlite3.connect(output, uri=True)
    os.chmod(output, 0o600)
    out.execute("PRAGMA page_size=65536")
    out.execute("PRAGMA journal_mode=DELETE")
    out.execute("PRAGMA synchronous=NORMAL")
    out.executescript(EXPORT_SCHEMA)
    meta = {
        "format": EXPORT_FORMAT,
        "release_format": RELEASE_FORMAT,
        "release_schema_version": RELEASE_SCHEMA_VERSION,
        "release_id": release_id,
        "part_id": str(part_id),
        "selection_model": model_exact,
        "selection_mode": "complete-session",
        "session_atomic": "true",
        "target_part_bytes": str(target_part_bytes),
        "compression": "preserved-from-source",
        "sensitive_raw_data": "true",
        "semantic_reward_available": "false",
        "created_at_utc": utc_now(),
    }
    out.executemany("INSERT INTO dataset_meta VALUES(?,?)", meta.items())
    next_record_id = 1
    next_segment_id = 1
    part_records = 0
    raw_bytes = 0
    stored_bytes = 0
    chunks = 0
    session_count = int(
        planner.execute(
            "SELECT count(*) FROM sessions WHERE selected=1 AND part_id=?", (part_id,)
        ).fetchone()[0]
    )
    for source_index, source_path in enumerate(inputs, start=1):
        selected = planner.execute(
            """
            SELECT r.source_record_id,r.model FROM records r JOIN sessions s USING(session_id)
             WHERE s.selected=1 AND s.part_id=? AND r.source_index=?
             ORDER BY coalesce(r.event_ts,''),r.capture_id
            """,
            (part_id, source_index),
        ).fetchall()
        if not selected:
            continue
        encoded = urllib.parse.quote(str(source_path), safe="/")
        out.execute(
            "ATTACH DATABASE ? AS source",
            (f"file:{encoded}?mode=ro&immutable=1",),
        )
        out.execute(
            "CREATE TEMP TABLE record_map("
            "source_record_id INTEGER PRIMARY KEY,new_record_id INTEGER NOT NULL,model TEXT)"
        )
        mappings = [
            (int(row[0]), next_record_id + index, row[1])
            for index, row in enumerate(selected)
        ]
        next_record_id += len(mappings)
        out.executemany("INSERT INTO record_map VALUES(?,?,?)", mappings)
        source_segments = out.execute(
            "SELECT DISTINCT i.segment_id FROM source.interactions i JOIN record_map m ON m.source_record_id=i.record_id ORDER BY i.segment_id"
        ).fetchall()
        out.execute("CREATE TEMP TABLE segment_map(source_segment_id INTEGER PRIMARY KEY,new_segment_id INTEGER NOT NULL)")
        segment_mappings = [
            (int(row[0]), next_segment_id + index) for index, row in enumerate(source_segments)
        ]
        next_segment_id += len(segment_mappings)
        out.executemany("INSERT INTO segment_map VALUES(?,?)", segment_mappings)
        out.execute(
            """
            INSERT INTO source_segments(segment_id,path,bytes,records,sha256)
            SELECT sm.new_segment_id,? || '::' || s.path,s.bytes,s.records,s.sha256
              FROM source.source_segments s JOIN segment_map sm ON sm.source_segment_id=s.segment_id
            """,
            (source_path.name,),
        )
        out.execute(
            """
            INSERT INTO interactions(
              record_id,capture_id,event_ts,received_at,started_at,finished_at,model,
              api_key_fingerprint,response_status,raw_bytes,stored_bytes,raw_sha256,
              segment_id,source_offset,source_length,metadata_json
            )
            SELECT m.new_record_id,i.capture_id,i.event_ts,i.received_at,i.started_at,
                   i.finished_at,m.model,i.api_key_fingerprint,i.response_status,
                   i.raw_bytes,i.stored_bytes,i.raw_sha256,sm.new_segment_id,
                   i.source_offset,i.source_length,i.metadata_json
              FROM source.interactions i
              JOIN record_map m ON m.source_record_id=i.record_id
              JOIN segment_map sm ON sm.source_segment_id=i.segment_id
             ORDER BY m.new_record_id
            """
        )
        out.execute(
            """
            INSERT INTO interaction_chunks(
              record_id,chunk_index,codec,raw_bytes,stored_bytes,payload
            )
            SELECT m.new_record_id,c.chunk_index,c.codec,c.raw_bytes,c.stored_bytes,c.payload
              FROM source.interaction_chunks c
              JOIN record_map m ON m.source_record_id=c.record_id
             ORDER BY m.new_record_id,c.chunk_index
            """
        )
        totals = out.execute(
            """
            SELECT count(*),coalesce(sum(i.raw_bytes),0),coalesce(sum(i.stored_bytes),0),
                   coalesce((SELECT count(*) FROM source.interaction_chunks c JOIN record_map m ON m.source_record_id=c.record_id),0)
              FROM source.interactions i JOIN record_map m ON m.source_record_id=i.record_id
            """
        ).fetchone()
        part_records += int(totals[0])
        raw_bytes += int(totals[1])
        stored_bytes += int(totals[2])
        chunks += int(totals[3])
        out.execute("DROP TABLE segment_map")
        out.execute("DROP TABLE record_map")
        out.commit()
        out.execute("DETACH DATABASE source")

    checks = {
        "record_count": (out.execute("SELECT count(*) FROM interactions").fetchone()[0], part_records),
        "duplicate_capture_ids": (
            out.execute(
                "SELECT count(*) FROM (SELECT capture_id FROM interactions GROUP BY capture_id HAVING count(*)>1)"
            ).fetchone()[0],
            0,
        ),
        "records_without_chunks": (
            out.execute(
                "SELECT count(*) FROM interactions i WHERE NOT EXISTS "
                "(SELECT 1 FROM interaction_chunks c WHERE c.record_id=i.record_id)"
            ).fetchone()[0],
            0,
        ),
        "foreign_key_rows": (len(out.execute("PRAGMA foreign_key_check").fetchall()), 0),
        "chunk_count": (out.execute("SELECT count(*) FROM interaction_chunks").fetchone()[0], chunks),
    }
    for name, (observed, expected) in checks.items():
        out.execute(
            "INSERT INTO validation_results VALUES(?,?,?,?)",
            (name, "pass" if observed == expected else "fail", str(observed), str(expected)),
        )
    integrity = str(out.execute("PRAGMA integrity_check").fetchone()[0])
    out.execute(
        "INSERT INTO validation_results VALUES(?,?,?,?)",
        ("sqlite_integrity_check", "pass" if integrity == "ok" else "fail", integrity, "ok"),
    )
    out.commit()
    if out.execute("SELECT count(*) FROM validation_results WHERE status='fail'").fetchone()[0]:
        raise RuntimeError(f"raw release part validation failed: {output}")
    out.execute("ANALYZE")
    out.commit()
    out.close()
    _fsync_file(output)
    return {
        "file": output.name,
        "bytes": output.stat().st_size,
        "sha256": _file_sha256(output),
        "records": part_records,
        "sessions": session_count,
        "raw_bytes": raw_bytes,
        "stored_payload_bytes": stored_bytes,
        "oversized_target": output.stat().st_size > target_part_bytes,
    }


def _build_manifest(
    planner: sqlite3.Connection,
    inputs: Sequence[Path],
    *,
    output_name: str,
    release_id: str,
    model_exact: str,
    target_part_bytes: int,
    scanned_records: int,
    duplicate_records: int,
    oversized_sessions: Sequence[str],
    part_summaries: Sequence[dict[str, Any]],
    catalog_path: Path,
    catalog: dict[str, Any],
) -> dict[str, Any]:
    selected = planner.execute(
        """
        SELECT count(*),coalesce(sum(records),0),coalesce(sum(raw_bytes),0),
               min(first_event_utc),max(last_event_utc)
          FROM sessions WHERE selected=1
        """
    ).fetchone()
    selected_models = [
        row[0]
        for row in planner.execute(
            """
            SELECT DISTINCT r.model FROM records r JOIN sessions s USING(session_id)
             WHERE s.selected=1 AND r.model IS NOT NULL ORDER BY r.model
            """
        )
    ]
    with sqlite3.connect(f"file:{catalog_path}?mode=ro", uri=True) as conn:
        quality = conn.execute(
            "SELECT round(avg(session_completeness_score),3),"
            "min(session_completeness_score),max(session_completeness_score) FROM session_quality"
        ).fetchone()
        grades = dict(
            conn.execute(
                "SELECT completeness_grade,count(*) FROM session_quality GROUP BY completeness_grade"
            )
        )
        incomplete_reasons = {
            "payload_parse_failed": int(conn.execute("SELECT count(*) FROM trajectories WHERE parse_ok_steps<steps").fetchone()[0]),
            "left_censored": int(conn.execute("SELECT count(*) FROM trajectories WHERE left_censored=1").fetchone()[0]),
            "right_censored": int(conn.execute("SELECT count(*) FROM trajectories WHERE right_censored=1").fetchone()[0]),
            "truncated": int(conn.execute("SELECT count(*) FROM trajectories WHERE truncated_steps>0").fetchone()[0]),
            "missing_session_identity": int(conn.execute("SELECT count(*) FROM trajectories WHERE thread_id_present_steps<steps").fetchone()[0]),
            "missing_turn_identity": int(conn.execute("SELECT count(*) FROM trajectories WHERE turn_id_present_steps<steps").fetchone()[0]),
            "missing_terminal": int(conn.execute("SELECT count(*) FROM trajectories WHERE terminal_present_steps<steps").fetchone()[0]),
            "missing_usage": int(conn.execute("SELECT count(*) FROM trajectories WHERE usage_present_steps<steps").fetchone()[0]),
            "unmatched_tool_calls": int(conn.execute("SELECT count(*) FROM trajectories WHERE matched_tool_calls<tool_calls").fetchone()[0]),
            "orphan_tool_results": int(conn.execute("SELECT count(*) FROM trajectories WHERE orphan_tool_results>0").fetchone()[0]),
        }
        tokens = conn.execute(
            "SELECT coalesce(sum(input_tokens),0),coalesce(sum(cached_input_tokens),0),"
            "coalesce(sum(cache_write_tokens),0),coalesce(sum(uncached_input_tokens),0),"
            "coalesce(sum(output_tokens),0),coalesce(sum(reasoning_tokens),0),"
            "coalesce(sum(total_tokens),0) FROM trajectories"
        ).fetchone()
    return {
        "format": RELEASE_FORMAT,
        "schema_version": RELEASE_SCHEMA_VERSION,
        "release_id": release_id,
        "directory_name": output_name,
        "created_at_utc": utc_now(),
        "selection": {"model": model_exact, "mode": "complete-session"},
        "session_atomic": True,
        "session_split_count": 0,
        "target_part_bytes": target_part_bytes,
        "records": int(selected[1]),
        "sessions": int(selected[0]),
        "raw_bytes": int(selected[2]),
        "actual_window": {"start": selected[3], "end": selected[4]},
        "models_present": selected_models,
        "sensitive_raw_data": True,
        "semantic_reward_available": False,
        "score_semantics": "observed session trace completeness; not task correctness",
        "session_quality": {
            "policy_version": QUALITY_POLICY_VERSION,
            "average": quality[0],
            "minimum": quality[1],
            "maximum": quality[2],
            "grades": grades,
            "incomplete_reasons": incomplete_reasons,
        },
        "token_totals": dict(
            zip(
                (
                    "input",
                    "cached_input",
                    "cache_write",
                    "uncached_input",
                    "output",
                    "reasoning",
                    "total",
                ),
                map(int, tokens),
            )
        ),
        "source_inputs": [
            {"file": path.name, "bytes": path.stat().st_size} for path in inputs
        ],
        "source_records_scanned": scanned_records,
        "duplicate_records_omitted": duplicate_records,
        "oversized_session_count": len(oversized_sessions),
        "oversized_session_ids": list(oversized_sessions),
        "parts": list(part_summaries),
        "catalog": {
            "file": catalog_path.name,
            "schema_version": CATALOG_SCHEMA_VERSION,
            "bytes": catalog_path.stat().st_size,
            "sha256": _file_sha256(catalog_path),
            "validation_status": catalog["validation_status"],
        },
        "validation_status": catalog["validation_status"],
    }


def _release_child(root: Path, name: str) -> Path:
    if Path(name).name != name or not name or name in {".", ".."}:
        raise RuntimeError(f"release entry is not a plain file name: {name!r}")
    path = (root / name).resolve()
    if path.parent != root:
        raise RuntimeError(f"release entry escapes its directory: {name!r}")
    return path


def _verify_release(root: Path, manifest: dict[str, Any]) -> None:
    part_files = [_release_child(root, str(part["file"])) for part in manifest["parts"]]
    catalog_path = _release_child(root, str(manifest["catalog"]["file"]))
    if manifest.get("validation_status") not in {"pass", "warn"}:
        raise RuntimeError(f"invalid release validation status: {manifest.get('validation_status')!r}")
    part_records = 0
    for part, path in zip(manifest["parts"], part_files):
        if not path.is_file() or path.stat().st_size != int(part["bytes"]):
            raise RuntimeError(f"release part size mismatch: {path}")
        if _file_sha256(path) != part["sha256"]:
            raise RuntimeError(f"release part checksum mismatch: {path}")
        with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as conn:
            integrity = str(conn.execute("PRAGMA integrity_check").fetchone()[0])
            foreign = len(conn.execute("PRAGMA foreign_key_check").fetchall())
            records_in_part = int(conn.execute("SELECT count(*) FROM interactions").fetchone()[0])
            if integrity != "ok" or foreign:
                raise RuntimeError(f"release part SQLite validation failed: {path}")
            if "records" in part and records_in_part != int(part["records"]):
                raise RuntimeError(f"release part record count mismatch: {path}")
            part_records += records_in_part
    if _file_sha256(catalog_path) != manifest["catalog"]["sha256"]:
        raise RuntimeError("session catalog checksum mismatch")
    with sqlite3.connect(f"file:{catalog_path}?mode=ro", uri=True) as conn:
        integrity = str(conn.execute("PRAGMA integrity_check").fetchone()[0])
        foreign = len(conn.execute("PRAGMA foreign_key_check").fetchall())
        if integrity != "ok" or foreign:
            raise RuntimeError("session catalog SQLite validation failed")
        split_sessions = int(
            conn.execute(
                "SELECT count(*) FROM (SELECT traj_id FROM steps GROUP BY traj_id "
                "HAVING count(DISTINCT shard_id)>1)"
            ).fetchone()[0]
        )
        records = int(conn.execute("SELECT count(*) FROM steps").fetchone()[0])
        sessions = int(conn.execute("SELECT count(*) FROM trajectories").fetchone()[0])
    if split_sessions:
        raise RuntimeError(f"release split {split_sessions} sessions across parts")
    if records != int(manifest["records"]) or sessions != int(manifest["sessions"]):
        raise RuntimeError("release manifest counts do not match session catalog")
    if part_records != records:
        raise RuntimeError("release part records do not match session catalog")


def _verify_sha256s(
    root: Path,
    sums_path: Path,
    *,
    expected_names: set[str] | None = None,
) -> None:
    seen: set[str] = set()
    for line in sums_path.read_text(encoding="ascii").splitlines():
        expected, separator, name = line.partition("  ")
        if not separator or not name or Path(name).name != name:
            raise RuntimeError("invalid SHA256SUMS entry")
        if name in seen:
            raise RuntimeError(f"duplicate SHA256SUMS entry: {name}")
        seen.add(name)
        path = _release_child(root, name)
        if not path.is_file() or _file_sha256(path) != expected:
            raise RuntimeError(f"SHA256SUMS mismatch: {name}")
    if expected_names is not None and seen != set(expected_names):
        missing = sorted(set(expected_names) - seen)
        unexpected = sorted(seen - set(expected_names))
        raise RuntimeError(f"SHA256SUMS file set mismatch: missing={missing}, unexpected={unexpected}")


def _safe_name(value: str) -> str:
    safe = "".join(
        character
        if character.isascii() and (character.isalnum() or character in "._-")
        else "-"
        for character in value
    )
    return safe.strip(".-") or "model"


def _stat_identity(path: Path) -> tuple[int, int, int, int]:
    stat = path.stat()
    return stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns


def _assert_inputs_unchanged(expected: dict[Path, tuple[int, int, int, int]]) -> None:
    for path, identity in expected.items():
        if _stat_identity(path) != identity:
            raise RuntimeError(f"raw SQLite input changed during release build: {path}")


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
