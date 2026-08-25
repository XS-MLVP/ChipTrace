from __future__ import annotations

import concurrent.futures
import json
import os
import shutil
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any

from .exporter import COMPRESSION_BATCH_BYTES, RAW_CHUNK_BYTES, export_sealed
from .model import utc_now


SHARDED_EXPORT_FORMAT = "router-v2-training-raw-sharded-sqlite-v1"


def _ledger_path(root: Path, ledger_path: Path | None) -> Path:
    if ledger_path is not None:
        return Path(ledger_path).resolve()
    nested = root / "state" / "capture-ledger.sqlite"
    return nested if nested.exists() else root / "capture-ledger.sqlite"


def _balanced_segment_groups(segments: list[sqlite3.Row], shard_count: int) -> list[list[int]]:
    width = min(shard_count, len(segments))
    groups: list[list[int]] = [[] for _index in range(width)]
    totals = [0] * width
    for row in sorted(segments, key=lambda item: (-int(item["bytes"]), int(item["segment_id"]))):
        target = min(range(width), key=lambda index: (totals[index], index))
        groups[target].append(int(row["segment_id"]))
        totals[target] += int(row["bytes"])
    for group in groups:
        group.sort()
    return groups


def _export_part(arguments: dict[str, Any]) -> dict[str, Any]:
    return export_sealed(**arguments)


def build_sharded_export(
    root: Path,
    output: Path,
    *,
    ledger_path: Path | None = None,
    shard_count: int = 4,
    max_writers: int = 4,
    compression_codec: str = "zlib",
    compression_level: int = 1,
    compression_workers_per_writer: int = 2,
    compression_batch_bytes: int = COMPRESSION_BATCH_BYTES,
    raw_chunk_bytes: int = RAW_CHUNK_BYTES,
    staging_sync: str = "fast",
) -> dict[str, Any]:
    root = Path(root).resolve()
    output = Path(output).resolve()
    database = _ledger_path(root, ledger_path)
    if min(shard_count, max_writers, compression_workers_per_writer) <= 0:
        raise ValueError("shard_count, max_writers, and compression workers must be positive")
    if output.exists():
        raise FileExistsError(f"output exists: {output}")
    if not database.exists():
        raise FileNotFoundError(f"capture ledger does not exist: {database}")

    source = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    source.row_factory = sqlite3.Row
    source.execute("PRAGMA query_only=ON")
    source.execute("BEGIN")
    try:
        segments = source.execute(
            "SELECT segment_id,path,bytes,records,sha256 FROM segments "
            "WHERE state IN ('sealed','archived') ORDER BY segment_id"
        ).fetchall()
        if not segments:
            raise RuntimeError("no sealed segments are available")
        expected_records, expected_raw_bytes = source.execute(
            "SELECT count(*),coalesce(sum(c.length-1),0) FROM captures c "
            "JOIN segments s USING(segment_id) WHERE s.state IN ('sealed','archived')"
        ).fetchone()
    finally:
        source.close()

    groups = _balanced_segment_groups(segments, shard_count)
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = output.with_name(f".{output.name}.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp")
    staging.mkdir(mode=0o700)
    started = time.monotonic()
    results: list[dict[str, Any]] = []
    try:
        jobs = []
        for index, segment_ids in enumerate(groups, start=1):
            jobs.append(
                {
                    "root": root,
                    "output": staging / f"raw-part-{index:03d}.sqlite",
                    "ledger_path": database,
                    "compression_codec": compression_codec,
                    "compression_level": compression_level,
                    "compression_workers": compression_workers_per_writer,
                    "compression_batch_bytes": compression_batch_bytes,
                    "raw_chunk_bytes": raw_chunk_bytes,
                    "staging_sync": staging_sync,
                    "segment_ids": segment_ids,
                }
            )
        writer_count = min(max_writers, len(jobs))
        with concurrent.futures.ProcessPoolExecutor(max_workers=writer_count) as pool:
            futures = [pool.submit(_export_part, job) for job in jobs]
            results = [future.result() for future in futures]

        expected_segment_ids = {int(row["segment_id"]) for row in segments}
        delivered_segment_ids: set[int] = set()
        overlap = 0
        for result in results:
            part_ids = {int(value) for value in result["segment_ids"]}
            overlap += len(delivered_segment_ids & part_ids)
            delivered_segment_ids.update(part_ids)
        records = sum(int(result["records"]) for result in results)
        raw_bytes = sum(int(result["raw_bytes"]) for result in results)
        stored_bytes = sum(int(result["stored_bytes"]) for result in results)
        checks = {
            "segment_overlap": (overlap, 0),
            "segment_coverage": (len(delivered_segment_ids), len(expected_segment_ids)),
            "segment_identity": (delivered_segment_ids, expected_segment_ids),
            "record_count": (records, int(expected_records)),
            "raw_bytes": (raw_bytes, int(expected_raw_bytes)),
        }
        if any(observed != expected for observed, expected in checks.values()):
            raise RuntimeError(f"sharded export conservation failed: {checks}")

        part_build_elapsed = time.monotonic() - started
        parts = []
        for index, result in enumerate(results, start=1):
            parts.append(
                {
                    "file": f"raw-part-{index:03d}.sqlite",
                    "bytes": int(result["output_bytes"]),
                    "sha256": result["sha256"],
                    "records": int(result["records"]),
                    "raw_bytes": int(result["raw_bytes"]),
                    "stored_bytes": int(result["stored_bytes"]),
                    "elapsed_seconds": result["elapsed_seconds"],
                    "raw_mib_per_second": result["raw_mib_per_second"],
                    "compression_ratio": result["compression_ratio"],
                    "segment_ids": result["segment_ids"],
                }
            )
        manifest = {
            "format": SHARDED_EXPORT_FORMAT,
            "created_at_utc": utc_now(),
            "source_root": str(root),
            "source_ledger": str(database),
            "selection": "all-sealed-at-snapshot",
            "session_atomic": False,
            "session_atomic_note": "run release to build complete-session delivery parts",
            "compression": f"{compression_codec}-{compression_level}",
            "shards": len(parts),
            "max_writers": writer_count,
            "compression_workers_per_writer": compression_workers_per_writer,
            "records": records,
            "raw_bytes": raw_bytes,
            "stored_bytes": stored_bytes,
            "part_build_elapsed_seconds": round(part_build_elapsed, 6),
            "part_build_raw_mib_per_second": round(
                raw_bytes / part_build_elapsed / 1024 / 1024,
                3,
            ),
            "parts": parts,
            "validation_status": "pass",
            "sensitive_raw_data": True,
            "semantic_reward_available": False,
        }
        manifest_path = staging / "manifest.json"
        _write_file(
            manifest_path,
            (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode(),
        )
        checksum_lines = [f"{part['sha256']}  {part['file']}" for part in parts]
        checksum_lines.append(f"{_sha256_file(manifest_path)}  manifest.json")
        _write_file(staging / "SHA256SUMS", ("\n".join(checksum_lines) + "\n").encode())
        _fsync_directory(staging)
        os.replace(staging, output)
        _fsync_directory(output.parent)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise

    elapsed = time.monotonic() - started
    return {
        "ok": True,
        "output": str(output),
        "parts": len(results),
        "records": sum(int(result["records"]) for result in results),
        "raw_bytes": sum(int(result["raw_bytes"]) for result in results),
        "stored_bytes": sum(int(result["stored_bytes"]) for result in results),
        "elapsed_seconds": round(elapsed, 6),
        "raw_mib_per_second": round(
            int(manifest["raw_bytes"]) / elapsed / 1024 / 1024,
            3,
        ),
        "part_build_elapsed_seconds": manifest["part_build_elapsed_seconds"],
        "part_build_raw_mib_per_second": manifest["part_build_raw_mib_per_second"],
        "validation_status": "pass",
    }


def _write_file(path: Path, value: bytes) -> None:
    with path.open("xb") as handle:
        handle.write(value)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(path, 0o600)


def _sha256_file(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(4 * 1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
