#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sqlite3
import tempfile
import time
from pathlib import Path

from trace_pipeline.compression import CompressionError, decompress_chunk
from trace_pipeline.exporter import export_sealed
from trace_pipeline.sharded_export import build_sharded_export
from trace_pipeline.store import CaptureStore, StoreConfig


MIB = 1024 * 1024


def replay_sample(input_sqlite: Path, store: CaptureStore, raw_budget: int) -> tuple[int, int]:
    resolved = input_sqlite.resolve()
    conn = sqlite3.connect(f"file:{resolved}?mode=ro", uri=True)
    conn.execute("PRAGMA query_only=ON")
    records = 0
    raw_total = 0
    current_record: int | None = None
    expected_index = 0
    raw = bytearray()

    def submit_current() -> None:
        nonlocal records, raw_total, raw
        if current_record is None:
            return
        encoded = bytes(raw).strip()
        value = json.loads(encoded)
        store.submit_raw(encoded, value=value)
        records += 1
        raw_total += len(encoded)
        raw = bytearray()

    try:
        for record_id, chunk_index, codec, raw_bytes, payload in conn.execute(
            "SELECT record_id,chunk_index,codec,raw_bytes,payload "
            "FROM interaction_chunks ORDER BY record_id,chunk_index"
        ):
            record_id = int(record_id)
            chunk_index = int(chunk_index)
            if current_record is not None and record_id != current_record:
                submit_current()
                if raw_total >= raw_budget:
                    break
                expected_index = 0
            if current_record != record_id:
                current_record = record_id
            if chunk_index != expected_index:
                raise RuntimeError(f"invalid source chunk sequence for record {record_id}")
            expected = int(raw_bytes)
            decoded = decompress_chunk(bytes(payload), str(codec), expected_raw_bytes=expected)
            if len(decoded) != expected:
                raise RuntimeError(f"source chunk length mismatch for record {record_id}")
            raw.extend(decoded)
            expected_index += 1
        else:
            submit_current()
    finally:
        conn.close()
    if not records:
        raise RuntimeError("input SQLite contains no replayable interaction chunks")
    return records, raw_total


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Isolated sealed-segment to validated-SQLite export benchmark",
    )
    parser.add_argument("--input-sqlite", required=True)
    parser.add_argument("--sample-mib", type=float, default=256)
    parser.add_argument("--work-root")
    parser.add_argument("--codec", choices=("zstd", "zlib"), default="zstd")
    parser.add_argument("--level", type=int, default=1)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--shards", type=int, default=1)
    parser.add_argument("--max-writers", type=int, default=4)
    parser.add_argument("--chunk-mib", type=float, default=4)
    parser.add_argument("--batch-mib", type=float, default=256)
    parser.add_argument("--staging-sync", choices=("fast", "full"), default="fast")
    parser.add_argument("--target-mib-per-second", type=float, default=0)
    args = parser.parse_args()
    if min(
        args.sample_mib,
        args.chunk_mib,
        args.batch_mib,
        args.workers,
        args.shards,
        args.max_writers,
    ) <= 0:
        raise SystemExit("workers and byte sizes must be positive")

    try:
        with tempfile.TemporaryDirectory(
            prefix="trace-export-benchmark-",
            dir=args.work_root,
        ) as temporary:
            base = Path(temporary)
            capture_root = base / "capture"
            state_root = base / "state"
            store = CaptureStore(
                StoreConfig(
                    root=capture_root,
                    state_root=state_root,
                    segment_max_bytes=128 * MIB,
                    batch_records=64,
                    batch_wait_ms=5,
                    fsync_each_batch=False,
                    max_envelope_bytes=1024 * MIB,
                )
            )
            import_started = time.monotonic()
            try:
                records, raw_bytes = replay_sample(
                    Path(args.input_sqlite),
                    store,
                    int(args.sample_mib * MIB),
                )
            finally:
                store.close()
            import_elapsed = time.monotonic() - import_started
            if args.shards == 1:
                output = base / "delivery.sqlite"
                result = export_sealed(
                    capture_root,
                    output,
                    ledger_path=state_root / "capture-ledger.sqlite",
                    compression_codec=args.codec,
                    compression_level=args.level,
                    compression_workers=args.workers,
                    compression_batch_bytes=int(args.batch_mib * MIB),
                    raw_chunk_bytes=int(args.chunk_mib * MIB),
                    staging_sync=args.staging_sync,
                )
            else:
                output = base / "delivery-shards"
                result = build_sharded_export(
                    capture_root,
                    output,
                    ledger_path=state_root / "capture-ledger.sqlite",
                    shard_count=args.shards,
                    max_writers=args.max_writers,
                    compression_codec=args.codec,
                    compression_level=args.level,
                    compression_workers_per_writer=args.workers,
                    compression_batch_bytes=int(args.batch_mib * MIB),
                    raw_chunk_bytes=int(args.chunk_mib * MIB),
                    staging_sync=args.staging_sync,
                )
            throughput = float(result["raw_mib_per_second"])
            target_pass = (
                args.target_mib_per_second <= 0
                or throughput >= args.target_mib_per_second
            )
            payload = {
                "ok": (
                    result["records"] == records
                    and result["raw_bytes"] == raw_bytes
                    and target_pass
                ),
                "scope": "sealed_segment_read_hash_compress_sqlite_check_fsync_sha256",
                "source_storage_cache_state": "uncontrolled",
                "source_records": records,
                "source_raw_bytes": raw_bytes,
                "fixture_import_seconds_excluded": round(import_elapsed, 6),
                "shards": args.shards,
                "max_writers": min(args.max_writers, args.shards),
                "compression_workers_per_writer": args.workers,
                "target_mib_per_second": args.target_mib_per_second or None,
                "target_pass": target_pass,
                "export": result,
            }
            print(json.dumps(payload, indent=2, sort_keys=True))
            return 0 if payload["ok"] else 2
    except (CompressionError, OSError, RuntimeError, sqlite3.Error, ValueError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
