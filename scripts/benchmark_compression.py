#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import os
import sqlite3
import time
from pathlib import Path

from trace_pipeline.compression import (
    ChunkCompressor,
    CompressionError,
    decompress_chunk,
)


MIB = 1024 * 1024


def trace_json_chunk(size: int, index: int) -> bytes:
    prefix = (
        f'{{"captureId":"cap-benchmark-{index:04d}","model":"gpt-next-sol",'
        '"requestBody":{"kind":"json","value":{"input":"'
    ).encode()
    middle = b'","opaque":"'
    suffix = b'"}},"responseStatus":200}\n'
    body_bytes = max(0, size - len(prefix) - len(middle) - len(suffix))
    opaque_bytes = int(body_bytes * 0.40)
    text_bytes = body_bytes - opaque_bytes
    phrase = b"session trace tool call result completed reasoning input output "
    text = (phrase * math.ceil(text_bytes / len(phrase)))[:text_bytes]
    entropy = hashlib.shake_256(f"trace-json-{index}".encode()).digest(
        math.ceil(opaque_bytes * 3 / 4) + 3
    )
    opaque = base64.b64encode(entropy)[:opaque_bytes]
    return prefix + text + middle + opaque + suffix


def make_chunk(profile: str, size: int, index: int) -> bytes:
    if profile == "trace-json":
        return trace_json_chunk(size, index)
    if profile == "incompressible":
        return hashlib.shake_256(f"trace-benchmark-{index}".encode()).digest(size)
    return bytes(size)


def load_sqlite_sample(path: Path, raw_budget: int) -> list[bytes]:
    resolved = path.resolve()
    conn = sqlite3.connect(f"file:{resolved}?mode=ro", uri=True)
    conn.execute("PRAGMA query_only=ON")
    chunks: list[bytes] = []
    sampled = 0
    try:
        for codec, raw_bytes, payload in conn.execute(
            "SELECT codec,raw_bytes,payload FROM interaction_chunks "
            "ORDER BY record_id,chunk_index"
        ):
            expected = int(raw_bytes)
            decoded = decompress_chunk(bytes(payload), str(codec), expected_raw_bytes=expected)
            if len(decoded) != expected:
                raise CompressionError("SQLite sample raw length mismatch")
            chunks.append(decoded)
            sampled += expected
            if sampled >= raw_budget:
                break
    finally:
        conn.close()
    if not chunks:
        raise CompressionError("SQLite sample contains no interaction chunks")
    return chunks


def main() -> int:
    parser = argparse.ArgumentParser(
        description="CPU-only bounded parallel chunk compression benchmark",
    )
    parser.add_argument("--codec", choices=("zstd", "zlib"), default="zstd")
    parser.add_argument("--level", type=int, default=1)
    parser.add_argument("--workers", type=int, default=min(8, os.cpu_count() or 1))
    parser.add_argument("--chunk-mib", type=float, default=4)
    parser.add_argument("--total-mib", type=float, default=512)
    parser.add_argument("--input-sqlite")
    parser.add_argument("--source-pool-mib", type=float, default=256)
    parser.add_argument(
        "--profile",
        choices=("trace-json", "incompressible", "zeros"),
        default="trace-json",
    )
    parser.add_argument("--target-mib-per-second", type=float, default=0)
    args = parser.parse_args()
    if (
        args.workers <= 0
        or args.chunk_mib <= 0
        or args.total_mib <= 0
        or args.source_pool_mib <= 0
    ):
        raise SystemExit("workers and byte sizes must be positive")

    chunk_bytes = max(1, int(args.chunk_mib * MIB))
    target_bytes = max(1, int(args.total_mib * MIB))
    try:
        if args.input_sqlite:
            source_pool = load_sqlite_sample(
                Path(args.input_sqlite),
                int(args.source_pool_mib * MIB),
            )
            profile = "sqlite-sample"
        else:
            chunks_needed = math.ceil(target_bytes / chunk_bytes)
            pool_width = min(chunks_needed, max(args.workers * 2, 8))
            source_pool = [
                make_chunk(args.profile, chunk_bytes, index)
                for index in range(pool_width)
            ]
            profile = args.profile
    except (CompressionError, OSError, sqlite3.Error) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2, sort_keys=True))
        return 2
    source_pool_raw_bytes = sum(map(len, source_pool))
    batch_width = min(len(source_pool), max(args.workers * 2, 8))
    raw_bytes = 0
    stored_bytes = 0
    batches = 0
    verification: tuple[bytes, bytes] | None = None
    pool_cursor = 0
    started = time.monotonic()
    try:
        with ChunkCompressor(args.codec, args.level, workers=args.workers) as compressor:
            while raw_bytes < target_bytes:
                batch = [
                    source_pool[(pool_cursor + offset) % len(source_pool)]
                    for offset in range(batch_width)
                ]
                pool_cursor = (pool_cursor + batch_width) % len(source_pool)
                payloads = compressor.compress_batch(batch)
                batches += 1
                raw_bytes += sum(map(len, batch))
                stored_bytes += sum(map(len, payloads))
                if verification is None:
                    verification = (batch[0], payloads[0])
    except (CompressionError, ValueError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2, sort_keys=True))
        return 2
    elapsed = time.monotonic() - started
    assert verification is not None
    decoded = decompress_chunk(
        verification[1],
        f"{args.codec}-{args.level}",
        expected_raw_bytes=len(verification[0]),
    )
    throughput = raw_bytes / elapsed / MIB
    target_pass = args.target_mib_per_second <= 0 or throughput >= args.target_mib_per_second
    result = {
        "ok": decoded == verification[0] and target_pass,
        "scope": "compression_cpu_only_no_sqlite_no_storage_io",
        "profile": profile,
        "input_sqlite": str(Path(args.input_sqlite).resolve()) if args.input_sqlite else None,
        "source_pool_chunks": len(source_pool),
        "source_pool_raw_bytes": source_pool_raw_bytes,
        "source_chunk_bytes_min": min(map(len, source_pool)),
        "source_chunk_bytes_average": round(source_pool_raw_bytes / len(source_pool), 3),
        "source_chunk_bytes_max": max(map(len, source_pool)),
        "codec": f"{args.codec}-{args.level}",
        "workers": args.workers,
        "synthetic_chunk_bytes": chunk_bytes if not args.input_sqlite else None,
        "raw_bytes": raw_bytes,
        "stored_bytes": stored_bytes,
        "compression_ratio": round(raw_bytes / stored_bytes, 6) if stored_bytes else None,
        "batches": batches,
        "elapsed_seconds": round(elapsed, 6),
        "raw_mib_per_second": round(throughput, 3),
        "stored_mib_per_second": round(stored_bytes / elapsed / MIB, 3),
        "target_mib_per_second": args.target_mib_per_second or None,
        "target_pass": target_pass,
        "round_trip_verified": decoded == verification[0],
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
