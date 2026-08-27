#!/usr/bin/env python3
from __future__ import annotations

import argparse
import concurrent.futures
import json
import tempfile
import time
from pathlib import Path

from chiptrace.audit import audit_root
from chiptrace.cli import fixture
from chiptrace.store import CaptureStore, StoreConfig


def main() -> int:
    parser = argparse.ArgumentParser(description="Core capture durability benchmark")
    parser.add_argument("--root")
    parser.add_argument("--records", type=int, default=2000)
    parser.add_argument("--payload-bytes", type=int, default=4096)
    parser.add_argument("--workers", type=int, default=16)
    parser.add_argument("--no-fsync", action="store_true")
    args = parser.parse_args()
    temporary = tempfile.TemporaryDirectory(prefix="chiptrace-benchmark-") if not args.root else None
    root = Path(args.root) if args.root else Path(temporary.name) / "capture"
    store = CaptureStore(
        StoreConfig(
            root=root,
            batch_records=64,
            batch_wait_ms=10,
            queue_max_items=max(args.records, 256),
            fsync_each_batch=not args.no_fsync,
        )
    )
    values = [fixture(f"cap-benchmark-{index:08d}", pad=args.payload_bytes) for index in range(args.records)]
    started = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        list(pool.map(store.submit, values))
    elapsed = time.monotonic() - started
    health = store.health()
    store.close()
    audit = audit_root(root, verify_payloads=False)
    result = {
        "ok": audit["ok"] and health["captures"] == args.records,
        "records": args.records,
        "payload_bytes": args.payload_bytes,
        "workers": args.workers,
        "fsync": not args.no_fsync,
        "elapsed_seconds": round(elapsed, 6),
        "records_per_second": round(args.records / elapsed, 3),
        "logical_mib_per_second": round(args.records * args.payload_bytes / elapsed / 1024 / 1024, 3),
        "audit": audit,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    if temporary is not None:
        temporary.cleanup()
    return 0 if result["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
