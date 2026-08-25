from __future__ import annotations

import argparse
import json
import os
import signal
import tempfile
import threading
from pathlib import Path
from typing import Iterable

from .audit import audit_root
from .exporter import export_sealed
from .release import build_session_release
from .server import serve
from .sharded_export import build_sharded_export
from .store import CaptureStore, StoreConfig, StoreError
from .trajectory import build_trajectory_catalog


def _store_config(args: argparse.Namespace) -> StoreConfig:
    return StoreConfig(
        root=Path(args.root),
        state_root=Path(args.state_root) if args.state_root else None,
        segment_max_bytes=int(args.segment_max_mib * 1024 * 1024),
        segment_max_age_seconds=args.segment_max_age_seconds,
        queue_max_items=args.queue_max_items,
        batch_records=args.batch_records,
        batch_wait_ms=args.batch_wait_ms,
        fsync_each_batch=not args.no_fsync,
        max_envelope_bytes=int(args.max_envelope_mib * 1024 * 1024),
        sqlite_journal_mode=args.sqlite_journal_mode,
    )


def run_serve(args: argparse.Namespace) -> int:
    store = CaptureStore(_store_config(args))
    stop = threading.Event()

    def request_stop(_signum: int, _frame: object) -> None:
        stop.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    print(json.dumps({"event": "server_ready", "host": args.host, "port": args.port, "root": str(store.root)}), flush=True)
    try:
        serve(
            store,
            args.host,
            args.port,
            stop,
            max_connections=args.max_connections,
            max_inflight_body_bytes=int(args.max_inflight_body_mib * 1024 * 1024),
            body_budget_wait_seconds=args.body_budget_wait_seconds,
        )
    finally:
        store.close()
    return 0


def run_audit(args: argparse.Namespace) -> int:
    result = audit_root(
        Path(args.root),
        ledger_path=Path(args.ledger) if args.ledger else None,
        verify_payloads=not args.structural_only,
    )
    print(json.dumps(result, ensure_ascii=True, indent=2, sort_keys=True))
    return 0 if result["ok"] else 2


def run_export(args: argparse.Namespace) -> int:
    result = export_sealed(
        Path(args.root),
        Path(args.output),
        ledger_path=Path(args.ledger) if args.ledger else None,
        compression_codec=args.compression_codec,
        compression_level=args.compression_level,
        compression_workers=args.compression_workers,
        compression_batch_bytes=int(args.compression_batch_mib * 1024 * 1024),
        raw_chunk_bytes=int(args.raw_chunk_mib * 1024 * 1024),
        staging_sync=args.staging_sync,
        replace=args.replace,
    )
    print(json.dumps(result, ensure_ascii=True, indent=2, sort_keys=True))
    return 0


def run_trajectory(args: argparse.Namespace) -> int:
    result = build_trajectory_catalog(
        [Path(value) for value in args.input],
        Path(args.output),
        model_exact=args.model,
        projection_mode=args.projection_mode,
        replace=args.replace,
    )
    print(json.dumps(result, ensure_ascii=True, indent=2, sort_keys=True))
    return 0


def run_export_sharded(args: argparse.Namespace) -> int:
    result = build_sharded_export(
        Path(args.root),
        Path(args.output),
        ledger_path=Path(args.ledger) if args.ledger else None,
        shard_count=args.shards,
        max_writers=args.max_writers,
        compression_codec=args.compression_codec,
        compression_level=args.compression_level,
        compression_workers_per_writer=args.compression_workers_per_writer,
        compression_batch_bytes=int(args.compression_batch_mib * 1024 * 1024),
        raw_chunk_bytes=int(args.raw_chunk_mib * 1024 * 1024),
        staging_sync=args.staging_sync,
    )
    print(json.dumps(result, ensure_ascii=True, indent=2, sort_keys=True))
    return 0


def run_release(args: argparse.Namespace) -> int:
    result = build_session_release(
        [Path(value) for value in args.input],
        Path(args.output),
        model_exact=args.model,
        target_part_bytes=int(args.target_part_gib * 1024 * 1024 * 1024),
        release_id=args.release_id,
    )
    print(json.dumps(result, ensure_ascii=True, indent=2, sort_keys=True))
    return 0


def fixture(capture_id: str, *, status: int = 200, pad: int = 0) -> dict:
    return {
        "captureId": capture_id,
        "receivedAt": "2026-08-24T00:00:00Z",
        "startedAt": "2026-08-24T00:00:00Z",
        "finishedAt": "2026-08-24T00:00:01Z",
        "method": "POST",
        "inboundPath": "/v1/responses",
        "proxiedPath": "/v1/responses",
        "apiKeyFingerprint": "self-test-key",
        "requestBody": {"kind": "json", "value": {"model": "model-self-test", "input": "x" * pad}},
        "requestTruncated": False,
        "responseStatus": status,
        "responseBody": {"kind": "json", "value": {"status": "completed" if status < 400 else "failed"}},
        "responseTruncated": False,
        "stream": False,
        "captureError": None,
    }


def run_self_test(_args: argparse.Namespace) -> int:
    with tempfile.TemporaryDirectory(prefix="trace-pipeline-self-test-") as temporary:
        root = Path(temporary) / "capture"
        store = CaptureStore(StoreConfig(root=root, segment_max_bytes=1400, batch_records=8, batch_wait_ms=5))
        first = store.submit(fixture("cap-self-test-1", status=200, pad=300))
        failure_sample = store.submit(fixture("cap-self-test-2", status=503, pad=300))
        duplicate = store.submit(fixture("cap-self-test-1", status=200, pad=300))
        conflict_seen = False
        changed = fixture("cap-self-test-1", status=429, pad=10)
        try:
            store.submit(changed)
        except StoreError:
            conflict_seen = True
        health = store.health()
        store.close()
        audit = audit_root(root)
        output = Path(temporary) / "training.sqlite"
        export = export_sealed(root, output)
        catalog_output = Path(temporary) / "trajectory-catalog.sqlite"
        catalog = build_trajectory_catalog(
            [output],
            catalog_output,
            model_exact="model-self-test",
            projection_mode="exact-model-projection",
        )
        release_output = Path(temporary) / "session-release"
        release = build_session_release(
            [output],
            release_output,
            model_exact="model-self-test",
            target_part_bytes=10 * 1024 * 1024,
            release_id="self-test-release",
        )
        result = {
            "ok": all(
                [
                    first.state == "accepted",
                    failure_sample.state == "accepted",
                    duplicate.duplicate,
                    conflict_seen,
                    health["captures"] == 2,
                    audit["ok"],
                    export["records"] == 2,
                    catalog["records"] == 2,
                    catalog["validation_status"] in {"pass", "warn"},
                    release["records"] == 2,
                    release["validation_status"] in {"pass", "warn"},
                ]
            ),
            "accepted_error_response": failure_sample.state == "accepted",
            "duplicate_idempotent": duplicate.duplicate,
            "conflict_rejected": conflict_seen,
            "audit": audit,
            "export": export,
            "trajectory_catalog": catalog,
            "session_release": release,
        }
        print(json.dumps(result, ensure_ascii=True, indent=2, sort_keys=True))
        return 0 if result["ok"] else 2


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(description="Durable agent trace training pipeline")
    sub = command.add_subparsers(dest="command", required=True)

    serve_parser = sub.add_parser("serve", help="run the compatible POST /capture service")
    serve_parser.add_argument("--root", required=True)
    serve_parser.add_argument("--state-root")
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=3010)
    serve_parser.add_argument("--max-connections", type=int, default=256)
    serve_parser.add_argument("--max-inflight-body-mib", type=float, default=4096)
    serve_parser.add_argument("--body-budget-wait-seconds", type=float, default=1.0)
    serve_parser.add_argument("--segment-max-mib", type=float, default=512)
    serve_parser.add_argument("--segment-max-age-seconds", type=int, default=3600)
    serve_parser.add_argument("--queue-max-items", type=int, default=2048)
    serve_parser.add_argument("--batch-records", type=int, default=64)
    serve_parser.add_argument("--batch-wait-ms", type=int, default=25)
    serve_parser.add_argument("--max-envelope-mib", type=float, default=1024)
    serve_parser.add_argument("--sqlite-journal-mode", choices=("WAL", "DELETE"), default="WAL")
    serve_parser.add_argument("--no-fsync", action="store_true", help="test-only: acknowledge before an fsync boundary")
    serve_parser.set_defaults(func=run_serve)

    audit_parser = sub.add_parser("audit", help="audit the ledger and immutable payload locators")
    audit_parser.add_argument("--root", required=True)
    audit_parser.add_argument("--ledger")
    audit_parser.add_argument("--structural-only", action="store_true")
    audit_parser.set_defaults(func=run_audit)

    export_parser = sub.add_parser("export", help="export sealed captures to one validated SQLite file")
    export_parser.add_argument("--root", required=True)
    export_parser.add_argument("--ledger")
    export_parser.add_argument("--output", required=True)
    export_parser.add_argument(
        "--compression-codec",
        choices=("zstd", "zlib"),
        default="zlib",
    )
    export_parser.add_argument("--compression-level", type=int, default=1)
    export_parser.add_argument(
        "--compression-workers",
        type=int,
        default=min(8, os.cpu_count() or 1),
    )
    export_parser.add_argument("--compression-batch-mib", type=float, default=64)
    export_parser.add_argument("--raw-chunk-mib", type=float, default=4)
    export_parser.add_argument(
        "--staging-sync",
        choices=("fast", "full"),
        default="fast",
        help="fast is safe for unpublished rebuildable staging; final output is fsynced",
    )
    export_parser.add_argument("--replace", action="store_true")
    export_parser.set_defaults(func=run_export)

    sharded_export_parser = sub.add_parser(
        "export-sharded",
        help="export sealed captures into parallel validated raw SQLite shards",
    )
    sharded_export_parser.add_argument("--root", required=True)
    sharded_export_parser.add_argument("--ledger")
    sharded_export_parser.add_argument("--output", required=True)
    sharded_export_parser.add_argument("--shards", type=int, default=4)
    sharded_export_parser.add_argument("--max-writers", type=int, default=4)
    sharded_export_parser.add_argument(
        "--compression-codec",
        choices=("zstd", "zlib"),
        default="zlib",
    )
    sharded_export_parser.add_argument("--compression-level", type=int, default=1)
    sharded_export_parser.add_argument("--compression-workers-per-writer", type=int, default=2)
    sharded_export_parser.add_argument("--compression-batch-mib", type=float, default=256)
    sharded_export_parser.add_argument("--raw-chunk-mib", type=float, default=4)
    sharded_export_parser.add_argument(
        "--staging-sync",
        choices=("fast", "full"),
        default="fast",
    )
    sharded_export_parser.set_defaults(func=run_export_sharded)

    trajectory_parser = sub.add_parser(
        "trajectory",
        help="build a validated trajectory catalog from raw SQLite exports",
    )
    trajectory_parser.add_argument("--input", action="append", required=True)
    trajectory_parser.add_argument("--output", required=True)
    trajectory_parser.add_argument("--model", required=True)
    trajectory_parser.add_argument(
        "--projection-mode",
        choices=("exact-model-projection", "complete-thread"),
        default="exact-model-projection",
    )
    trajectory_parser.add_argument("--replace", action="store_true")
    trajectory_parser.set_defaults(func=run_trajectory)

    release_parser = sub.add_parser(
        "release",
        help="build an atomic complete-session release directory from raw SQLite inputs",
    )
    release_parser.add_argument("--input", action="append", required=True)
    release_parser.add_argument("--output", required=True)
    release_parser.add_argument("--model", required=True)
    release_parser.add_argument("--release-id")
    release_parser.add_argument("--target-part-gib", type=float, default=10.0)
    release_parser.set_defaults(func=run_release)

    self_test = sub.add_parser("self-test", help="run an isolated durability and delivery smoke test")
    self_test.set_defaults(func=run_self_test)
    return command


def main(argv: Iterable[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if (
        getattr(args, "segment_max_mib", 1) <= 0
        or getattr(args, "max_envelope_mib", 1) <= 0
        or getattr(args, "max_inflight_body_mib", 1) <= 0
        or getattr(args, "raw_chunk_mib", 1) <= 0
        or getattr(args, "compression_batch_mib", 1) <= 0
        or getattr(args, "compression_workers", 1) <= 0
        or getattr(args, "compression_workers_per_writer", 1) <= 0
        or getattr(args, "shards", 1) <= 0
        or getattr(args, "max_writers", 1) <= 0
        or getattr(args, "target_part_gib", 1) <= 0
    ):
        raise SystemExit("size limits must be positive")
    return int(args.func(args))
