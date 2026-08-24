from __future__ import annotations

import concurrent.futures
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trace_pipeline.audit import audit_root
from trace_pipeline.cli import fixture
from trace_pipeline.exporter import export_sealed
from trace_pipeline.store import (
    CaptureStore,
    RecoveryError,
    StoreConfig,
    StoreError,
    _filesystem_type,
)


class CaptureStoreTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="trace-store-test-")
        self.root = Path(self.temporary.name) / "capture"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def store(self, **overrides: object) -> CaptureStore:
        config = {
            "root": self.root,
            "segment_max_bytes": 8 * 1024,
            "queue_max_items": 128,
            "batch_records": 64,
            "batch_wait_ms": 20,
        }
        config.update(overrides)
        return CaptureStore(StoreConfig(**config))

    def test_accepts_error_status_and_deduplicates(self) -> None:
        store = self.store()
        value = fixture("cap-error", status=503, pad=100)
        first = store.submit(value)
        second = store.submit(value)
        changed = fixture("cap-error", status=429, pad=100)
        with self.assertRaises(StoreError):
            store.submit(changed)
        health = store.health()
        store.close()

        self.assertEqual(first.state, "accepted")
        self.assertEqual(second.state, "duplicate")
        self.assertTrue(second.duplicate)
        self.assertEqual(health["captures"], 1)
        self.assertEqual(health["attempts"], 3)
        with sqlite3.connect(self.root / "state" / "capture-ledger.sqlite") as conn:
            self.assertEqual(conn.execute("SELECT response_status FROM captures").fetchone()[0], 503)
            states = dict(conn.execute("SELECT state,count(*) FROM capture_attempts GROUP BY state"))
        self.assertEqual(states, {"accepted": 1, "conflict": 1, "duplicate": 1})

    def test_concurrent_same_batch_is_idempotent(self) -> None:
        store = self.store(batch_wait_ms=100, batch_records=128)
        value = fixture("cap-concurrent-duplicate", pad=200)
        with concurrent.futures.ThreadPoolExecutor(max_workers=24) as pool:
            results = list(pool.map(lambda _index: store.submit(value), range(48)))
        health = store.health()
        store.close()

        self.assertEqual(sum(not item.duplicate for item in results), 1)
        self.assertEqual(sum(item.duplicate for item in results), 47)
        self.assertEqual(health["captures"], 1)
        self.assertEqual(health["attempts"], 48)
        self.assertTrue(audit_root(self.root)["ok"])

    def test_rotation_and_validated_export(self) -> None:
        store = self.store(segment_max_bytes=1300, batch_records=8)
        for index in range(12):
            store.submit(fixture(f"cap-rotate-{index:03d}", status=500 if index % 3 == 0 else 200, pad=250))
        store.close()
        audit = audit_root(self.root)
        output = Path(self.temporary.name) / "delivery.sqlite"
        result = export_sealed(self.root, output, raw_chunk_bytes=128)

        self.assertTrue(audit["ok"], audit)
        self.assertGreater(audit["segments"], 1)
        self.assertEqual(result["records"], 12)
        with sqlite3.connect(output) as conn:
            self.assertEqual(conn.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            self.assertEqual(conn.execute("SELECT count(*) FROM interactions").fetchone()[0], 12)
            self.assertEqual(conn.execute("SELECT count(*) FROM validation_results WHERE status!='pass'").fetchone()[0], 0)
            self.assertGreater(conn.execute("SELECT count(*) FROM interaction_chunks").fetchone()[0], 12)
            chunks = conn.execute(
                "SELECT payload FROM interaction_chunks WHERE record_id=1 ORDER BY chunk_index"
            ).fetchall()
            rebuilt = b"".join(__import__("zlib").decompress(row[0]) for row in chunks)
            self.assertEqual(json.loads(rebuilt)["captureId"], "cap-rotate-000")

    def test_export_cannot_replace_ledger_or_source_segment(self) -> None:
        store = self.store()
        store.submit(fixture("cap-export-target-guard", pad=50))
        store.close()
        ledger = self.root / "state" / "capture-ledger.sqlite"
        segment = next((self.root / "segments").glob("*.sealed.ndjson"))
        with self.assertRaises(ValueError):
            export_sealed(self.root, ledger, replace=True)
        with self.assertRaises(ValueError):
            export_sealed(self.root, segment, replace=True)

    def test_export_rejects_tampered_sealed_segment(self) -> None:
        store = self.store()
        store.submit(fixture("cap-export-integrity", pad=50))
        store.close()
        segment = next((self.root / "segments").glob("*.sealed.ndjson"))
        with segment.open("ab") as handle:
            handle.write(b"x")
        with self.assertRaises(RuntimeError):
            export_sealed(self.root, Path(self.temporary.name) / "tampered.sqlite")

    def test_recovers_crash_and_truncates_incomplete_open_tail(self) -> None:
        code = """
import os,sys
from pathlib import Path
from trace_pipeline.cli import fixture
from trace_pipeline.store import CaptureStore,StoreConfig
store=CaptureStore(StoreConfig(root=Path(sys.argv[1]),batch_wait_ms=1))
store.submit(fixture('cap-crash-recovery',status=502,pad=400))
os._exit(0)
"""
        env = dict(os.environ)
        source = str(Path(__file__).resolve().parents[1] / "src")
        env["PYTHONPATH"] = source + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
        subprocess.run([sys.executable, "-c", code, str(self.root)], check=True, env=env)
        open_segment = next((self.root / "segments").glob("*.open.ndjson"))
        valid_size = open_segment.stat().st_size
        with open_segment.open("ab") as handle:
            handle.write(b'{"captureId":"cap-incomplete"')
            handle.flush()
            os.fsync(handle.fileno())
        self.assertGreater(open_segment.stat().st_size, valid_size)

        recovered = self.store()
        self.assertEqual(recovered.health()["captures"], 1)
        self.assertEqual(open_segment.stat().st_size, valid_size)
        recovered.close()
        result = audit_root(self.root)
        self.assertTrue(result["ok"], result)

    def test_complete_invalid_open_record_is_not_silently_truncated(self) -> None:
        code = """
import os,sys
from pathlib import Path
from trace_pipeline.cli import fixture
from trace_pipeline.store import CaptureStore,StoreConfig
store=CaptureStore(StoreConfig(root=Path(sys.argv[1]),batch_wait_ms=1))
store.submit(fixture('cap-before-invalid-line',pad=100))
os._exit(0)
"""
        env = dict(os.environ)
        source = str(Path(__file__).resolve().parents[1] / "src")
        env["PYTHONPATH"] = source + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
        subprocess.run([sys.executable, "-c", code, str(self.root)], check=True, env=env)
        open_segment = next((self.root / "segments").glob("*.open.ndjson"))
        with open_segment.open("ab") as handle:
            handle.write(b'{"captureId":"cap-invalid",NaN}\n')
            handle.flush()
            os.fsync(handle.fileno())
        size = open_segment.stat().st_size
        with self.assertRaises(RecoveryError):
            self.store()
        self.assertEqual(open_segment.stat().st_size, size)

    def test_pretty_json_raw_is_canonicalized_to_one_line(self) -> None:
        store = self.store()
        value = fixture("cap-pretty", pad=50)
        raw = json.dumps(value, indent=2).encode()
        store.submit_raw(raw, value=value)
        store.close()
        segment = next((self.root / "segments").glob("*.sealed.ndjson"))
        self.assertEqual(segment.read_bytes().count(b"\n"), 1)
        self.assertTrue(audit_root(self.root)["ok"])

    def test_missing_sealed_segment_prevents_restart(self) -> None:
        store = self.store()
        store.submit(fixture("cap-missing-segment", pad=50))
        store.close()
        segment = next((self.root / "segments").glob("*.sealed.ndjson"))
        segment.unlink()
        with self.assertRaises(RecoveryError) as context:
            self.store()
        self.assertIn("missing segments", str(context.exception))

    @unittest.skipUnless(
        _filesystem_type(Path(__file__).resolve()) in {"nfs", "nfs4"},
        "requires an NFS-backed repository",
    )
    def test_wal_state_on_nfs_is_rejected(self) -> None:
        repository = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory(prefix="trace-nfs-guard-", dir=repository) as temporary:
            with self.assertRaises(StoreError) as context:
                CaptureStore(StoreConfig(root=Path(temporary)))
        self.assertIn("SQLite WAL state cannot be placed", str(context.exception))

    @unittest.skipUnless(
        _filesystem_type(Path(__file__).resolve()) in {"nfs", "nfs4"},
        "requires an NFS-backed repository",
    )
    def test_nfs_segments_with_local_state_are_supported(self) -> None:
        repository = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory(prefix="trace-nfs-data-", dir=repository) as data_directory:
            with tempfile.TemporaryDirectory(prefix="trace-local-state-") as state_directory:
                store = CaptureStore(
                    StoreConfig(root=Path(data_directory), state_root=Path(state_directory), batch_wait_ms=1)
                )
                result = store.submit(fixture("cap-split-storage", pad=100))
                self.assertEqual(result.state, "accepted")
                self.assertEqual(store.db_path.parent, Path(state_directory).resolve())
                store.close()
                self.assertTrue(audit_root(Path(data_directory), ledger_path=store.db_path)["ok"])

    def test_recovery_indexes_sealed_bytes_committed_before_ledger_rows(self) -> None:
        store = self.store(segment_max_bytes=900, batch_records=8, batch_wait_ms=1)
        store.submit(fixture("cap-ledger-present", pad=100))
        store.submit(fixture("cap-ledger-gap", pad=100))
        store.close()
        with sqlite3.connect(self.root / "state" / "capture-ledger.sqlite") as conn:
            conn.execute("DELETE FROM captures WHERE capture_id='cap-ledger-gap'")
            conn.commit()

        recovered = self.store(segment_max_bytes=900)
        self.assertEqual(recovered.health()["captures"], 2)
        self.assertGreaterEqual(recovered.health()["stats"]["recovered"], 1)
        recovered.close()
        self.assertTrue(audit_root(self.root)["ok"])


if __name__ == "__main__":
    unittest.main()
