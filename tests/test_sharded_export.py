from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from trace_pipeline.cli import fixture
from trace_pipeline.compression import codec_available
from trace_pipeline.release import build_session_release
from trace_pipeline.sharded_export import build_sharded_export
from trace_pipeline.store import CaptureStore, StoreConfig


class ShardedExportTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="trace-sharded-export-test-")
        self.base = Path(self.temporary.name)
        self.root = self.base / "capture"
        self.output = self.base / "raw-shards"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def prepare(self) -> None:
        store = CaptureStore(
            StoreConfig(
                root=self.root,
                segment_max_bytes=1400,
                batch_records=8,
                batch_wait_ms=1,
            )
        )
        for index in range(18):
            store.submit(fixture(f"cap-sharded-{index:03d}", pad=300))
        store.close()

    def test_parallel_parts_conserve_segments_records_and_release_inputs(self) -> None:
        self.prepare()
        codec = "zstd" if codec_available("zstd") else "zlib"
        result = build_sharded_export(
            self.root,
            self.output,
            shard_count=3,
            max_writers=2,
            compression_codec=codec,
            compression_workers_per_writer=2,
            compression_batch_bytes=512,
            raw_chunk_bytes=128,
        )

        self.assertTrue(result["ok"])
        self.assertEqual(result["parts"], 3)
        self.assertEqual(result["records"], 18)
        manifest = json.loads((self.output / "manifest.json").read_text())
        self.assertFalse(manifest["session_atomic"])
        self.assertEqual(manifest["validation_status"], "pass")
        segment_ids: set[int] = set()
        capture_ids: set[str] = set()
        raw_parts = []
        for part in manifest["parts"]:
            path = self.output / part["file"]
            raw_parts.append(path)
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), part["sha256"])
            ids = set(map(int, part["segment_ids"]))
            self.assertTrue(segment_ids.isdisjoint(ids))
            segment_ids.update(ids)
            with sqlite3.connect(path) as conn:
                self.assertEqual(conn.execute("PRAGMA integrity_check").fetchone()[0], "ok")
                part_captures = {row[0] for row in conn.execute("SELECT capture_id FROM interactions")}
            self.assertTrue(capture_ids.isdisjoint(part_captures))
            capture_ids.update(part_captures)
        self.assertEqual(len(capture_ids), 18)

        release = self.base / "release"
        released = build_session_release(
            raw_parts,
            release,
            model_exact="gpt-self-test",
        )
        self.assertEqual(released["records"], 18)
        self.assertIn(released["validation_status"], {"pass", "warn"})

        sums = (self.output / "SHA256SUMS").read_text().splitlines()
        self.assertEqual(len(sums), 4)
        for line in sums:
            expected, name = line.split("  ", 1)
            self.assertEqual(hashlib.sha256((self.output / name).read_bytes()).hexdigest(), expected)

    def test_output_directory_is_immutable(self) -> None:
        self.prepare()
        self.output.mkdir()
        with self.assertRaises(FileExistsError):
            build_sharded_export(self.root, self.output)


if __name__ == "__main__":
    unittest.main()
