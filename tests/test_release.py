from __future__ import annotations

import hashlib
import tarfile
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from trace_pipeline.exporter import export_sealed
from trace_pipeline.release import archive_session_release, build_session_release, verify_session_release
from trace_pipeline.store import CaptureStore, StoreConfig


class CompleteSessionReleaseTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="trace-release-test-")
        self.base = Path(self.temporary.name)
        self.raw_a = self.base / "source-a.sqlite"
        self.raw_b = self.base / "source-b.sqlite"
        self.release = self.base / "release-v1"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def record(
        self,
        capture_id: str,
        *,
        thread_id: str,
        turn_id: str,
        model: str,
        timestamp: str,
        request_items: list[dict],
        output_item: dict | None,
        terminal_type: str = "response.completed",
    ) -> dict:
        response_status = terminal_type.removeprefix("response.")
        events = []
        if output_item is not None:
            events.append(
                {
                    "type": "response.output_item.done",
                    "output_index": 0,
                    "item": output_item,
                }
            )
        events.append(
            {
                "type": terminal_type,
                "response": {
                    "status": response_status,
                    "usage": {
                        "input_tokens": 100,
                        "input_tokens_details": {"cached_tokens": 60},
                        "output_tokens": 10,
                        "output_tokens_details": {"reasoning_tokens": 2},
                        "total_tokens": 110,
                    },
                },
            }
        )
        response = "".join(
            f"data: {json.dumps(event, separators=(',', ':'))}\n\n" for event in events
        )
        return {
            "version": "full-trace-spool-v3",
            "captureId": capture_id,
            "receivedAt": timestamp,
            "startedAt": timestamp,
            "finishedAt": timestamp,
            "method": "POST",
            "inboundPath": "/v1/responses",
            "proxiedPath": "/v1/responses",
            "apiKeyFingerprint": "release-fixture-key",
            "requestBody": {
                "kind": "json",
                "value": {
                    "model": model,
                    "client_metadata": {"thread_id": thread_id, "turn_id": turn_id},
                    "input": request_items,
                },
            },
            "requestTruncated": False,
            "responseStatus": 200 if terminal_type == "response.completed" else 500,
            "responseBody": {"kind": "text", "value": response},
            "responseTruncated": False,
            "stream": True,
            "captureError": None,
        }

    def export_records(self, name: str, records: list[dict], output: Path) -> None:
        root = self.base / name
        store = CaptureStore(StoreConfig(root=root, batch_wait_ms=1))
        for record in records:
            store.submit(record)
        store.close()
        export_sealed(root, output, raw_chunk_bytes=128)

    def prepare_inputs(self) -> None:
        call = {
            "type": "function_call",
            "call_id": "release-call-1",
            "name": "lookup",
            "arguments": "{}",
        }
        first = self.record(
            "cap-release-session-a-1",
            thread_id="session-a",
            turn_id="turn-a",
            model="target-model-v1",
            timestamp="2026-08-25T00:00:00Z",
            request_items=[{"type": "message", "role": "user", "content": "question"}],
            output_item=call,
        )
        unrelated = self.record(
            "cap-release-unrelated",
            thread_id="session-unrelated",
            turn_id="turn-x",
            model="helper-model-v1",
            timestamp="2026-08-25T00:00:01Z",
            request_items=[{"type": "message", "role": "user", "content": "ignore"}],
            output_item={
                "type": "message",
                "role": "assistant",
                "phase": "final_answer",
                "content": [{"type": "output_text", "text": "ignored"}],
            },
        )
        second = self.record(
            "cap-release-session-a-2",
            thread_id="session-a",
            turn_id="turn-a",
            model="helper-model-v1",
            timestamp="2026-08-25T00:00:02Z",
            request_items=[
                {"type": "message", "role": "user", "content": "question"},
                call,
                {
                    "type": "function_call_output",
                    "call_id": "release-call-1",
                    "output": "result",
                },
            ],
            output_item={
                "type": "message",
                "role": "assistant",
                "phase": "final_answer",
                "content": [{"type": "output_text", "text": "answer"}],
            },
        )
        failed = self.record(
            "cap-release-session-b-1",
            thread_id="session-b",
            turn_id="turn-b",
            model="target-model-v1",
            timestamp="2026-08-25T00:00:03Z",
            request_items=[{"type": "message", "role": "user", "content": "fails"}],
            output_item=None,
            terminal_type="response.failed",
        )
        self.export_records("capture-a", [first, unrelated], self.raw_a)
        self.export_records("capture-b", [first, second, failed], self.raw_b)

    def test_release_keeps_complete_sessions_atomic_and_scores_trace_completeness(self) -> None:
        self.prepare_inputs()
        result = build_session_release(
            [self.raw_a, self.raw_b],
            self.release,
            model_exact="target-model-v1",
            target_part_bytes=1,
            release_id="session-release-test-v1",
        )

        self.assertTrue(result["ok"])
        self.assertEqual(result["records"], 3)
        self.assertEqual(result["sessions"], 2)
        self.assertEqual(result["parts"], 2)
        self.assertEqual(result["oversized_sessions"], 2)
        self.assertEqual(result["duplicate_records_omitted"], 1)
        manifest = json.loads((self.release / "manifest.json").read_text())
        self.assertTrue(manifest["session_atomic"])
        self.assertEqual(manifest["session_split_count"], 0)
        self.assertEqual(manifest["models_present"], ["helper-model-v1", "target-model-v1"])
        self.assertEqual(manifest["session_quality"]["average"], 100.0)
        self.assertFalse(manifest["semantic_reward_available"])
        self.assertEqual(manifest["source_records_scanned"], 5)
        self.assertEqual(manifest["duplicate_records_omitted"], 1)

        verification = verify_session_release(self.release)
        self.assertTrue(verification["ok"])
        self.assertEqual(verification["records"], 3)
        self.assertEqual(verification["sessions"], 2)
        self.assertEqual(verification["parts"], 2)
        with self.assertRaises(RuntimeError):
            verify_session_release(self.release, require_pass=True)

        archive = self.base / "release-v1.tar.gz"
        archive_result = archive_session_release(self.release, archive)
        self.assertTrue(archive_result["ok"])
        with tarfile.open(archive, "r:gz") as handle:
            names = sorted(member.name for member in handle.getmembers())
        self.assertIn("release-v1/manifest.json", names)
        self.assertIn("release-v1/SHA256SUMS", names)

        catalog = self.release / "session-catalog.sqlite"
        with sqlite3.connect(catalog) as conn:
            rows = conn.execute(
                "SELECT session_completeness_score,closed FROM session_quality ORDER BY session_id"
            ).fetchall()
            self.assertEqual(rows, [(100.0, 1), (100.0, 1)])
            self.assertEqual(
                conn.execute(
                    "SELECT count(*) FROM (SELECT traj_id FROM steps GROUP BY traj_id "
                    "HAVING count(DISTINCT shard_id)>1)"
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                conn.execute("SELECT count(*) FROM trajectories WHERE reward IS NOT NULL").fetchone()[0],
                0,
            )

        delivered_ids: set[str] = set()
        copied_payload: bytes | None = None
        for part in manifest["parts"]:
            with sqlite3.connect(self.release / part["file"]) as conn:
                ids = {row[0] for row in conn.execute("SELECT capture_id FROM interactions")}
                self.assertTrue(delivered_ids.isdisjoint(ids))
                delivered_ids.update(ids)
                if "cap-release-session-a-1" in ids:
                    copied_payload = conn.execute(
                        "SELECT c.payload FROM interaction_chunks c JOIN interactions i USING(record_id) "
                        "WHERE i.capture_id=? ORDER BY c.chunk_index LIMIT 1",
                        ("cap-release-session-a-1",),
                    ).fetchone()[0]
        self.assertEqual(
            delivered_ids,
            {
                "cap-release-session-a-1",
                "cap-release-session-a-2",
                "cap-release-session-b-1",
            },
        )
        with sqlite3.connect(self.raw_a) as conn:
            source_payload = conn.execute(
                "SELECT c.payload FROM interaction_chunks c JOIN interactions i USING(record_id) "
                "WHERE i.capture_id=? ORDER BY c.chunk_index LIMIT 1",
                ("cap-release-session-a-1",),
            ).fetchone()[0]
        self.assertEqual(copied_payload, source_payload)

        checksum_lines = (self.release / "SHA256SUMS").read_text().splitlines()
        self.assertEqual(len(checksum_lines), 4)
        for line in checksum_lines:
            expected, name = line.split("  ", 1)
            self.assertEqual(hashlib.sha256((self.release / name).read_bytes()).hexdigest(), expected)

    def test_release_directory_is_immutable(self) -> None:
        self.prepare_inputs()
        self.release.mkdir()
        with self.assertRaises(FileExistsError):
            build_session_release(
                [self.raw_a, self.raw_b],
                self.release,
                model_exact="target-model-v1",
            )

    def test_conflicting_capture_across_inputs_aborts_without_release(self) -> None:
        original = self.record(
            "cap-release-conflict",
            thread_id="session-conflict",
            turn_id="turn-conflict",
            model="target-model-v1",
            timestamp="2026-08-25T00:00:00Z",
            request_items=[{"type": "message", "role": "user", "content": "question"}],
            output_item={
                "type": "message",
                "role": "assistant",
                "phase": "final_answer",
                "content": [{"type": "output_text", "text": "first"}],
            },
        )
        changed = json.loads(json.dumps(original))
        changed["responseStatus"] = 500
        self.export_records("capture-conflict-a", [original], self.raw_a)
        self.export_records("capture-conflict-b", [changed], self.raw_b)

        with self.assertRaises(RuntimeError) as context:
            build_session_release(
                [self.raw_a, self.raw_b],
                self.release,
                model_exact="target-model-v1",
            )
        self.assertIn("captureId conflict", str(context.exception))
        self.assertFalse(self.release.exists())

    def test_open_tool_session_is_retained_and_scored_partial(self) -> None:
        open_call = self.record(
            "cap-release-open-tool",
            thread_id="session-open-tool",
            turn_id="turn-open-tool",
            model="target-model-v1",
            timestamp="2026-08-25T00:00:00Z",
            request_items=[{"type": "message", "role": "user", "content": "question"}],
            output_item={
                "type": "function_call",
                "call_id": "open-call",
                "name": "lookup",
                "arguments": "{}",
            },
        )
        self.export_records("capture-open-tool", [open_call], self.raw_a)
        result = build_session_release(
            [self.raw_a],
            self.release,
            model_exact="target-model-v1",
        )

        self.assertEqual(result["records"], 1)
        with sqlite3.connect(self.release / "session-catalog.sqlite") as conn:
            quality = conn.execute(
                "SELECT session_completeness_score,completeness_grade,right_censored,"
                "tool_calls,matched_tool_calls FROM session_quality"
            ).fetchone()
        self.assertEqual(quality, (70.0, "C_partial", 1, 1, 0))
        manifest = json.loads((self.release / "manifest.json").read_text())
        self.assertEqual(manifest["session_quality"]["incomplete_reasons"]["right_censored"], 1)
        self.assertEqual(manifest["session_quality"]["incomplete_reasons"]["unmatched_tool_calls"], 1)

    def test_release_recovers_missing_model_index_from_raw_request(self) -> None:
        record = self.record(
            "cap-release-model-fallback",
            thread_id="session-model-fallback",
            turn_id="turn-model-fallback",
            model="target-model-v1",
            timestamp="2026-08-25T00:00:00Z",
            request_items=[{"type": "message", "role": "user", "content": "question"}],
            output_item={
                "type": "message",
                "role": "assistant",
                "phase": "final_answer",
                "content": [{"type": "output_text", "text": "answer"}],
            },
        )
        self.export_records("capture-model-fallback", [record], self.raw_a)
        with sqlite3.connect(self.raw_a) as conn:
            conn.execute("UPDATE interactions SET model=NULL")
            conn.commit()

        result = build_session_release(
            [self.raw_a],
            self.release,
            model_exact="target-model-v1",
        )
        self.assertEqual(result["records"], 1)
        part = json.loads((self.release / "manifest.json").read_text())["parts"][0]["file"]
        with sqlite3.connect(self.release / part) as conn:
            self.assertEqual(conn.execute("SELECT model FROM interactions").fetchone()[0], "target-model-v1")


if __name__ == "__main__":
    unittest.main()
