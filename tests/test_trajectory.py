from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from trace_pipeline.exporter import export_sealed
from trace_pipeline.store import CaptureStore, StoreConfig
from trace_pipeline.trajectory import build_trajectory_catalog, parse_sse_response


class TrajectoryCatalogTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="trace-trajectory-test-")
        self.base = Path(self.temporary.name)
        self.root = self.base / "capture"
        self.raw = self.base / "raw-part-001.sqlite"
        self.catalog = self.base / "trajectory-catalog.sqlite"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def record(
        self,
        capture_id: str,
        *,
        model: str,
        turn_id: str,
        request_items: list[dict],
        output_item: dict,
        usage: tuple[int, int, int, int],
        timestamp: str,
    ) -> dict:
        input_tokens, cached_tokens, output_tokens, reasoning_tokens = usage
        event = json.dumps(
            {"type": "response.output_item.done", "output_index": 0, "item": output_item},
            separators=(",", ":"),
        )
        terminal = json.dumps(
            {
                "type": "response.completed",
                "response": {
                    "status": "completed",
                    "usage": {
                        "input_tokens": input_tokens,
                        "input_tokens_details": {"cached_tokens": cached_tokens},
                        "output_tokens": output_tokens,
                        "output_tokens_details": {"reasoning_tokens": reasoning_tokens},
                        "total_tokens": input_tokens + output_tokens,
                    },
                },
            },
            separators=(",", ":"),
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
            "apiKeyFingerprint": "fixture-key",
            "requestBody": {
                "kind": "json",
                "value": {
                    "model": model,
                    "client_metadata": {"thread_id": "thread-one", "turn_id": turn_id},
                    "input": request_items,
                },
            },
            "requestTruncated": False,
            "responseStatus": 200,
            "responseBody": {"kind": "text", "value": f"data: {event}\n\ndata: {terminal}\n\n"},
            "responseTruncated": False,
            "stream": True,
            "captureError": None,
        }

    def prepare_raw_export(self) -> None:
        call = {"type": "function_call", "call_id": "call-1", "name": "lookup", "arguments": "{}"}
        records = [
            self.record(
                "cap-traj-1",
                model="gpt-next-sol",
                turn_id="turn-one",
                request_items=[{"type": "message", "role": "user", "content": "question"}],
                output_item=call,
                usage=(100, 80, 10, 3),
                timestamp="2026-08-24T00:00:00Z",
            ),
            self.record(
                "cap-traj-2",
                model="gpt-next-sol",
                turn_id="turn-one",
                request_items=[
                    {"type": "message", "role": "user", "content": "question"},
                    call,
                    {"type": "function_call_output", "call_id": "call-1", "output": "result"},
                ],
                output_item={
                    "type": "message",
                    "role": "assistant",
                    "phase": "final_answer",
                    "content": [{"type": "output_text", "text": "answer"}],
                },
                usage=(120, 80, 12, 4),
                timestamp="2026-08-24T00:00:01Z",
            ),
            self.record(
                "cap-traj-3",
                model="gpt-helper",
                turn_id="turn-two",
                request_items=[{"type": "message", "role": "user", "content": "follow up"}],
                output_item={
                    "type": "message",
                    "role": "assistant",
                    "phase": "final_answer",
                    "content": [{"type": "output_text", "text": "helper answer"}],
                },
                usage=(50, 10, 5, 1),
                timestamp="2026-08-24T00:00:02Z",
            ),
        ]
        store = CaptureStore(StoreConfig(root=self.root, batch_wait_ms=1))
        for record in records:
            store.submit(record)
        store.close()
        export_sealed(self.root, self.raw, raw_chunk_bytes=128)

    def test_exact_projection_builds_linked_scored_catalog(self) -> None:
        self.prepare_raw_export()
        result = build_trajectory_catalog(
            [self.raw],
            self.catalog,
            model_exact="gpt-next-sol",
            projection_mode="exact-model-projection",
        )
        self.assertEqual(result["records"], 2)
        self.assertEqual(result["trajectories"], 1)
        self.assertEqual(result["turns"], 1)
        self.assertEqual(result["validation_status"], "pass")
        self.assertEqual(result["structural_score_average"], 100.0)
        with sqlite3.connect(self.catalog) as conn:
            trajectory = conn.execute(
                "SELECT steps,turns,tool_calls,tool_results,matched_tool_calls,total_tokens,reward,closed "
                "FROM trajectories"
            ).fetchone()
            self.assertEqual(trajectory, (2, 1, 1, 1, 1, 242, None, 1))
            self.assertEqual(conn.execute("SELECT result_present FROM tool_calls").fetchone()[0], 1)
            self.assertEqual(conn.execute("SELECT matched_call FROM tool_results").fetchone()[0], 1)
            self.assertEqual(conn.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            self.assertEqual(conn.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_complete_thread_includes_other_models(self) -> None:
        self.prepare_raw_export()
        result = build_trajectory_catalog(
            [self.raw],
            self.catalog,
            model_exact="gpt-next-sol",
            projection_mode="complete-thread",
        )
        self.assertEqual(result["records"], 3)
        self.assertEqual(result["trajectories"], 1)
        self.assertEqual(result["turns"], 2)
        with sqlite3.connect(self.catalog) as conn:
            models = dict(conn.execute("SELECT model,count(*) FROM steps GROUP BY model"))
            total_tokens = conn.execute("SELECT total_tokens FROM trajectories").fetchone()[0]
        self.assertEqual(models, {"gpt-helper": 1, "gpt-next-sol": 2})
        self.assertEqual(total_tokens, 297)

    def test_sparse_sse_output_index_is_preserved(self) -> None:
        value = "\n".join(
            [
                'data: {"type":"response.custom_tool_call_input.done","output_index":3,"input":"cmd"}',
                'data: {"type":"response.output_item.done","output_index":3,"item":{"type":"custom_tool_call","call_id":"c","name":"exec"}}',
                'data: {"type":"response.completed","response":{"status":"completed","usage":{}}}',
            ]
        )
        parsed = parse_sse_response(value)
        self.assertEqual(parsed["output_indexes"], [3])
        self.assertEqual(parsed["output"][0]["input"], "cmd")

    def test_raw_record_without_chunk_is_rejected(self) -> None:
        self.prepare_raw_export()
        with sqlite3.connect(self.raw) as conn:
            conn.execute("PRAGMA foreign_keys=OFF")
            conn.execute("DELETE FROM interaction_chunks WHERE record_id=1")
            conn.commit()
        with self.assertRaises(RuntimeError) as context:
            build_trajectory_catalog(
                [self.raw],
                self.catalog,
                model_exact="gpt-next-sol",
                projection_mode="exact-model-projection",
            )
        self.assertIn("chunk coverage failed", str(context.exception))

    def test_catalog_cannot_replace_raw_input(self) -> None:
        self.prepare_raw_export()
        with self.assertRaises(ValueError):
            build_trajectory_catalog(
                [self.raw],
                self.raw,
                model_exact="gpt-next-sol",
                replace=True,
            )


if __name__ == "__main__":
    unittest.main()
