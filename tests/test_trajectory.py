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
        source_namespace: str = "fixture-source",
        session_id: str | None = "session-one",
        thread_id: str | None = "thread-one",
        response_id: str | None = None,
        previous_response_id: str | None = None,
        tools: list[dict] | None = None,
        metadata_extra: dict | None = None,
        observed_lifecycle_events: list[str] | None = None,
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
                    "id": response_id,
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
        metadata = {"turn_id": turn_id}
        if session_id is not None:
            metadata["session_id"] = session_id
        if thread_id is not None:
            metadata["thread_id"] = thread_id
        metadata.update(metadata_extra or {})
        request_value = {
            "model": model,
            "client_metadata": metadata,
            "input": request_items,
        }
        if previous_response_id is not None:
            request_value["previous_response_id"] = previous_response_id
        if tools is not None:
            request_value["tools"] = tools
        return {
            "version": "full-trace-spool-v3",
            "captureId": capture_id,
            "sourceNamespace": source_namespace,
            "receivedAt": timestamp,
            "startedAt": timestamp,
            "finishedAt": timestamp,
            "method": "POST",
            "inboundPath": "/v1/responses",
            "proxiedPath": "/v1/responses",
            "apiKeyFingerprint": "fixture-key",
            "requestBody": {
                "kind": "json",
                "value": request_value,
            },
            "requestTruncated": False,
            "responseStatus": 200,
            "responseBody": {"kind": "text", "value": f"data: {event}\n\ndata: {terminal}\n\n"},
            "responseTruncated": False,
            "stream": True,
            "captureError": None,
            "observedLifecycleEvents": observed_lifecycle_events or [],
        }

    def prepare_raw_export(self) -> None:
        call = {"type": "function_call", "call_id": "call-1", "name": "lookup", "arguments": "{}"}
        tools = [{
            "type": "function",
            "name": "lookup",
            "description": "Look up a value.",
            "parameters": {"type": "object", "properties": {}},
            "schema_version": "1",
        }]
        records = [
            self.record(
                "cap-traj-1",
                model="target-model-v1",
                turn_id="turn-one",
                request_items=[{"type": "message", "role": "user", "content": "question"}],
                output_item=call,
                usage=(100, 80, 10, 3),
                timestamp="2026-08-24T00:00:00Z",
                response_id="response-one",
                tools=tools,
                observed_lifecycle_events=["response.completed"],
            ),
            self.record(
                "cap-traj-2",
                model="target-model-v1",
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
                response_id="response-two",
                previous_response_id="response-one",
                tools=tools,
            ),
            self.record(
                "cap-traj-3",
                model="helper-model-v1",
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
                response_id="response-three",
                previous_response_id="response-two",
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
            model_exact="target-model-v1",
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
            self.assertEqual(conn.execute("SELECT definition_present FROM tool_calls").fetchone()[0], 1)
            self.assertEqual(conn.execute("SELECT linkage_status FROM tool_calls").fetchone()[0], "executed")
            self.assertEqual(conn.execute("SELECT matched_call FROM tool_results").fetchone()[0], 1)
            self.assertEqual(conn.execute("SELECT count(*) FROM trajectory_edges").fetchone()[0], 1)
            self.assertEqual(conn.execute("SELECT event_type FROM lifecycle_events").fetchone()[0], "response.completed")
            self.assertEqual(conn.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            self.assertEqual(conn.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_complete_thread_includes_other_models(self) -> None:
        self.prepare_raw_export()
        result = build_trajectory_catalog(
            [self.raw],
            self.catalog,
            model_exact="target-model-v1",
            projection_mode="complete-thread",
        )
        self.assertEqual(result["records"], 3)
        self.assertEqual(result["trajectories"], 1)
        self.assertEqual(result["turns"], 2)
        with sqlite3.connect(self.catalog) as conn:
            models = dict(conn.execute("SELECT model,count(*) FROM steps GROUP BY model"))
            total_tokens = conn.execute("SELECT total_tokens FROM trajectories").fetchone()[0]
        self.assertEqual(models, {"helper-model-v1": 1, "target-model-v1": 2})
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
                model_exact="target-model-v1",
                projection_mode="exact-model-projection",
            )
        self.assertIn("chunk coverage failed", str(context.exception))

    def test_catalog_cannot_replace_raw_input(self) -> None:
        self.prepare_raw_export()
        with self.assertRaises(ValueError):
            build_trajectory_catalog(
                [self.raw],
                self.raw,
                model_exact="target-model-v1",
                replace=True,
            )

    def test_same_session_id_in_distinct_namespaces_is_not_merged(self) -> None:
        output_item = {
            "type": "message",
            "role": "assistant",
            "phase": "final_answer",
            "content": [{"type": "output_text", "text": "done"}],
        }
        records = [
            self.record(
                "cap-namespace-a",
                model="target-model-v1",
                turn_id="turn-one",
                request_items=[{"type": "message", "role": "user", "content": "a"}],
                output_item=output_item,
                usage=(10, 0, 2, 0),
                timestamp="2026-08-24T00:00:00Z",
                source_namespace="source-a",
                response_id="response-a",
            ),
            self.record(
                "cap-namespace-b",
                model="target-model-v1",
                turn_id="turn-one",
                request_items=[{"type": "message", "role": "user", "content": "b"}],
                output_item=output_item,
                usage=(10, 0, 2, 0),
                timestamp="2026-08-24T00:00:01Z",
                source_namespace="source-b",
                response_id="response-b",
            ),
        ]
        store = CaptureStore(StoreConfig(root=self.root, batch_wait_ms=1))
        for record in records:
            store.submit(record)
        store.close()
        export_sealed(self.root, self.raw, raw_chunk_bytes=128)
        result = build_trajectory_catalog(
            [self.raw], self.catalog, model_exact="target-model-v1", projection_mode="complete-thread"
        )
        self.assertEqual(result["trajectories"], 2)
        with sqlite3.connect(self.catalog) as conn:
            namespaces = {row[0] for row in conn.execute("SELECT source_namespace FROM trajectories")}
        self.assertEqual(namespaces, {"source-a", "source-b"})

    def test_parent_session_relation_and_open_tail_are_explicit(self) -> None:
        call = {"type": "function_call", "call_id": "call-open", "name": "lookup", "arguments": "{}"}
        tool = {
            "type": "function",
            "name": "lookup",
            "description": "Look up a value.",
            "parameters": {"type": "object", "properties": {}},
        }
        record = self.record(
            "cap-open-tail",
            model="target-model-v1",
            turn_id="turn-open",
            request_items=[{"type": "message", "role": "user", "content": "lookup"}],
            output_item=call,
            usage=(10, 0, 2, 0),
            timestamp="2026-08-24T00:00:00Z",
            session_id="child-session",
            response_id="response-open",
            tools=[tool],
            metadata_extra={"root_session_id": "root-session", "parent_session_id": "parent-session"},
        )
        store = CaptureStore(StoreConfig(root=self.root, batch_wait_ms=1))
        store.submit(record)
        store.close()
        export_sealed(self.root, self.raw, raw_chunk_bytes=128)
        result = build_trajectory_catalog(
            [self.raw], self.catalog, model_exact="target-model-v1", projection_mode="complete-thread"
        )
        self.assertEqual(result["validation_status"], "pass")
        with sqlite3.connect(self.catalog) as conn:
            self.assertEqual(conn.execute("SELECT linkage_status FROM tool_calls").fetchone()[0], "open_tail")
            relations = dict(conn.execute("SELECT relation_type,parent_present FROM session_relations"))
        self.assertEqual(relations, {"parent_session": 0, "root_session": 0})

        self.catalog.unlink()
        build_trajectory_catalog(
            [self.raw], self.catalog, model_exact="target-model-v1", projection_mode="exact-model-projection"
        )
        with sqlite3.connect(self.catalog) as conn:
            self.assertEqual(conn.execute("SELECT linkage_status FROM tool_calls").fetchone()[0], "capture_gap")


if __name__ == "__main__":
    unittest.main()
