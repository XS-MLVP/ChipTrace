from __future__ import annotations

import http.client
import json
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from chiptrace.cli import fixture
from chiptrace.exporter import export_sealed
from chiptrace.server import CaptureHTTPServer
from chiptrace.store import CaptureStore, StoreConfig


class HTTPCaptureTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="chiptrace-http-test-")
        self.root = Path(self.temporary.name) / "capture"
        self.store = CaptureStore(StoreConfig(root=self.root, batch_wait_ms=2))
        self.server = CaptureHTTPServer(("127.0.0.1", 0), self.store, max_connections=16)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.store.close()
        self.temporary.cleanup()

    def request(self, method: str, path: str, body: bytes | None = None, content_type: str = "application/json") -> tuple[int, dict]:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {"content-type": content_type} if body is not None else {}
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        payload = json.loads(response.read())
        conn.close()
        return response.status, payload

    def test_current_capture_contract_and_error_preservation(self) -> None:
        value = fixture("cap-http-error", status=503, pad=100)
        raw = json.dumps(value, separators=(",", ":")).encode()
        status, first = self.request("POST", "/capture", raw)
        duplicate_status, duplicate = self.request("POST", "/capture", raw)
        health_status, health = self.request("GET", "/health")
        audit_status, audit = self.request("GET", "/audit")

        self.assertEqual(status, 202)
        self.assertTrue(first["durable"])
        self.assertFalse(first["duplicate"])
        self.assertEqual(duplicate_status, 202)
        self.assertTrue(duplicate["duplicate"])
        self.assertEqual(health_status, 200)
        self.assertEqual(health["captures"], 1)
        self.assertEqual(audit_status, 200)
        self.assertTrue(audit["ok"])

    def test_flush_seals_queued_records_without_stopping_collector(self) -> None:
        value = fixture("cap-http-flush", status=200, pad=100)
        raw = json.dumps(value, separators=(",", ":")).encode()
        self.assertEqual(self.request("POST", "/capture", raw)[0], 202)

        status, payload = self.request("POST", "/flush")

        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["sealed"])
        self.assertEqual(payload["captures"], 1)
        health = self.store.health()
        self.assertEqual(health["captures"], 1)
        self.assertGreaterEqual(health["segments"].get("sealed", {}).get("count", 0), 1)
        self.assertGreaterEqual(health["segments"].get("open", {}).get("count", 0), 1)
        raw_output = self.root.parent / "flushed-export.sqlite"
        exported = export_sealed(self.root, raw_output, raw_chunk_bytes=128)
        self.assertEqual(exported["records"], 1)

    def test_invalid_attempt_is_counted(self) -> None:
        status, payload = self.request("POST", "/capture", b'{"missing":"capture-id"}')
        self.assertEqual(status, 400)
        self.assertEqual(payload["reason"], "invalid_capture")
        self.assertEqual(self.store.health()["attempts"], 1)
        self.assertEqual(self.store.health()["stats"]["rejected"], 1)

    def test_protocol_rejections_are_counted(self) -> None:
        self.assertEqual(self.request("POST", "/capture", b"{}", content_type="text/plain")[0], 415)
        self.assertEqual(self.request("POST", "/capture", b"")[0], 400)
        health = self.store.health()
        self.assertEqual(health["attempt_states"], {"rejected": 2})

    def test_body_budget_overload_is_explicit_and_counted(self) -> None:
        self.assertTrue(self.server.body_budget.acquire(self.server.body_budget.capacity, 0))
        try:
            value = json.dumps(fixture("cap-budget-overload"), separators=(",", ":")).encode()
            status, payload = self.request("POST", "/capture", value)
        finally:
            self.server.body_budget.release(self.server.body_budget.capacity)
        self.assertEqual(status, 503)
        self.assertEqual(payload["reason"], "body_budget_exhausted")
        self.assertEqual(self.store.health()["attempt_states"], {"rejected": 1})

    def test_capture_id_conflict_is_409(self) -> None:
        first = json.dumps(fixture("cap-http-conflict", status=200), separators=(",", ":")).encode()
        changed = json.dumps(fixture("cap-http-conflict", status=429), separators=(",", ":")).encode()
        self.assertEqual(self.request("POST", "/capture", first)[0], 202)
        status, payload = self.request("POST", "/capture", changed)
        self.assertEqual(status, 409)
        self.assertEqual(payload["reason"], "capture_store")

    def test_current_relay_shape_is_normalized_for_trajectory_readers(self) -> None:
        request_body = {"model": "target-model-v1", "input": [{"role": "user", "content": "question"}]}
        response_text = 'data: {"type":"response.failed","response":{"status":"failed"}}\n\n'
        value = {
            "captureId": "cap-http-relay-shape",
            "startedAt": "2026-08-24T00:00:00Z",
            "finishedAt": "2026-08-24T00:00:02Z",
            "method": "POST",
            "inboundPath": "/v1/responses",
            "proxiedPath": "/v1/responses",
            "apiKeyFingerprint": "fingerprint",
            "requestBodyText": json.dumps(request_body, separators=(",", ":")),
            "requestTruncated": False,
            "responseStatus": 503,
            "responseBodyText": response_text,
            "responseTruncated": False,
            "stream": True,
            "captureError": "upstream failed",
        }
        raw = json.dumps(value, separators=(",", ":")).encode()
        status, first = self.request("POST", "/capture", raw)
        duplicate_status, duplicate = self.request("POST", "/capture", raw)

        self.assertEqual(status, 202)
        self.assertEqual(duplicate_status, 202)
        self.assertFalse(first["duplicate"])
        self.assertTrue(duplicate["duplicate"])
        with sqlite3.connect(self.root / "state" / "capture-ledger.sqlite") as conn:
            row = conn.execute(
                "SELECT c.model,c.response_status,c.offset,c.length,s.path "
                "FROM captures c JOIN segments s USING(segment_id) WHERE c.capture_id=?",
                (value["captureId"],),
            ).fetchone()
        self.assertEqual(row[:2], ("target-model-v1", 503))
        with (self.root / row[4]).open("rb") as handle:
            handle.seek(row[2])
            record = json.loads(handle.read(row[3]))
        self.assertNotIn("requestBodyText", record)
        self.assertEqual(record["requestBody"]["value"]["model"], "target-model-v1")
        self.assertEqual(record["responseBody"], {"kind": "text", "value": response_text})
        self.assertEqual(record["receivedAt"], value["finishedAt"])


if __name__ == "__main__":
    unittest.main()
