from __future__ import annotations

import unittest

from chiptrace.model import (
    PERSISTED_RECORD_VERSION,
    ValidationError,
    canonical_envelope,
    normalize_capture_envelope,
    sha256_bytes,
    validate_envelope,
)


class ModelTest(unittest.TestCase):
    def test_capture_id_is_required(self) -> None:
        with self.assertRaises(ValidationError):
            validate_envelope({})
        with self.assertRaises(ValidationError):
            validate_envelope({"captureId": "bad id"})

    def test_canonical_hash_is_order_independent(self) -> None:
        left = {"captureId": "cap-one", "b": 2, "a": 1}
        right = {"a": 1, "captureId": "cap-one", "b": 2}
        self.assertEqual(canonical_envelope(left), canonical_envelope(right))

    def test_relay_envelope_is_normalized_without_status_filtering(self) -> None:
        request = '{"model":"target-model-v1","input":"question"}'
        response = 'data: {"type":"response.failed"}\n\n'
        value = {
            "captureId": "cap-relay-normalize",
            "startedAt": "2026-08-24T00:00:00Z",
            "finishedAt": "2026-08-24T00:00:01Z",
            "requestBodyText": request,
            "responseBodyText": response,
            "responseStatus": 503,
            "captureError": "upstream closed",
            "captureErrorCode": "ECONNRESET",
        }
        record = normalize_capture_envelope(value)

        self.assertEqual(record["version"], PERSISTED_RECORD_VERSION)
        self.assertEqual(record["receivedAt"], value["finishedAt"])
        self.assertEqual(record["requestBody"], {"kind": "json", "value": {"model": "target-model-v1", "input": "question"}})
        self.assertEqual(record["responseBody"], {"kind": "text", "value": response})
        self.assertEqual(record["requestBodySha256"], sha256_bytes(request.encode()))
        self.assertEqual(record["responseStatus"], 503)
        self.assertEqual(record["captureErrorCode"], "ECONNRESET")

    def test_non_string_relay_body_is_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            normalize_capture_envelope({"captureId": "cap-bad-body", "requestBodyText": {"model": "x"}})

    def test_invalid_trace_metadata_types_are_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            normalize_capture_envelope({"captureId": "cap-bad-context", "traceContext": []})
        with self.assertRaises(ValidationError):
            normalize_capture_envelope({"captureId": "cap-bad-events", "observedLifecycleEvents": [""]})
        with self.assertRaises(ValidationError):
            normalize_capture_envelope({"captureId": "cap-long-namespace", "sourceNamespace": "x" * 257})

    def test_missing_relay_timestamps_do_not_break_retry_stability(self) -> None:
        value = {"captureId": "cap-no-time", "requestBodyText": "{}", "responseBodyText": ""}
        self.assertEqual(normalize_capture_envelope(value), normalize_capture_envelope(value))
        self.assertIsNone(normalize_capture_envelope(value)["receivedAt"])

    def test_sensitive_headers_are_removed_and_reported(self) -> None:
        value = {
            "captureId": "cap-sensitive-headers",
            "requestBodyText": "{}",
            "responseBodyText": "{}",
            "requestHeaders": {
                "Authorization": "Bearer secret",
                "X-Auth-Token": "secret",
                "content-type": "application/json",
            },
            "responseHeaders": {"Set-Cookie": "session=secret", "x-request-id": "request-1"},
        }
        normalized = normalize_capture_envelope(value)
        self.assertEqual(normalized["requestHeaders"], {"content-type": "application/json"})
        self.assertEqual(normalized["responseHeaders"], {"x-request-id": "request-1"})
        self.assertEqual(normalized["redactedHeaders"], ["authorization", "set-cookie", "x-auth-token"])

        normalized_again = normalize_capture_envelope(normalized)
        self.assertEqual(normalized_again["redactedHeaders"], ["authorization", "set-cookie", "x-auth-token"])

    def test_trace_context_and_observed_lifecycle_are_preserved(self) -> None:
        value = {
            "captureId": "cap-trace-context",
            "requestBodyText": "{}",
            "responseBodyText": "{}",
            "traceContext": {"session_id": "session-1", "turn_id": "turn-1"},
            "observedLifecycleEvents": ["response.completed"],
        }
        normalized = normalize_capture_envelope(value)
        self.assertEqual(normalized["traceContext"]["session_id"], "session-1")
        self.assertEqual(normalized["observedLifecycleEvents"], ["response.completed"])


if __name__ == "__main__":
    unittest.main()
