from __future__ import annotations

import unittest

from trace_pipeline.model import (
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
        request = '{"model":"gpt-5.6-sol","input":"question"}'
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
        self.assertEqual(record["requestBody"], {"kind": "json", "value": {"model": "gpt-5.6-sol", "input": "question"}})
        self.assertEqual(record["responseBody"], {"kind": "text", "value": response})
        self.assertEqual(record["requestBodySha256"], sha256_bytes(request.encode()))
        self.assertEqual(record["responseStatus"], 503)
        self.assertEqual(record["captureErrorCode"], "ECONNRESET")

    def test_non_string_relay_body_is_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            normalize_capture_envelope({"captureId": "cap-bad-body", "requestBodyText": {"model": "x"}})

    def test_missing_relay_timestamps_do_not_break_retry_stability(self) -> None:
        value = {"captureId": "cap-no-time", "requestBodyText": "{}", "responseBodyText": ""}
        self.assertEqual(normalize_capture_envelope(value), normalize_capture_envelope(value))
        self.assertIsNone(normalize_capture_envelope(value)["receivedAt"])


if __name__ == "__main__":
    unittest.main()
