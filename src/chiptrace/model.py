from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any


CAPTURE_ID_RE = re.compile(r"^cap-[A-Za-z0-9._:-]+$")
CAPTURE_ENVELOPE_SCHEMA_VERSION = "capture-envelope-v3"
PERSISTED_RECORD_VERSION = "full-trace-spool-v3"
# Public name retained for callers that inspect the current envelope format.
SCHEMA_VERSION = CAPTURE_ENVELOPE_SCHEMA_VERSION
# This value is a persisted data-format identifier from an earlier collector
# release; it is intentionally accepted for ledger migration only.
HISTORICAL_RECORD_SCHEMA_VERSION = "router-v2-capture-envelope-v3"
SUPPORTED_RECORD_VERSIONS = {
    CAPTURE_ENVELOPE_SCHEMA_VERSION,
    PERSISTED_RECORD_VERSION,
    HISTORICAL_RECORD_SCHEMA_VERSION,
}
SENSITIVE_HEADER_NAMES = {
    "api-key",
    "authorization",
    "cookie",
    "proxy-authorization",
    "set-cookie",
    "x-auth-token",
    "x-api-key",
}


class ValidationError(ValueError):
    """Raised when an HTTP capture envelope cannot be safely persisted."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def compact_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")


def storage_json(value: Any) -> bytes:
    """Encode one NDJSON record while preserving useful nested key order."""
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def validate_envelope(value: Any, *, max_capture_id_bytes: int = 256) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValidationError("capture envelope must be a JSON object")
    capture_id = value.get("captureId")
    if not isinstance(capture_id, str) or not CAPTURE_ID_RE.fullmatch(capture_id):
        raise ValidationError("captureId must match cap-[A-Za-z0-9._:-]+")
    if len(capture_id.encode("utf-8")) > max_capture_id_bytes:
        raise ValidationError("captureId is too long")
    version = value.get("version")
    if version is not None and version not in SUPPORTED_RECORD_VERSIONS:
        raise ValidationError(f"unsupported capture envelope version: {version!r}")
    for name in ("receivedAt", "startedAt", "finishedAt", "sourceNamespace"):
        if value.get(name) is not None and not isinstance(value.get(name), str):
            raise ValidationError(f"{name} must be a string or null")
    source_namespace = value.get("sourceNamespace")
    if isinstance(source_namespace, str) and len(source_namespace.encode("utf-8")) > 256:
        raise ValidationError("sourceNamespace is too long")
    for name in ("requestHeaders", "responseHeaders"):
        if value.get(name) is not None and not isinstance(value.get(name), dict):
            raise ValidationError(f"{name} must be an object or null")
    for name in ("requestBodyText", "responseBodyText"):
        if value.get(name) is not None and not isinstance(value.get(name), str):
            raise ValidationError(f"{name} must be a string or null")
    if value.get("traceContext") is not None and not isinstance(value.get("traceContext"), dict):
        raise ValidationError("traceContext must be an object or null")
    lifecycle_events = value.get("observedLifecycleEvents")
    if lifecycle_events is not None and (
        not isinstance(lifecycle_events, list)
        or any(not isinstance(event_type, str) or not event_type for event_type in lifecycle_events)
    ):
        raise ValidationError("observedLifecycleEvents must be an array of non-empty strings or null")
    status = value.get("responseStatus")
    if status is not None:
        if isinstance(status, bool):
            raise ValidationError("responseStatus must be an integer or null")
        try:
            parsed_status = int(status)
        except (TypeError, ValueError) as exc:
            raise ValidationError("responseStatus must be an integer or null") from exc
        if parsed_status < 100 or parsed_status > 599:
            raise ValidationError("responseStatus must be between 100 and 599")
    # Keep all response statuses and error bodies. Quality filtering is
    # downstream; serialization is checked once by canonical_envelope.
    return value


def canonical_envelope(value: dict[str, Any]) -> tuple[bytes, str]:
    validate_envelope(value)
    try:
        raw = compact_json(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"capture envelope is not JSON-serializable: {exc}") from exc
    return raw, sha256_bytes(raw)


def encode_envelope(value: dict[str, Any]) -> tuple[bytes, str]:
    validate_envelope(value)
    try:
        raw = storage_json(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"capture envelope is not JSON-serializable: {exc}") from exc
    return raw, sha256_bytes(raw)


def normalize_capture_envelope(
    value: dict[str, Any],
) -> dict[str, Any]:
    """Map the current relay POST body to the persisted spool record contract.

    Already-normalized spool records are returned unchanged. The relay always
    supplies startedAt/finishedAt; using those as the persisted receivedAt
    fallback keeps a retry byte-stable while SQLite imported_at records the
    collector's actual receipt time. If the relay omits all event timestamps,
    receivedAt remains null instead of introducing a retry-varying value.
    """
    validate_envelope(value)
    if "requestBodyText" not in value and "responseBodyText" not in value:
        normalized = dict(value)
        request_headers, request_redacted = sanitize_headers(value.get("requestHeaders"))
        response_headers, response_redacted = sanitize_headers(value.get("responseHeaders"))
        prior_redacted = value.get("redactedHeaders")
        prior_names = prior_redacted if isinstance(prior_redacted, list) else []
        normalized["version"] = value.get("version") or PERSISTED_RECORD_VERSION
        normalized["requestHeaders"] = request_headers
        normalized["responseHeaders"] = response_headers
        normalized["redactedHeaders"] = sorted(
            set(request_redacted + response_redacted + [str(name).lower() for name in prior_names])
        )
        return normalized

    request_text = _body_text(value.get("requestBodyText"), "requestBodyText")
    response_text = _body_text(value.get("responseBodyText"), "responseBodyText")
    request_sha256, request_bytes = _text_fingerprint(request_text)
    response_sha256, response_bytes = _text_fingerprint(response_text)
    received_at = next(
        (
            candidate
            for candidate in (
                _nonempty_text(value.get("receivedAt")),
                _nonempty_text(value.get("finishedAt")),
                _nonempty_text(value.get("startedAt")),
            )
            if candidate is not None
        ),
        None,
    )

    request_headers, request_redacted = sanitize_headers(value.get("requestHeaders"))
    response_headers, response_redacted = sanitize_headers(value.get("responseHeaders"))
    return {
        "version": PERSISTED_RECORD_VERSION,
        "receivedAt": received_at,
        "captureId": value["captureId"],
        "sourceNamespace": _nonempty_text(value.get("sourceNamespace")),
        "startedAt": value.get("startedAt"),
        "finishedAt": value.get("finishedAt"),
        "method": value.get("method"),
        "inboundPath": value.get("inboundPath"),
        "proxiedPath": value.get("proxiedPath"),
        "apiKeyFingerprint": value.get("apiKeyFingerprint"),
        "actor": value.get("actor"),
        "requestHeaders": request_headers,
        "requestBody": _body_from_text(request_text),
        "requestBodySha256": request_sha256,
        "requestTruncated": bool(value.get("requestTruncated")),
        "requestBytesCaptured": _nonnegative_int(value.get("requestBytesCaptured"), request_bytes),
        "responseStatus": value.get("responseStatus"),
        "responseHeaders": response_headers,
        "responseBody": _body_from_text(response_text),
        "responseBodySha256": response_sha256,
        "responseTruncated": bool(value.get("responseTruncated")),
        "responseBytesCaptured": _nonnegative_int(value.get("responseBytesCaptured"), response_bytes),
        "stream": bool(value.get("stream")),
        "captureError": value.get("captureError"),
        "captureErrorCode": value.get("captureErrorCode"),
        "traceContext": value.get("traceContext") if isinstance(value.get("traceContext"), dict) else {},
        "observedLifecycleEvents": (
            value.get("observedLifecycleEvents")
            if isinstance(value.get("observedLifecycleEvents"), list)
            else []
        ),
        "redactedHeaders": sorted(set(request_redacted + response_redacted)),
    }


def sanitize_headers(value: Any) -> tuple[dict[str, Any], list[str]]:
    headers = value if isinstance(value, dict) else {}
    retained: dict[str, Any] = {}
    redacted: list[str] = []
    for name, content in headers.items():
        key = str(name)
        if key.lower() in SENSITIVE_HEADER_NAMES:
            redacted.append(key.lower())
            continue
        retained[key] = content
    return retained, redacted


def envelope_metadata(value: dict[str, Any]) -> dict[str, Any]:
    """Extract low-cardinality fields for the ledger without changing raw data."""
    return {
        "capture_id": value.get("captureId"),
        "received_at": value.get("receivedAt"),
        "started_at": value.get("startedAt"),
        "finished_at": value.get("finishedAt"),
        "model": _request_model(value.get("requestBody")),
        "inbound_path": value.get("inboundPath"),
        "proxied_path": value.get("proxiedPath"),
        "api_key_fingerprint": value.get("apiKeyFingerprint"),
        "response_status": value.get("responseStatus"),
        "request_truncated": bool(value.get("requestTruncated")),
        "response_truncated": bool(value.get("responseTruncated")),
        "capture_error": value.get("captureError"),
        "stream": bool(value.get("stream")),
    }


def _request_model(body: Any) -> str | None:
    if not isinstance(body, dict):
        return None
    if body.get("kind") == "json":
        body = body.get("value")
    return body.get("model") if isinstance(body, dict) and isinstance(body.get("model"), str) else None


def _body_text(value: Any, field: str) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValidationError(f"{field} must be a string or null")
    return value


def _body_from_text(text: str) -> dict[str, Any]:
    def reject_constant(value: str) -> None:
        raise ValueError(f"invalid JSON constant: {value}")

    try:
        parsed = json.loads(text, parse_constant=reject_constant)
    except (json.JSONDecodeError, ValueError):
        return {"kind": "text", "value": text}
    return {"kind": "json", "value": parsed}


def _nonempty_text(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _nonnegative_int(value: Any, fallback: int) -> int:
    try:
        return max(int(value), 0) if value is not None else fallback
    except (TypeError, ValueError):
        return fallback


def _text_fingerprint(value: str) -> tuple[str, int]:
    raw = value.encode("utf-8")
    return sha256_bytes(raw), len(raw)
