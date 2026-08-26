from __future__ import annotations

import json
import hashlib
import threading
import time
from dataclasses import asdict
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

from .model import ValidationError, encode_envelope, normalize_capture_envelope
from .store import CaptureStore, StoreError


class CaptureHTTPServer(ThreadingHTTPServer):
    daemon_threads = False
    allow_reuse_address = True

    def __init__(
        self,
        address: tuple[str, int],
        store: CaptureStore,
        max_connections: int = 256,
        max_inflight_body_bytes: int = 4 * 1024 * 1024 * 1024,
        body_budget_wait_seconds: float = 1.0,
    ):
        self.store = store
        self._connections = threading.BoundedSemaphore(max(1, max_connections))
        self.body_budget = ByteBudget(max_inflight_body_bytes)
        self.body_budget_wait_seconds = max(float(body_budget_wait_seconds), 0.0)
        super().__init__(address, CaptureHandler)

    def process_request(self, request: Any, client_address: Any) -> None:
        self._connections.acquire()
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._connections.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._connections.release()


class CaptureHandler(BaseHTTPRequestHandler):
    server: CaptureHTTPServer
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        path = urlsplit(self.path).path
        if path == "/health":
            health = self.server.store.health()
            health["http"] = {
                "body_budget": self.server.body_budget.snapshot(),
                "body_budget_wait_seconds": self.server.body_budget_wait_seconds,
            }
            self._json(HTTPStatus.OK if health["ok"] else HTTPStatus.SERVICE_UNAVAILABLE, health)
            return
        if path == "/audit":
            result = self.server.store.audit()
            self._json(HTTPStatus.OK if result["ok"] else HTTPStatus.INTERNAL_SERVER_ERROR, result)
            return
        self._json(HTTPStatus.NOT_FOUND, {"ok": False, "reason": "not_found"})

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        path = urlsplit(self.path).path
        if path == "/flush":
            # This is deliberately a local administration primitive. The
            # default listener is loopback; deployments exposing the port
            # should restrict it at the network boundary.
            try:
                result = self.server.store.flush(timeout=30.0, seal=True)
            except TimeoutError as exc:
                self._json(
                    HTTPStatus.GATEWAY_TIMEOUT,
                    {"ok": False, "reason": "flush_timeout", "detail": str(exc)[:300]},
                )
                return
            except StoreError as exc:
                self._json(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    {"ok": False, "reason": "flush_failed", "detail": str(exc)[:300]},
                )
                return
            self._json(HTTPStatus.OK, {"ok": True, "sealed": True, **result})
            return
        if path != "/capture":
            self._json(HTTPStatus.NOT_FOUND, {"ok": False, "reason": "not_found"})
            return
        content_type = self.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            self.close_connection = True
            self.server.store.record_rejection("content_type")
            self._json(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, {"ok": False, "reason": "content_type"})
            return
        try:
            length = int(self.headers.get("content-length", ""))
        except ValueError:
            self.close_connection = True
            self.server.store.record_rejection("content_length")
            self._json(HTTPStatus.LENGTH_REQUIRED, {"ok": False, "reason": "content_length"})
            return
        if length <= 0:
            self.server.store.record_rejection("empty_body")
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "reason": "empty_body"})
            return
        if length > self.server.store.config.max_envelope_bytes:
            self._discard_body(min(length, 64 * 1024))
            self.close_connection = True
            self.server.store.record_rejection("body_too_large")
            self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"ok": False, "reason": "body_too_large"})
            return
        if not self.server.body_budget.acquire(length, self.server.body_budget_wait_seconds):
            self.close_connection = True
            self.server.store.record_rejection("body_budget_exhausted")
            self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"ok": False, "reason": "body_budget_exhausted"})
            return
        try:
            try:
                raw = self.rfile.read(length)
                if len(raw) != length:
                    raise ValueError("incomplete request body")
                value = json.loads(raw)
                normalized = normalize_capture_envelope(value)
                stored_raw, _digest = encode_envelope(normalized)
                result = self.server.store.submit_raw(stored_raw, value=normalized)
            except (json.JSONDecodeError, ValidationError, ValueError) as exc:
                capture_id = value.get("captureId") if isinstance(locals().get("value"), dict) else None
                self.server.store.record_rejection(
                    "invalid_capture",
                    capture_id=str(capture_id) if capture_id is not None else None,
                    raw_sha256=hashlib.sha256(raw).hexdigest() if "raw" in locals() else None,
                )
                self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "reason": "invalid_capture", "detail": str(exc)[:300]})
                return
            except TimeoutError as exc:
                # The client must retry with the same captureId. Idempotence makes
                # an ambiguous timeout safe: it will either commit once or retry.
                self._json(HTTPStatus.GATEWAY_TIMEOUT, {"ok": False, "reason": "durability_timeout", "detail": str(exc)[:300]})
                return
            except StoreError as exc:
                code = HTTPStatus.CONFLICT if "reused" in str(exc) else HTTPStatus.SERVICE_UNAVAILABLE
                self._json(code, {"ok": False, "reason": "capture_store", "detail": str(exc)[:300]})
                return
        finally:
            self.server.body_budget.release(length)
        self._json(
            HTTPStatus.ACCEPTED,
            {
                "ok": True,
                "durable": True,
                "retry_safe": True,
                **asdict(result),
            },
        )

    def log_message(self, fmt: str, *args: Any) -> None:
        # Production supervisors already add timestamps and service identity.
        print(f"capture-http {self.client_address[0]} {fmt % args}", flush=True)

    def _discard_body(self, count: int) -> None:
        if count > 0:
            self.rfile.read(count)

    def _json(self, status: HTTPStatus, value: dict[str, Any]) -> None:
        raw = json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        self.send_response(int(status))
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(raw)))
        self.send_header("cache-control", "no-store")
        self.end_headers()
        self.wfile.write(raw)


def serve(
    store: CaptureStore,
    host: str,
    port: int,
    stop: threading.Event | None = None,
    *,
    max_connections: int = 256,
    max_inflight_body_bytes: int = 4 * 1024 * 1024 * 1024,
    body_budget_wait_seconds: float = 1.0,
) -> None:
    server = CaptureHTTPServer(
        (host, port),
        store,
        max_connections=max_connections,
        max_inflight_body_bytes=max_inflight_body_bytes,
        body_budget_wait_seconds=body_budget_wait_seconds,
    )
    if stop is None:
        server.serve_forever(poll_interval=0.5)
        return
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
    thread.start()
    stop.wait()
    server.shutdown()
    thread.join()
    server.server_close()


class ByteBudget:
    def __init__(self, capacity: int):
        if int(capacity) <= 0:
            raise ValueError("body byte budget must be positive")
        self.capacity = int(capacity)
        self._used = 0
        self._waiters = 0
        self._rejections = 0
        self._condition = threading.Condition()

    def acquire(self, amount: int, timeout: float) -> bool:
        amount = int(amount)
        if amount <= 0:
            raise ValueError("body byte reservation must be positive")
        deadline = time.monotonic() + max(float(timeout), 0.0)
        with self._condition:
            if amount > self.capacity:
                self._rejections += 1
                return False
            self._waiters += 1
            try:
                while self._used + amount > self.capacity:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        self._rejections += 1
                        return False
                    self._condition.wait(remaining)
                self._used += amount
                return True
            finally:
                self._waiters -= 1

    def release(self, amount: int) -> None:
        with self._condition:
            self._used -= int(amount)
            if self._used < 0:
                self._used = 0
                raise RuntimeError("body byte budget released more bytes than reserved")
            self._condition.notify_all()

    def snapshot(self) -> dict[str, int]:
        with self._condition:
            return {
                "capacity_bytes": self.capacity,
                "used_bytes": self._used,
                "available_bytes": self.capacity - self._used,
                "waiters": self._waiters,
                "rejections": self._rejections,
            }
