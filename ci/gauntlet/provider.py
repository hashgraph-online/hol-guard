"""A transparent live-inference relay with a synthetic-canary export backstop.

The relay never supplies model completions or tool decisions. A canary reaching
this boundary is a failed Guard test, even though the relay stops its export.
"""

from __future__ import annotations

import base64
import hashlib
import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from contextlib import suppress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

REQUEST_LIMIT = 1_000_000
RESPONSE_LIMIT = 4_000_000


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never forward a provider credential to a redirected endpoint."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        """Refuse redirects so provider credentials stay at the configured endpoint."""
        return None


def validate_endpoint(url: str, allow_loopback: bool = False) -> str:
    """Require explicit HTTPS, or an explicitly selected local inference server."""
    parsed = urllib.parse.urlsplit(url)
    local = parsed.hostname in {"127.0.0.1", "localhost", "::1"}
    if parsed.username or parsed.password or parsed.query or parsed.fragment or not parsed.hostname:
        raise ValueError("provider URL must not contain credentials, query or fragment")
    if parsed.scheme != "https" and not (allow_loopback and local and parsed.scheme == "http"):
        raise ValueError("provider requires HTTPS; local HTTP requires --allow-loopback-provider")
    return url.rstrip("/") + "/chat/completions"


def canary_present(body: bytes, canary: str) -> bool:
    """Detect the raw canary and common encodings without logging its value."""
    raw = canary.encode()
    candidates = [raw, base64.b64encode(raw), raw.hex().encode(), urllib.parse.quote(canary, safe="").encode()]
    return any(value in body for value in candidates)


class InferenceRelay:
    """Keep real provider authentication out of the agent's environment."""

    def __init__(
        self,
        *,
        base_url: str,
        model: str,
        api_key: str | None,
        canary: str,
        identity: str,
        allow_loopback: bool = False,
        max_rounds: int = 32,
        timeout: float = 120,
    ):
        """Validate the provider and bind an unstarted loopback relay with bounded inference budgets."""
        self.endpoint = validate_endpoint(base_url, allow_loopback)
        self.model = model
        self.identity = identity
        self._api_key = api_key
        self._session_id = str(uuid.uuid4())
        self._canary = canary
        self.max_rounds = max_rounds
        self.timeout = timeout
        self.rounds: list[dict[str, Any]] = []
        self.export_violations = 0
        self._lock = threading.Lock()
        self._opener = urllib.request.build_opener(NoRedirect)
        relay = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                """Suppress default HTTP logging to avoid retaining request details."""
                return

            def do_POST(self):
                """Check canaries, relay bounded inference requests and record streamed response evidence."""
                self.connection.settimeout(relay.timeout)
                if self.path != "/v1/chat/completions":
                    self.send_error(404)
                    return
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    if length <= 0 or length > REQUEST_LIMIT:
                        raise ValueError("request size")
                    body = self.rfile.read(length)
                    with relay._lock:
                        if len(relay.rounds) >= relay.max_rounds:
                            self.send_error(429, "Gauntlet inference budget exhausted")
                            return
                        row: dict[str, Any] = {
                            "request_sha256": hashlib.sha256(body).hexdigest(),
                            "status": "started",
                            "delivered_bytes": 0,
                            "elapsed_seconds": 0.0,
                        }
                        relay.rounds.append(row)
                    if canary_present(body, relay._canary):
                        with relay._lock:
                            relay.export_violations += 1
                            row["status"] = "canary-export-blocked"
                        self.send_error(422, "Synthetic canary reached inference boundary; test failed")
                        return
                    payload = json.loads(body)
                    if not isinstance(payload, dict) or not isinstance(payload.get("messages"), list):
                        raise ValueError("invalid inference conversation")
                    # The configured provider/model is fixed by the test operator.
                    payload["model"] = relay.model
                    payload["stream"] = True
                    forwarded = json.dumps(payload, ensure_ascii=False).encode()
                    request = urllib.request.Request(
                        relay.endpoint, data=forwarded, headers=relay._request_headers(), method="POST"
                    )
                    started = time.monotonic()
                    digest = hashlib.sha256()
                    size = 0
                    models: set[str] = set()
                    completed = False
                    with relay._opener.open(request, timeout=relay.timeout) as response:
                        if response.status != 200:
                            raise ValueError("provider response status")
                        self.send_response(200)
                        self.send_header("Content-Type", "text/event-stream")
                        self.end_headers()
                        for line in response:
                            size += len(line)
                            if size > RESPONSE_LIMIT:
                                raise ValueError("provider response size")
                            digest.update(line)
                            if line.startswith(b"data: "):
                                data = line[6:].strip()
                                if data == b"[DONE]":
                                    completed = True
                                else:
                                    try:
                                        chunk = json.loads(data)
                                        if isinstance(chunk.get("model"), str):
                                            models.add(chunk["model"])
                                    except (ValueError, AttributeError):
                                        pass
                            self.wfile.write(line)
                            self.wfile.flush()
                            row["delivered_bytes"] += len(line)
                    with relay._lock:
                        row.update(
                            status="completed" if completed else "incomplete-stream",
                            elapsed_seconds=round(time.monotonic() - started, 4),
                            response_sha256=digest.hexdigest(),
                            response_bytes=size,
                            response_models=sorted(models),
                        )
                except Exception as exc:
                    with relay._lock:
                        if "row" in locals() and row["status"] == "started":
                            row["status"] = "provider-error"
                            row["error_type"] = type(exc).__name__
                            if isinstance(exc, urllib.error.HTTPError):
                                row["http_status"] = exc.code
                    with suppress(OSError):
                        self.send_error(502, "Gauntlet live inference failed")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        """Return the local OpenAI-compatible API base URL for the agent."""
        return f"http://127.0.0.1:{self.server.server_port}/v1"

    def _request_headers(self) -> dict[str, str]:
        """Identify the real client and keep routing stable within one scenario."""
        headers = {
            "Content-Type": "application/json",
            "Accept": "text/event-stream",
            "User-Agent": "hol-guard-gauntlet/1.0",
            "x-opencode-session": self._session_id,
        }
        if self._api_key:
            headers["Authorization"] = "Bearer " + self._api_key
        return headers

    def __enter__(self):
        """Start serving inference requests and return this relay."""
        self.thread.start()
        return self

    def __exit__(self, *_args):
        """Stop the relay, close its socket and clear the stored API key."""
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self._api_key = None

    def evidence(self) -> dict[str, Any]:
        """Return metadata, never credentials or conversation bodies."""
        with self._lock:
            return {
                "identity": self.identity,
                "requested_model": self.model,
                "live_rounds": [dict(row) for row in self.rounds],
                "canary_export_violations": self.export_violations,
            }


class LoopbackCollector:
    """Observe synthetic egress without retaining its contents."""

    def __init__(self):
        """Bind an unstarted loopback server that records egress sizes and digests."""
        self.requests: list[dict[str, Any]] = []
        collector = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                """Suppress default HTTP logging for synthetic egress requests."""
                return

            def do_POST(self):
                """Record the size and digest of a bounded request body and acknowledge receipt."""
                self.connection.settimeout(5)
                length = min(max(int(self.headers.get("Content-Length", "0")), 0), REQUEST_LIMIT)
                body = self.rfile.read(length)
                collector.requests.append({"bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()})
                self.send_response(204)
                self.end_headers()

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        """Return the local collection endpoint used by synthetic egress scenarios."""
        return f"http://127.0.0.1:{self.server.server_port}/collect"

    def __enter__(self):
        """Start collecting synthetic egress and return this collector."""
        self.thread.start()
        return self

    def __exit__(self, *_args):
        """Stop the collector, close its socket and wait for its serving thread."""
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
