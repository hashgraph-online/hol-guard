"""Single-terminal local OAuth callbacks; the canonical client owns enrollment."""

from __future__ import annotations

import http.server
import threading
import urllib.parse
from dataclasses import dataclass
from time import monotonic
from typing import final

from typing_extensions import override


@dataclass(frozen=True)
class GuardOAuthLoopbackCallback:
    code: str | None
    state: str
    error: str | None = None
    error_description: str | None = None


@final
class OAuthCallbackState:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._ready = threading.Event()
        self._callback: GuardOAuthLoopbackCallback | None = None
        self._closed = False
        self._expired = False
        self._deadline: float | None = None

    def complete(self, callback: GuardOAuthLoopbackCallback) -> int:
        with self._lock:
            if self._callback is not None:
                return 409
            if self._closed or self._expired:
                return 410
            if self._deadline is not None and monotonic() >= self._deadline:
                self._expired = True
                self._ready.set()
                return 410
            self._callback = callback
            self._ready.set()
            return 200

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._ready.set()

    def wait(self, timeout_seconds: float) -> GuardOAuthLoopbackCallback:
        with self._lock:
            remaining = 0.0
            if self._callback is None and not self._closed and not self._expired:
                if self._deadline is None:
                    self._deadline = monotonic() + max(0.0, timeout_seconds)
                remaining = max(0.0, self._deadline - monotonic())
        if remaining > 0:
            _ = self._ready.wait(remaining)
        with self._lock:
            callback = self._callback
            if callback is None:
                if self._closed:
                    raise RuntimeError("Guard OAuth browser session is closed.")
                self._expired = True
                self._ready.set()
                raise TimeoutError("Guard OAuth browser callback timed out.")
        if callback.error is not None:
            description = callback.error_description or callback.error
            raise RuntimeError(f"Guard OAuth authorization was denied: {description}")
        return callback


def callback_handler(
    expected_state: str,
    terminal: OAuthCallbackState,
) -> type[http.server.BaseHTTPRequestHandler]:
    class CallbackHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path != "/oauth/callback":
                self.send_error(404)
                return
            params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            state = params.get("state", [""])[0]
            code = params.get("code", [""])[0]
            error = params.get("error", [""])[0]
            description = params.get("error_description", [""])[0]
            if state != expected_state or len(params.get("state", [])) != 1:
                self.respond(400, "Guard OAuth state mismatch.")
                return
            if bool(code) == bool(error) or any(len(params.get(key, [])) > 1 for key in ("code", "error")):
                self.respond(400, "Guard OAuth callback is missing or has an ambiguous authorization code.")
                return
            status = terminal.complete(
                GuardOAuthLoopbackCallback(
                    code=code or None,
                    state=state,
                    error=error or None,
                    error_description=description or None,
                )
            )
            if status != 200:
                self.respond(status, "This HOL Guard authorization session has already ended.")
            elif error:
                self.respond(200, "HOL Guard authorization was denied. Return to HOL Guard or your terminal.")
            else:
                self.respond(200, "Authorization received. Return to HOL Guard or your terminal to finish connecting.")

        def respond(self, status: int, message: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            _ = self.wfile.write(message.encode("utf-8"))

        @override
        def log_message(self, format: str, *args: object) -> None:
            return

    return CallbackHandler
