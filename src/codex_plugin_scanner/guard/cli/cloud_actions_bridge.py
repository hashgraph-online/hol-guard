"""`hol-guard cloud-actions bridge <ai-tool>`: the local MCP server an AI tool launches for Cloud actions.

The AI tool starts this command from its settings entry and speaks MCP over
stdin and stdout, one JSON-RPC message per line. Each message is forwarded to
the Cloud actions server on Guard Cloud (MCP Streamable HTTP), and every
answer, plain JSON or an event stream, is written back as lines.

Access comes from this computer's `hol-guard connect` pairing: the bridge
exchanges it for that AI tool's short-lived Cloud actions access when it first
needs it, again shortly before that access expires, and once more if Guard
Cloud stops accepting it. The access lives in this process's memory only; it
is never written to the settings file, to disk or to the AI tool.
"""

from __future__ import annotations

import json
import sys
import threading
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable, Iterator, Mapping
from pathlib import Path
from typing import BinaryIO, TextIO

from .cloud_actions_access import (
    CloudActionsAccess,
    CloudActionsAccessError,
    exchange_cloud_actions_access,
    open_paired_store,
    read_cloud_actions_pairing,
)

_REFRESH_BEFORE_SECONDS = 30.0
_REQUEST_TIMEOUT_SECONDS = 300
_MAX_LINE_BYTES = 8 * 1024 * 1024
_JSONRPC_SERVER_ERROR = -32000
_JSONRPC_PARSE_ERROR = -32700

Exchange = Callable[[], CloudActionsAccess]
Opener = Callable[[urllib.request.Request, float], BinaryIO]


class _Access:
    """The current access, obtained again shortly before it expires or when Guard Cloud refuses it."""

    def __init__(self, exchange: Exchange) -> None:
        self._exchange = exchange
        self._lock = threading.Lock()
        self._current: CloudActionsAccess | None = None

    def token(self, *, refused: str | None = None) -> str:
        with self._lock:
            current = self._current
            stale = current is None or current.expires_within(_REFRESH_BEFORE_SECONDS)
            # Only the first caller that saw a token refused replaces it.
            if stale or (refused is not None and current is not None and current.access_token == refused):
                current = self._exchange()
                self._current = current
            assert current is not None
            return current.access_token


class CloudActionsBridge:
    def __init__(self, *, url: str, exchange: Exchange, output: TextIO, opener: Opener) -> None:
        self._url = url
        self._access = _Access(exchange)
        self._output = output
        self._opener = opener
        self._write_lock = threading.Lock()
        self._session_lock = threading.Lock()
        self._session_id: str | None = None
        self._protocol_version: str | None = None

    def serve(self, lines: Iterable[str]) -> None:
        workers: list[threading.Thread] = []
        try:
            for line in lines:
                if not line.strip():
                    continue
                try:
                    message = json.loads(line)
                except ValueError:
                    self._write({"jsonrpc": "2.0", "id": None, "error": _error(_JSONRPC_PARSE_ERROR, "Parse error")})
                    continue
                if _is_initialize(message):
                    # Later messages need the session this one opens.
                    self.handle(message)
                    continue
                worker = threading.Thread(target=self.handle, args=(message,), daemon=True)
                worker.start()
                workers.append(worker)
                workers = [item for item in workers if item.is_alive()]
        finally:
            for worker in workers:
                worker.join()
            self._close_session()

    def handle(self, message: object) -> None:
        request_id = _request_id(message)
        try:
            for answer in self._post(message):
                self._write(answer)
        except CloudActionsAccessError as error:
            self._fail(request_id, str(error))
        except urllib.error.HTTPError as error:
            self._fail(request_id, f"Guard Cloud answered HTTP {error.code}.")
        except (OSError, ValueError):
            self._fail(request_id, "Guard Cloud could not be reached.")

    def _post(self, message: object) -> Iterator[object]:
        body = json.dumps(message, separators=(",", ":")).encode("utf-8")
        token = self._access.token()
        try:
            response = self._send("POST", body, token)
        except urllib.error.HTTPError as error:
            if error.code != 401:
                raise
            response = self._send("POST", body, self._access.token(refused=token))
        with response:
            headers = getattr(response, "headers", None)
            session_id = headers.get("Mcp-Session-Id") if headers is not None else None
            if session_id:
                with self._session_lock:
                    self._session_id = session_id
            content_type = (headers.get("Content-Type") if headers is not None else None) or ""
            if content_type.startswith("text/event-stream"):
                for answer in _read_events(response):
                    self._note_protocol(message, answer)
                    yield answer
                return
            raw = response.read(_MAX_LINE_BYTES + 1)
            if not raw.strip():
                return
            if len(raw) > _MAX_LINE_BYTES:
                raise ValueError("answer too large")
            answer = json.loads(raw)
            self._note_protocol(message, answer)
            yield answer

    def _send(self, method: str, body: bytes | None, token: str) -> BinaryIO:
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json, text/event-stream",
        }
        if body is not None:
            headers["Content-Type"] = "application/json"
        with self._session_lock:
            if self._session_id:
                headers["Mcp-Session-Id"] = self._session_id
            if self._protocol_version:
                headers["MCP-Protocol-Version"] = self._protocol_version
        request = urllib.request.Request(self._url, data=body, method=method, headers=headers)
        return self._opener(request, _REQUEST_TIMEOUT_SECONDS)

    def _note_protocol(self, message: object, answer: object) -> None:
        if not _is_initialize(message) or not isinstance(answer, Mapping):
            return
        result = answer.get("result")
        version = result.get("protocolVersion") if isinstance(result, Mapping) else None
        if isinstance(version, str) and version:
            with self._session_lock:
                self._protocol_version = version

    def _close_session(self) -> None:
        with self._session_lock:
            session_id = self._session_id
        if not session_id:
            return
        try:
            with self._send("DELETE", None, self._access.token()):
                pass
        except (CloudActionsAccessError, OSError, ValueError):
            # The session ends on its own when it times out.
            pass

    def _fail(self, request_id: object, message: str) -> None:
        if request_id is None:
            print(f"hol-guard cloud-actions bridge: {message}", file=sys.stderr)
            return
        self._write({"jsonrpc": "2.0", "id": request_id, "error": _error(_JSONRPC_SERVER_ERROR, message)})

    def _write(self, message: object) -> None:
        line = json.dumps(message, separators=(",", ":"))
        with self._write_lock:
            self._output.write(line + "\n")
            self._output.flush()


def _error(code: int, message: str) -> dict[str, object]:
    return {"code": code, "message": message}


def _is_initialize(message: object) -> bool:
    return isinstance(message, Mapping) and message.get("method") == "initialize" and "id" in message


def _request_id(message: object) -> object:
    if isinstance(message, Mapping) and "method" in message:
        return message.get("id")
    return None


def _read_events(response: BinaryIO) -> Iterator[object]:
    """JSON-RPC messages from a server-sent event stream; each event's data lines form one message."""

    data: list[str] = []
    while True:
        raw = response.readline(_MAX_LINE_BYTES + 1)
        if len(raw) > _MAX_LINE_BYTES:
            raise ValueError("event too large")
        line = raw.decode("utf-8").rstrip("\r\n")
        if line.startswith("data:"):
            data.append(line[5:].removeprefix(" "))
        elif not line:
            if data:
                yield json.loads("\n".join(data))
                data = []
            if not raw:
                return


def _managed_opener(request: urllib.request.Request, timeout: float) -> BinaryIO:
    from ..mdm.network import managed_urlopen

    return managed_urlopen(request, timeout=timeout)  # pyright: ignore[reportReturnType]


def run_cloud_actions_bridge(
    guard_home: Path,
    *,
    ai_tool: str,
    input_stream: TextIO,
    output_stream: TextIO,
    opener: Opener | None = None,
) -> int:
    try:
        store = open_paired_store(guard_home)
        pairing = read_cloud_actions_pairing(store)
    except CloudActionsAccessError as error:
        print(f"hol-guard cloud-actions bridge: {error}", file=sys.stderr)
        return 4
    bridge = CloudActionsBridge(
        url=pairing.gateway_url,
        exchange=lambda: exchange_cloud_actions_access(store, ai_tool=ai_tool),
        output=output_stream,
        opener=opener or _managed_opener,
    )
    bridge.serve(input_stream)
    return 0


__all__ = ["CloudActionsBridge", "run_cloud_actions_bridge"]
