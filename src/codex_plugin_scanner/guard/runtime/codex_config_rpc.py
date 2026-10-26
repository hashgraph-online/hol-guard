"""Bounded, task-owned access to Codex's supported configuration RPCs.

This session never creates a thread, invokes a tool, or starts an inference turn.
Configuration writes always carry the host's version; there is no CLI-write fallback.
"""

from __future__ import annotations

import json
import logging
import queue
import subprocess
import threading
import time
from collections.abc import Mapping
from contextlib import suppress
from types import TracebackType
from typing import BinaryIO, cast

from ..strict_json_pairs import unique_json_object
from .bounded_json_depth import check_json_depth

_MAX_MESSAGE_BYTES = 1_048_576
_MAX_JSON_DEPTH = 64
# Bound unsolicited notifications while waiting for one config RPC response.
_MAX_RECEIVED_MESSAGES = 64
_METHODS = frozenset({"config/read", "config/batchWrite"})
_LOGGER = logging.getLogger(__name__)


def _reject_json_constant(_value: str) -> None:
    raise ValueError("codex_config_rpc_invalid")


def _check_json_depth(message: bytes) -> None:
    check_json_depth(message, maximum=_MAX_JSON_DEPTH, error_code="codex_config_rpc_invalid")


class CodexConfigRpc:
    def __init__(self, executable: str, *, timeout: float = 8.0) -> None:
        self._executable: str = executable
        self._timeout: float = timeout
        self._process: subprocess.Popen[bytes] | None = None
        self._reader: threading.Thread | None = None
        self._writer: threading.Thread | None = None
        self._messages: queue.Queue[object] = queue.Queue(maxsize=8)
        self._closed: threading.Event = threading.Event()
        self._sequence: int = 0

    def __enter__(self) -> CodexConfigRpc:
        try:
            self._process = subprocess.Popen(
                [self._executable, "app-server", "--listen", "stdio://"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                # Host diagnostics can contain private configuration. Surface typed
                # protocol/process failures, never unfiltered child output.
                stderr=subprocess.DEVNULL,
            )
            self._reader = threading.Thread(target=self._read_messages, daemon=True)
            self._reader.start()
            _ = self._request(
                "initialize",
                {"clientInfo": {"name": "hol_guard_setup", "title": "HOL Guard setup", "version": "1"}},
            )
            self._send({"method": "initialized"})
        except (OSError, ValueError) as error:
            self.close()
            raise ValueError("codex_config_rpc_unavailable") from error
        return self

    def __exit__(
        self,
        _kind: type[BaseException] | None,
        _error: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        self.close()

    def _read_messages(self) -> None:
        process = self._process
        assert process is not None and process.stdout is not None
        stream = cast(BinaryIO, process.stdout)
        try:
            while not self._closed.is_set():
                line = stream.readline(_MAX_MESSAGE_BYTES + 1)
                if not line:
                    message: object = ValueError("codex_config_rpc_unavailable")
                elif len(line) > _MAX_MESSAGE_BYTES:
                    message = ValueError("codex_config_rpc_limit")
                else:
                    _check_json_depth(line)
                    message = cast(
                        object,
                        json.loads(line, object_pairs_hook=unique_json_object, parse_constant=_reject_json_constant),
                    )
                while not self._closed.is_set():
                    try:
                        self._messages.put(message, timeout=0.1)
                        break
                    except queue.Full:
                        continue
                if not line or isinstance(message, ValueError):
                    return
        except (OSError, ValueError, RecursionError):
            if not self._closed.is_set():
                with suppress(queue.Full):
                    self._messages.put_nowait(ValueError("codex_config_rpc_invalid"))

    def _send(self, message: Mapping[str, object]) -> None:
        process = self._process
        if process is None or process.stdin is None or process.poll() is not None:
            raise ValueError("codex_config_rpc_unavailable")
        encoded = json.dumps(message, separators=(",", ":"), allow_nan=False).encode() + b"\n"
        if len(encoded) > _MAX_MESSAGE_BYTES:
            raise ValueError("codex_config_rpc_limit")
        outcome: queue.Queue[object] = queue.Queue(maxsize=1)
        stream = cast(BinaryIO, process.stdin)

        def write() -> None:
            assert process.stdin is not None
            try:
                _ = stream.write(encoded)
                stream.flush()
                outcome.put_nowait(None)
            except (OSError, ValueError) as error:
                outcome.put_nowait(error)

        self._writer = threading.Thread(target=write, daemon=True)
        self._writer.start()
        self._writer.join(timeout=self._timeout)
        if self._writer.is_alive():
            raise ValueError("codex_config_rpc_timeout")
        failure = outcome.get_nowait()
        if isinstance(failure, BaseException):
            raise ValueError("codex_config_rpc_unavailable") from failure

    def _request(self, method: str, params: Mapping[str, object]) -> dict[str, object]:
        self._sequence += 1
        request_id = self._sequence
        self._send({"id": request_id, "method": method, "params": dict(params)})
        deadline = time.monotonic() + self._timeout
        for _ in range(_MAX_RECEIVED_MESSAGES):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError("codex_config_rpc_timeout")
            try:
                message = self._messages.get(timeout=remaining)
            except queue.Empty as error:
                raise ValueError("codex_config_rpc_timeout") from error
            if isinstance(message, ValueError):
                raise message
            if not isinstance(message, dict):
                raise ValueError("codex_config_rpc_invalid")
            message = cast(dict[str, object], message)
            if "id" not in message:
                continue
            if type(message["id"]) is not int or message["id"] != request_id:
                raise ValueError("codex_config_rpc_invalid")
            if "error" in message:
                error = message["error"]
                data = cast(dict[str, object], error).get("data") if isinstance(error, dict) else None
                details = cast(dict[str, object], data) if isinstance(data, dict) else {}
                code = details.get("configWriteErrorCode", details.get("code")) if isinstance(data, dict) else data
                if code == "configVersionConflict":
                    raise ValueError("codex_config_changed")
                if isinstance(code, str) and code in {"configLayerReadonly", "configRequirementReadonly"}:
                    raise ValueError("codex_config_readonly")
                raise ValueError("codex_config_rpc_rejected")
            result = message.get("result")
            if not isinstance(result, dict):
                raise ValueError("codex_config_rpc_invalid")
            return cast(dict[str, object], result)
        raise ValueError("codex_config_rpc_limit")

    def request(self, method: str, params: Mapping[str, object]) -> dict[str, object]:
        if method not in _METHODS:
            raise ValueError("unsupported_codex_config_operation")
        if method == "config/batchWrite":
            version = params.get("expectedVersion")
            if not isinstance(version, str) or not 1 <= len(version) <= 256:
                raise ValueError("codex_config_version_required")
        return self._request(method, params)

    def close(self) -> None:
        self._closed.set()
        process = self._process
        if process is not None:
            if self._writer is not None and self._writer.is_alive() and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
                self._writer.join(timeout=1)
            if process.stdin is not None:
                with suppress(OSError, ValueError):
                    process.stdin.close()
            try:
                process.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
            if self._reader is not None:
                self._reader.join(timeout=1)
            if process.stdout is not None:
                with suppress(OSError, ValueError):
                    process.stdout.close()
            # Only report the exit status: child diagnostics may contain secrets.
            _LOGGER.debug("Codex app-server exited with code %s", process.returncode)
