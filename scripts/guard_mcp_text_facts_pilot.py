"""Explicit qualification adapter for four pure MCP text predicates.

This module is not imported by the product. A benchmark opts in to one
private helper; Python continues normalization, category composition, policy,
approval identity and freshness. No selected-helper failure becomes fallback.
"""

from __future__ import annotations

import contextvars
import hashlib
import os
import select
import struct
import subprocess
import sys
import threading
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from codex_plugin_scanner.guard.proxy.framing import (
    ProxyIoLimitError,
    ProxyIoTimeoutError,
    remaining_timeout,
)

MAX_PACKET_BYTES = 16 * 1024 * 1024
HEADER = struct.Struct(">4sQI")
REPLY = struct.Struct(">4sQB")
MINIMUM_CHARACTERS = 256 * 1024
_CHUNK_CHARACTERS = 64 * 1024
_SOURCE = "native_mcp_text_facts"


def executable_identity(path: Path) -> dict[str, Any]:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        status = os.fstat(stream.fileno())
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return {
        "path": str(path),
        "resolved_path": str(path.resolve()),
        "sha256": digest.hexdigest(),
        "device": status.st_dev,
        "inode": status.st_ino,
        "size": status.st_size,
    }


class TextFactsPilot:
    """One admitted packet, one absolute deadline, one private child process."""

    def __init__(self, executable: Path, *, minimum_characters: int = MINIMUM_CHARACTERS) -> None:
        if minimum_characters < 0:
            raise ValueError("native_mcp_text_invalid_threshold")
        self.executable = executable.absolute()
        self.minimum_characters = minimum_characters
        self.process: subprocess.Popen[bytes] | None = None
        self.lock = threading.Lock()
        self.sequence = 0
        self.closed = False
        self.counters: Counter[str] = Counter()
        self.provenance: dict[str, Any] | None = None
        self.executed_provenance: dict[str, Any] | None = None
        self.max_packet_bytes = 0
        self.max_helper_rss_bytes = 0
        self.pipe_capacity_bytes: dict[str, int] = {}

    @staticmethod
    def _remaining(deadline: float) -> float:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ProxyIoTimeoutError(source=_SOURCE, timeout_seconds=0)
        return remaining

    def _retire(self) -> None:
        self.closed = True
        process = self.process
        if process is None:
            return
        if process.poll() is None:
            process.kill()
        try:
            process.wait(timeout=0.25)
            self.counters["reaped"] += 1
        except subprocess.TimeoutExpired:
            self.counters["reap_deadline_exceeded"] += 1
        for stream in (process.stdin, process.stdout):
            if stream is not None:
                stream.close()
        self.process = None

    def close(self) -> None:
        with self.lock:
            self._retire()

    def _start(self, deadline: float) -> subprocess.Popen[bytes]:
        self._remaining(deadline)
        if self.process is not None:
            return self.process
        self.provenance = executable_identity(self.executable)
        self._remaining(deadline)
        process = subprocess.Popen(
            [str(self.executable)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env={},
            cwd="/",
            close_fds=True,
            bufsize=0,
        )
        self.process = process
        self.counters["starts"] += 1
        assert process.stdin is not None and process.stdout is not None
        os.set_blocking(process.stdin.fileno(), False)
        os.set_blocking(process.stdout.fileno(), False)
        if sys.platform == "linux":
            import fcntl

            self.pipe_capacity_bytes = {
                "request": fcntl.fcntl(process.stdin.fileno(), fcntl.F_GETPIPE_SZ),
                "response": fcntl.fcntl(process.stdout.fileno(), fcntl.F_GETPIPE_SZ),
            }
            self.executed_provenance = executable_identity(Path(f"/proc/{process.pid}/exe"))
            if self.executed_provenance["sha256"] != self.provenance["sha256"]:
                raise ProxyIoLimitError(source=_SOURCE, reason="executable_changed")
        self._remaining(deadline)
        return process

    def _write(self, descriptor: int, data: bytes, deadline: float) -> None:
        view = memoryview(data)
        offset = 0
        while offset < len(view):
            remaining = self._remaining(deadline)
            _, ready, _ = select.select([], [descriptor], [], remaining)
            if not ready:
                raise ProxyIoTimeoutError(source=_SOURCE, timeout_seconds=remaining)
            try:
                count = os.write(descriptor, view[offset : offset + 65536])
            except BlockingIOError:
                continue
            if count <= 0:
                raise ProxyIoLimitError(source=_SOURCE, reason="ambiguous_write")
            offset += count
            self.counters["request_bytes_written"] += count

    def _read_reply(self, descriptor: int, deadline: float) -> bytes:
        response = bytearray()
        while len(response) < REPLY.size:
            remaining = self._remaining(deadline)
            ready, _, _ = select.select([descriptor], [], [], remaining)
            if not ready:
                raise ProxyIoTimeoutError(source=_SOURCE, timeout_seconds=remaining)
            try:
                chunk = os.read(descriptor, REPLY.size - len(response))
            except BlockingIOError:
                continue
            if not chunk:
                raise ProxyIoLimitError(source=_SOURCE, reason="unexpected_eof")
            response.extend(chunk)
            self.counters["response_bytes_read"] += len(chunk)
        return bytes(response)

    def _require_quiet(self, descriptor: int) -> None:
        if select.select([descriptor], [], [], 0)[0]:
            try:
                pending = os.read(descriptor, 1)
            except BlockingIOError:
                return
            self.counters["unexpected_output_probe_bytes"] += len(pending)
            raise ProxyIoLimitError(source=_SOURCE, reason="unexpected_output" if pending else "unexpected_eof")

    def classify(self, text: str) -> int | None:
        if self.closed:
            raise ProxyIoLimitError(source=_SOURCE, reason="stream_retired")
        # These are declared pre-dispatch Python selections, not error recovery.
        if os.name != "posix":
            self.counters["python_unsupported_platform"] += 1
            return None
        if type(text) is not str:
            self.counters["python_unsupported_text_type"] += 1
            return None
        if len(text) < self.minimum_characters:
            self.counters["python_small_text"] += 1
            return None
        if len(text) > MAX_PACKET_BYTES - HEADER.size:
            self.counters["python_packet_bound"] += 1
            return None
        deadline = time.monotonic() + remaining_timeout(30.0, source=_SOURCE)
        if not self.lock.acquire(timeout=self._remaining(deadline)):
            self.counters["admission_timeout"] += 1
            raise ProxyIoTimeoutError(source=_SOURCE, timeout_seconds=0)
        try:
            if self.closed:
                raise ProxyIoLimitError(source=_SOURCE, reason="stream_retired")
            self._remaining(deadline)
            self.counters["admitted"] += 1
            chunks = []
            total = HEADER.size
            try:
                for offset in range(0, len(text), _CHUNK_CHARACTERS):
                    self._remaining(deadline)
                    chunk = text[offset : offset + _CHUNK_CHARACTERS].encode("utf-8", errors="strict")
                    self._remaining(deadline)
                    total += len(chunk)
                    if total > MAX_PACKET_BYTES:
                        self.counters["python_packet_bound"] += 1
                        return None
                    chunks.append(chunk)
            except UnicodeError:
                self._remaining(deadline)
                self.counters["python_unsupported_utf8"] += 1
                return None
            self.counters["native_attempts"] += 1
            self.max_packet_bytes = max(self.max_packet_bytes, total)
            process = self._start(deadline)
            assert process.stdin is not None and process.stdout is not None
            self._require_quiet(process.stdout.fileno())
            self.sequence += 1
            if self.sequence > (1 << 64) - 1:
                raise ProxyIoLimitError(source=_SOURCE, reason="request_identity_exhausted")
            self._write(process.stdin.fileno(), HEADER.pack(b"MFT1", self.sequence, total - HEADER.size), deadline)
            for chunk in chunks:
                self._write(process.stdin.fileno(), chunk, deadline)
            magic, sequence, flags = REPLY.unpack(self._read_reply(process.stdout.fileno(), deadline))
            if magic != b"MFR1" or sequence != self.sequence or flags & ~15:
                raise ProxyIoLimitError(source=_SOURCE, reason="invalid_reply")
            self._require_quiet(process.stdout.fileno())
            self._remaining(deadline)
            # Diagnostic sampling is part of this explicit pilot's measured cost.
            import psutil

            self.max_helper_rss_bytes = max(self.max_helper_rss_bytes, psutil.Process(process.pid).memory_info().rss)
            self._remaining(deadline)
            self.counters["native_completed"] += 1
            return flags
        except (Exception, KeyboardInterrupt) as error:
            self.counters["native_failures"] += 1
            self._retire()
            if isinstance(error, (ProxyIoLimitError, ProxyIoTimeoutError, KeyboardInterrupt)):
                raise
            raise ProxyIoLimitError(source=_SOURCE, reason="helper_io_failure") from None
        finally:
            self.lock.release()

    def evidence(self) -> dict[str, Any]:
        return {
            "qualification": False,
            "scope": "explicit_benchmark_four_text_predicates_only",
            "counters": dict(self.counters),
            "max_packet_bytes": self.max_packet_bytes,
            "packet_limit_bytes_including_header": MAX_PACKET_BYTES,
            "response_limit_bytes": REPLY.size,
            "surplus_rejection_probe_bytes": 1,
            "inflight_packet_limit": 1,
            "encoding_chunk_characters": _CHUNK_CHARACTERS,
            "overflow_chunk_max_utf8_bytes": 4 * _CHUNK_CHARACTERS,
            "observed_pipe_capacity_bytes": self.pipe_capacity_bytes,
            "minimum_characters": self.minimum_characters,
            "deadline": "one_absolute_deadline_capped_by_current_operation_remaining_budget",
            "kill_reap_cleanup_seconds": 0.25,
            "max_sampled_helper_rss_bytes": self.max_helper_rss_bytes,
            "requested_executable": self.provenance,
            "executed_executable": self.executed_provenance,
        }


def pattern_groups() -> dict[tuple[str, ...], int]:
    """Frozen Python pattern spellings, independently checked against source."""
    return {
        (
            r"(?<![a-z0-9_])(subprocess|child_process|childprocess|popen|os\.system|runtime\.exec)(?![a-z0-9_])",
            r"(?<![a-z0-9_])(spawn|execfile|system)(?:_sync)?\s*\(",
        ): 1,
        (
            r"(http://|https://)",
            r"(?<![a-z0-9])(curl|wget|fetch|axios|requests)(?![a-z0-9])",
            r"(?<![a-z0-9_])(socket|net|dns)\s*[.(]",
            r"(?<![a-z0-9_])(create_connection|getaddrinfo|gethostbyname|sendto|recvfrom)\s*\(",
            r"(?<![a-z0-9_])(urllib\.request|urllib|http\.client|http|https)\s*\.",
            r"(?<![a-z0-9_])(udp|tcp|socks|proxy|tunnel|port_forward|port\-forward)(?![a-z0-9_])",
        ): 2,
        (
            r"(?<![a-z0-9_-])(\.env)(?![a-z0-9_-])",
            r"(?<![a-z0-9_-])(\.ssh)(?![a-z0-9_-])",
            r"(?<![a-z0-9])(idrsa|id_rsa|id\-rsa|credentials|token|secret|passwd)(?![a-z0-9])",
            r"(?<![a-z0-9_-])(\.npmrc|\.pypirc)(?![a-z0-9_-])",
        ): 4,
        (r"(?<![a-z0-9])(sudo|chmod|chown|launchctl|systemctl)(?![a-z0-9])",): 8,
    }


@dataclass
class _Analysis:
    text: str | None = None
    selected: bool = False
    flags: int | None = None


def install_adapter(module: Any, pilot: TextFactsPilot) -> Any:
    """Adapt only exact groups on one immutable normalized analysis string."""
    if getattr(module, "_text_facts_pilot_installed", False):
        raise RuntimeError("native_mcp_text_adapter_already_installed")
    groups = pattern_groups()
    active: contextvars.ContextVar[_Analysis | None] = contextvars.ContextVar("mcp_text_pilot_analysis", default=None)
    original_analyze = module._tool_call_risk_category_set
    original_normalize = module._risk_match_text
    original_matches = module._matches_any

    def analyze(*args: Any, **kwargs: Any) -> Any:
        token = active.set(_Analysis())
        try:
            return original_analyze(*args, **kwargs)
        finally:
            active.reset(token)

    def normalize(value: str) -> str:
        result = original_normalize(value)
        state = active.get()
        if state is not None and state.text is None:
            state.text = result
        return result

    def matches(value: str, patterns: Any) -> bool:
        state = active.get()
        if state is not None and value is state.text:
            expressions = tuple(
                pattern.expression if hasattr(pattern, "expression") else pattern for pattern in patterns
            )
            bit = groups.get(expressions)
            if bit is not None:
                if not state.selected:
                    state.flags = pilot.classify(value)
                    state.selected = True
                if state.flags is not None:
                    return bool(state.flags & bit)
        return original_matches(value, patterns)

    module._tool_call_risk_category_set = analyze
    module._risk_match_text = normalize
    module._matches_any = matches
    module._text_facts_pilot_installed = True

    def restore() -> None:
        module._tool_call_risk_category_set = original_analyze
        module._risk_match_text = original_normalize
        module._matches_any = original_matches
        del module._text_facts_pilot_installed
        pilot.close()

    return restore
