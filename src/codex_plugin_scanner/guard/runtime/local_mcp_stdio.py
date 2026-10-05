"""Stdio JSON-RPC exchange for MCP initialize + tools/list probes."""

from __future__ import annotations

import contextlib
import json
import os
import shlex
import signal
import subprocess
import tempfile
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, TypeGuard

from .local_mcp_probe_env import (
    is_package_shim_executable as is_package_shim_executable,
)
from .local_mcp_probe_env import probe_env
from .local_mcp_probe_env import probe_search_path as probe_search_path
from .mcp_skills import McpSkillError, McpSkillsClient, mcp_skills_declared

_PROTOCOL = "2025-11-25"
_MODERN_PROTOCOL = "2026-07-28"
_LEGACY_PROTOCOLS = frozenset({"2024-11-05", "2025-03-26", "2025-06-18", _PROTOCOL})
_MODERN_ERROR_CODES = frozenset({-32020, -32021, -32022})
MCP_PROBE_TIMEOUT_SECONDS = 6.0
MCP_PACKAGE_PROBE_TIMEOUT_SECONDS = 20.0
MCP_PROBE_OUTPUT_LIMIT = 1_000_000
MAX_MCP_PROBE_TOOLS = 100


@dataclass(frozen=True, slots=True)
class McpCatalogResult:
    """Bounded discovery evidence; a partial inventory is never a complete one."""

    tools: tuple[dict[str, object], ...] = ()
    complete: bool = False
    reason: str | None = None
    pages: int = 0
    protocol_version: str | None = None
    server_info: dict[str, object] | None = None
    capabilities: dict[str, object] | None = None
    cache_ttl_ms: int = 0
    cache_scope: Literal["private", "public"] = "private"
    cache_received_at: str | None = None
    skills: tuple[dict[str, object], ...] = ()
    skills_complete: bool | None = None
    skills_reason: str | None = None


def _native_catalog_result(payload: dict[str, object]) -> McpCatalogResult | None:
    """Accept only a well-typed native catalog; malformed payloads use Python."""
    if payload.get("status") != "ok":
        reason = payload.get("reason", "native_failed")
        return McpCatalogResult(reason=reason) if reason is None or isinstance(reason, str) else None
    tools = payload.get("tools")
    protocol_version = payload.get("protocol_version")
    server_info = payload.get("server_info")
    capabilities = payload.get("capabilities")
    if not isinstance(tools, list) or len(tools) > MAX_MCP_PROBE_TOOLS:
        return None
    if any(not isinstance(tool, dict) or any(not isinstance(key, str) for key in tool) for tool in tools):
        return None
    if protocol_version is not None and not isinstance(protocol_version, str):
        return None
    if server_info is not None and not isinstance(server_info, dict):
        return None
    if capabilities is not None and not isinstance(capabilities, dict):
        return None
    return McpCatalogResult(
        tools=tuple(tools),
        complete=True,
        protocol_version=protocol_version,
        server_info=server_info,
        capabilities=capabilities,
    )


def _shlex_join_safe(argv: list[str]) -> str:
    try:
        return shlex.join(argv)
    except Exception:
        return " ".join(argv)


def run_mcp_catalog(
    argv: Sequence[str],
    *,
    timeout: float = MCP_PROBE_TIMEOUT_SECONDS,
    extra_env: Mapping[str, str] | None = None,
    cancel: threading.Event | None = None,
    connection_identity_hash: str | None = None,
    guard_home: Path | None = None,
) -> McpCatalogResult:
    """Discover tools while retaining bounded partial results and their cause."""

    if not argv or any(not part or "\x00" in part for part in argv):
        return McpCatalogResult(reason="invalid_launch")
    if cancel is not None and cancel.is_set():
        return McpCatalogResult(reason="cancelled")
    from .. import native_execution as _native_execution
    from ..config import resolve_guard_home

    _native_result = _native_execution.mcp_stdio_probe_native(
        _shlex_join_safe(list(argv)),
        cwd=Path.cwd(),
        extra_env=extra_env,
        guard_home=guard_home if guard_home is not None else resolve_guard_home(),
        timeout_seconds=timeout,
        connection_identity_hash=connection_identity_hash,
    )
    if _native_result is not None:
        native_catalog = _native_catalog_result(_native_result)
        if native_catalog is not None:
            return native_catalog
    try:
        with tempfile.TemporaryDirectory(prefix="hol-guard-mcp-probe-") as tmp:
            return _exchange_tools_list(
                list(argv),
                tmp,
                timeout=timeout,
                extra_env=extra_env,
                cancel=cancel,
                connection_identity_hash=connection_identity_hash,
            )
    except (OSError, ValueError, subprocess.TimeoutExpired, json.JSONDecodeError, UnicodeError):
        return McpCatalogResult(reason="transport_failed")


def run_mcp_tools_list(
    argv: Sequence[str],
    *,
    timeout: float = MCP_PROBE_TIMEOUT_SECONDS,
    extra_env: Mapping[str, str] | None = None,
) -> list[dict[str, object]] | None:
    """Compatibility API: return tools only when discovery is complete."""

    catalog = run_mcp_catalog(argv, timeout=timeout, extra_env=extra_env)
    return list(catalog.tools) if catalog.complete else None


def _exchange_tools_list(
    argv: list[str],
    tmp: str,
    *,
    timeout: float,
    extra_env: Mapping[str, str] | None = None,
    cancel: threading.Event | None = None,
    connection_identity_hash: str | None = None,
) -> McpCatalogResult:
    if cancel is not None and cancel.is_set():
        return McpCatalogResult(reason="cancelled")
    process = subprocess.Popen(
        argv,
        cwd=tmp,
        env=probe_env(tmp, extra_env),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    session = _RpcSession(process, cancel=cancel)
    deadline = time.monotonic() + max(timeout, 0.05)
    try:
        catalog = _negotiate_catalog(session, deadline)
        if cancel is not None and cancel.is_set():
            return McpCatalogResult(reason="cancelled")
        if catalog.reason is not None:
            return catalog
        collected: list[dict[str, object]] = []
        cursor: str | None = None
        seen_cursors: set[str] = set()
        seen_names: set[str] = set()
        request_id = 2
        pages = 0
        cache_deadline = time.monotonic()
        cache_scope: Literal["private", "public"] = "private"
        page_scope: str | None = None
        catalog_generation = session.catalog_generation

        def partial(reason: str) -> McpCatalogResult:
            return replace(catalog, tools=tuple(collected), reason=reason, pages=pages)

        for _ in range(8):
            params: dict[str, object] = {} if cursor is None else {"cursor": cursor}
            if catalog.protocol_version == _MODERN_PROTOCOL:
                params["_meta"] = _modern_request_meta()
            session.write({"jsonrpc": "2.0", "id": request_id, "method": "tools/list", "params": params})
            listed = _await_result(session, request_id, deadline)
            if cancel is not None and cancel.is_set():
                return partial("cancelled")
            if session.catalog_generation != catalog_generation:
                return partial("catalog_changed")
            if listed is None or listed.get("error") is not None:
                return partial("list_failed")
            result = listed.get("result")
            if not isinstance(result, dict):
                return partial("invalid_page")
            if catalog.protocol_version == _MODERN_PROTOCOL and result.get("resultType") != "complete":
                return partial("invalid_page")
            if catalog.protocol_version == _MODERN_PROTOCOL and not {"ttlMs", "cacheScope"}.issubset(result):
                return partial("invalid_cache_hints")
            ttl = result.get("ttlMs", 0)
            scope = result.get("cacheScope", "private")
            if type(ttl) is not int or scope not in ("private", "public"):
                return partial("invalid_cache_hints")
            # Hints never expand authority or share this private local cache.
            # Bound a claimed long TTL, and retain the earliest page deadline.
            page_deadline = time.monotonic() + min(max(ttl, 0), 86_400_000) / 1000
            if page_scope is not None and scope != page_scope:
                return partial("inconsistent_cache_scope")
            page_scope = scope
            cache_scope = "public" if scope == "public" else "private"
            cache_deadline = page_deadline if pages == 0 else min(cache_deadline, page_deadline)
            tools = result.get("tools")
            if not isinstance(tools, list):
                return partial("invalid_page")
            pages += 1
            page: list[dict[str, object]] = []
            page_names: set[str] = set()
            for item in tools:
                if not isinstance(item, dict):
                    return partial("invalid_tool")
                name = item.get("name")
                if not isinstance(name, str) or not name or name != name.strip():
                    return partial("invalid_tool")
                if name in seen_names or name in page_names:
                    return partial("duplicate_tool")
                page_names.add(name)
                page.append(item)
            remaining = MAX_MCP_PROBE_TOOLS - len(collected)
            collected.extend(page[:remaining])
            seen_names.update(page_names)
            next_cursor = result.get("nextCursor")
            if next_cursor is not None and not isinstance(next_cursor, str):
                return partial("invalid_cursor")
            if len(page) > remaining:
                return partial("tool_limit")
            if next_cursor is None:
                complete_catalog = replace(
                    catalog,
                    tools=tuple(collected),
                    complete=True,
                    pages=pages,
                    cache_ttl_ms=max(0, int((cache_deadline - time.monotonic()) * 1000)),
                    cache_scope=cache_scope,
                    cache_received_at=datetime.now(timezone.utc).isoformat(),
                )
                return _append_skill_metadata(
                    complete_catalog,
                    session,
                    deadline,
                    connection_identity_hash=connection_identity_hash,
                )
            if len(collected) == MAX_MCP_PROBE_TOOLS:
                return partial("tool_limit")
            if next_cursor in seen_cursors:
                return partial("repeated_cursor")
            seen_cursors.add(next_cursor)
            cursor = next_cursor
            request_id += 1
        return partial("page_limit")
    finally:
        _stop(process, session)


def _append_skill_metadata(
    catalog: McpCatalogResult,
    session: _RpcSession,
    deadline: float,
    *,
    connection_identity_hash: str | None,
) -> McpCatalogResult:
    if not mcp_skills_declared(catalog.capabilities, protocol_version=catalog.protocol_version or ""):
        return catalog
    if connection_identity_hash is None:
        return replace(catalog, skills_complete=False, skills_reason="skill_origin_not_bound")
    request_id = 100
    generation = session.catalog_generation

    def request(method: str, params: dict[str, object]) -> dict[str, object]:
        nonlocal request_id
        request_id += 1
        session.write({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        response = _await_result(session, request_id, deadline)
        if response is None or response.get("error") is not None:
            raise McpSkillError("skill_discovery_failed")
        result = response.get("result")
        if not isinstance(result, dict):
            raise McpSkillError("invalid_skills_result")
        return result

    try:
        client = McpSkillsClient(
            origin=connection_identity_hash,
            capabilities=catalog.capabilities,
            protocol_version=catalog.protocol_version or "",
            request=request,
        )
        entries, complete, reason = client.list_metadata()
    except McpSkillError as error:
        return replace(catalog, skills_complete=False, skills_reason=str(error))
    public: list[dict[str, object]] = []
    size = 0
    for entry in entries:
        metadata = entry.public_metadata()
        size += len(json.dumps(metadata, ensure_ascii=True).encode())
        if size > 512_000:
            complete, reason = False, "skill_metadata_limit"
            break
        public.append(metadata)
    result = replace(catalog, skills=tuple(public), skills_complete=complete, skills_reason=reason)
    if session.catalog_generation != generation:
        result = replace(result, complete=False, reason="catalog_changed")
    return result


def _modern_request_meta() -> dict[str, object]:
    return {
        "io.modelcontextprotocol/protocolVersion": _MODERN_PROTOCOL,
        "io.modelcontextprotocol/clientInfo": {"name": "hol-guard", "version": "3.0"},
        "io.modelcontextprotocol/clientCapabilities": {},
    }


def _negotiate_catalog(session: _RpcSession, deadline: float) -> McpCatalogResult:
    """Probe modern stdio, falling back only when it is not recognized."""

    session.write({"jsonrpc": "2.0", "id": 0, "method": "server/discover", "params": {"_meta": _modern_request_meta()}})
    remaining = max(0.0, deadline - time.monotonic())
    discovered = _await_result(session, 0, min(deadline, time.monotonic() + min(1.0, remaining / 4)))
    if discovered is not None:
        error = discovered.get("error")
        code = error.get("code") if isinstance(error, dict) else None
        if isinstance(code, int) and code in _MODERN_ERROR_CODES:
            reason = "unsupported_protocol" if code == -32022 else "discovery_rejected"
            return McpCatalogResult(reason=reason)
        if error is None:
            result = discovered.get("result")
            if not isinstance(result, dict) or result.get("resultType") != "complete":
                return McpCatalogResult(reason="invalid_discovery")
            versions = result.get("supportedVersions")
            capabilities = result.get("capabilities")
            if not isinstance(versions, list) or not all(isinstance(version, str) for version in versions):
                return McpCatalogResult(reason="invalid_discovery")
            if _MODERN_PROTOCOL not in versions:
                return McpCatalogResult(reason="unsupported_protocol")
            if not isinstance(capabilities, dict):
                return McpCatalogResult(reason="invalid_discovery")
            meta = result.get("_meta")
            server_info = meta.get("io.modelcontextprotocol/serverInfo") if isinstance(meta, dict) else None
            return McpCatalogResult(
                protocol_version=_MODERN_PROTOCOL,
                server_info=server_info if isinstance(server_info, dict) else None,
                capabilities=capabilities,
            )
    session.write({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": _initialize_params()})
    initialize = _await_result(session, 1, deadline)
    if initialize is None or initialize.get("error") is not None:
        return McpCatalogResult(reason="initialize_failed")
    result = initialize.get("result")
    if not isinstance(result, dict):
        return McpCatalogResult(reason="invalid_initialize")
    version = result.get("protocolVersion")
    if not isinstance(version, str) or version not in _LEGACY_PROTOCOLS:
        return McpCatalogResult(reason="unsupported_protocol")
    capabilities = result.get("capabilities")
    if not isinstance(capabilities, dict):
        return McpCatalogResult(reason="invalid_initialize")
    server_info = result.get("serverInfo")
    session.write({"jsonrpc": "2.0", "method": "notifications/initialized"})
    return McpCatalogResult(
        protocol_version=version,
        server_info=server_info if isinstance(server_info, dict) else None,
        capabilities=capabilities,
    )


def _initialize_params() -> dict[str, object]:
    return {
        "protocolVersion": _PROTOCOL,
        "capabilities": {"roots": {"listChanged": False}},
        "clientInfo": {"name": "hol-guard", "version": "3.0"},
    }


def _await_result(session: _RpcSession, request_id: int, deadline: float) -> dict[str, object] | None:
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        message = session.read(timeout=remaining)
        if message is None:
            return None
        if message.get("id") == request_id:
            return message
        if message.get("method") in {"notifications/tools/list_changed", "tools/list_changed"}:
            session.catalog_generation += 1
        _reply_server_request(session, message)


def _reply_server_request(session: _RpcSession, message: dict[str, object]) -> None:
    method = message.get("method")
    req_id = message.get("id")
    if not isinstance(method, str) or req_id is None or "result" in message or "error" in message:
        return
    if method == "roots/list":
        session.write({"jsonrpc": "2.0", "id": req_id, "result": {"roots": []}})
        return
    if method == "ping":
        session.write({"jsonrpc": "2.0", "id": req_id, "result": {}})
        return
    session.write({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": "Method not found"}})


class _RpcSession:
    def __init__(self, process: subprocess.Popen[bytes], *, cancel: threading.Event | None = None) -> None:
        self._process = process
        self._cancel = cancel
        self.catalog_generation = 0
        self._buffer = b""
        self._output_bytes = 0
        self._messages: list[dict[str, object]] = []
        self._lock = threading.Lock()
        self._closed = threading.Event()
        self._eof = threading.Event()
        self._thread = threading.Thread(target=self._drain, daemon=True)
        self._thread.start()

    def write(self, message: dict[str, object]) -> None:
        stdin = self._process.stdin
        if stdin is None:
            return
        payload = (json.dumps(message, separators=(",", ":")) + "\n").encode("utf-8")
        with contextlib.suppress(OSError, ValueError):
            _ = os.write(stdin.fileno(), payload)

    def read(self, *, timeout: float) -> dict[str, object] | None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._cancel is not None and self._cancel.is_set():
                return None
            with self._lock:
                if self._messages:
                    return self._messages.pop(0)
            if self._process.poll() is not None and self._eof.is_set():
                with self._lock:
                    return self._messages.pop(0) if self._messages else None
            time.sleep(0.01)
        return None

    def close(self) -> None:
        self._closed.set()
        stdout = self._process.stdout
        if stdout is not None:
            with contextlib.suppress(OSError):
                stdout.close()
        self._thread.join(1)

    def _drain(self) -> None:
        try:
            self._drain_stream()
        finally:
            self._eof.set()

    def _drain_stream(self) -> None:
        stdout = self._process.stdout
        if stdout is None:
            return
        fd = stdout.fileno()
        while not self._closed.is_set():
            try:
                chunk = os.read(fd, 8192)
            except OSError:
                return
            if chunk == b"":
                return
            with self._lock:
                self._output_bytes += len(chunk)
                if self._output_bytes > MCP_PROBE_OUTPUT_LIMIT:
                    return
                self._buffer += chunk
                while True:
                    parsed = _pop_json_message(self._buffer)
                    if parsed is None:
                        break
                    message, rest = parsed
                    self._buffer = rest
                    if _is_rpc_message(message):
                        if len(self._messages) >= 256:
                            return
                        self._messages.append(message)
                if len(self._buffer) > MCP_PROBE_OUTPUT_LIMIT:
                    self._buffer = b""
                    return


def _is_rpc_message(message: dict[str, object] | None) -> TypeGuard[dict[str, object]]:
    if message is None:
        return False
    if "result" in message or "error" in message:
        return True
    return "method" in message and (
        "id" in message
        or (
            message.get("jsonrpc") == "2.0"
            and message.get("method") in ("notifications/tools/list_changed", "tools/list_changed")
        )
    )


def _pop_json_message(buffer: bytes) -> tuple[dict[str, object] | None, bytes] | None:
    if buffer.startswith(b"Content-Length:"):
        header, sep, rest = buffer.partition(b"\r\n\r\n")
        if not sep:
            header, sep, rest = buffer.partition(b"\n\n")
        if not sep:
            return None
        try:
            length = int(header.split(b":", 1)[1].strip().splitlines()[0])
        except ValueError:
            return None
        if length > MCP_PROBE_OUTPUT_LIMIT:
            return (None, b"")
        if len(rest) < length:
            return None
        try:
            payload = _strict_rpc_json(rest[:length])
        except (ValueError, UnicodeDecodeError, RecursionError):
            return (None, rest[length:])
        return (payload if isinstance(payload, dict) else None, rest[length:])
    line, sep, rest = buffer.partition(b"\n")
    if not sep:
        return None
    stripped = line.strip()
    if not stripped:
        return (None, rest)
    try:
        payload = _strict_rpc_json(stripped)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return (None, rest)
    return (payload if isinstance(payload, dict) else None, rest)


def _strict_rpc_json(raw: bytes) -> object:
    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def constant(_value: str) -> object:
        raise ValueError("nonfinite JSON value")

    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)


def _stop(process: subprocess.Popen[bytes], session: _RpcSession | None = None) -> None:
    try:
        if os.name != "nt" and process.pid:
            # The launched parent can exit while its descendants keep stdout
            # open. Its private process group still belongs to this probe.
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except (ProcessLookupError, PermissionError, OSError):
        with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
            process.kill()
    with contextlib.suppress(subprocess.TimeoutExpired):
        _ = process.wait(timeout=1)
    if session is not None:
        session.close()
