"""Bounded stdio MCP initialize + tools/list probe for custom extensions."""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .command_model import parse_shell_command
from .local_cli_commands import OTHER_COMMAND_ID, LocalCliCommand, slug_local_cli_command_id
from .local_cli_identity import (
    UnlistedCliIdentity,
    identify_unlisted_cli,
    unlisted_cli_invocation_is_safe,
)
from .mcp_protection import McpServerIdentity, build_mcp_server_identity

McpProbeStatus = Literal["ok", "empty", "failed"]
McpToolsRunner = Callable[[Sequence[str]], list[dict[str, object]] | None]

_PROTOCOL = "2024-11-05"
_TIMEOUT_SECONDS = 6.0
_OUTPUT_LIMIT = 64_000
_MAX_TOOLS = 80
_PACKAGE_LAUNCHERS = frozenset({"bunx", "npx", "npm", "pnpm", "uvx", "yarn", "pipx"})
_STRICT_PACKAGE_LAUNCHERS = frozenset({"bunx", "npx", "pipx", "uvx"})


@dataclass(frozen=True, slots=True)
class McpProbeResult:
    identity: UnlistedCliIdentity
    server_identity: McpServerIdentity
    tools: tuple[LocalCliCommand, ...]
    status: McpProbeStatus
    argv: tuple[str, ...]


def mcp_launch_tokens(
    command_text: str,
    *,
    cwd: Path,
    home_dir: Path | None,
) -> tuple[str, ...] | None:
    """Return launch tokens when the pasted text is one safe invocation."""

    try:
        model = parse_shell_command(command_text, cwd=cwd, home_dir=home_dir)
    except ValueError:
        return None
    if not unlisted_cli_invocation_is_safe(model) or not model.segments:
        return None
    segment = model.segments[0]
    executable = segment.executable
    if executable is None or not executable.strip():
        return None
    return (executable, *segment.arguments)


def is_package_mcp_launcher(tokens: Sequence[str]) -> bool:
    if not tokens:
        return False
    name = _executable_basename(tokens[0])
    if name not in _PACKAGE_LAUNCHERS:
        return False
    identity = build_mcp_server_identity(
        config_path="",
        command=tokens[0],
        args=tuple(tokens[1:]),
        transport="stdio",
    )
    return bool(identity.package_name)


def is_strict_package_mcp_launcher(tokens: Sequence[str]) -> bool:
    return is_package_mcp_launcher(tokens) and _executable_basename(tokens[0]) in _STRICT_PACKAGE_LAUNCHERS


def looks_like_mcp_launch(
    tokens: Sequence[str],
    *,
    command_text: str,
    cwd: Path,
    home_dir: Path | None,
) -> bool:
    if is_package_mcp_launcher(tokens):
        return True
    return identify_unlisted_cli(command_text, cwd=cwd, home_dir=home_dir) is not None


def probe_stdio_mcp_server(
    command_text: str,
    *,
    cwd: Path,
    home_dir: Path | None,
    runner: McpToolsRunner | None = None,
    timeout: float = _TIMEOUT_SECONDS,
) -> McpProbeResult | None:
    """Launch a stdio MCP server and list tools, or return None when it is not MCP."""

    tokens = mcp_launch_tokens(command_text, cwd=cwd, home_dir=home_dir)
    if tokens is None:
        return None
    server_identity = build_mcp_server_identity(
        config_path="",
        command=tokens[0],
        args=tuple(tokens[1:]),
        transport="stdio",
    )
    argv = _resolve_launch_argv(tokens, cwd=cwd)
    if argv is None:
        return None
    raw_tools = runner(argv) if runner is not None else run_mcp_tools_list(argv, timeout=timeout)
    if raw_tools is None:
        return None
    tools = _tools_from_payload(raw_tools, server_name=_display_name(server_identity, tokens))
    status: McpProbeStatus = "ok" if any(tool.command_id != OTHER_COMMAND_ID for tool in tools) else "empty"
    identity = UnlistedCliIdentity(
        cli_id=f"local-cli.mcp-{server_identity.identity_hash[:8]}",
        name=_display_name(server_identity, tokens),
        kind="executable",
        identity_hash=server_identity.identity_hash,
        example_label=_example_label(tokens),
        interpreter_name=None,
    )
    return McpProbeResult(
        identity=identity,
        server_identity=server_identity,
        tools=tools,
        status=status,
        argv=argv,
    )


def run_mcp_tools_list(
    argv: Sequence[str],
    *,
    timeout: float = _TIMEOUT_SECONDS,
) -> list[dict[str, object]] | None:
    """Run initialize + tools/list against argv and return tool objects."""

    if not argv or any(not isinstance(part, str) or not part or "\x00" in part for part in argv):
        return None
    try:
        with tempfile.TemporaryDirectory(prefix="hol-guard-mcp-probe-") as tmp:
            return _exchange_tools_list(list(argv), tmp, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError, UnicodeError):
        return None


def _exchange_tools_list(argv: list[str], tmp: str, *, timeout: float) -> list[dict[str, object]] | None:
    process = subprocess.Popen(
        argv,
        cwd=tmp,
        env=_probe_env(tmp),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    session = _RpcSession(process)
    try:
        session.write({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": _initialize_params()})
        initialize = session.read(timeout=timeout)
        if initialize is None or initialize.get("error") is not None:
            return None
        session.write({"jsonrpc": "2.0", "method": "notifications/initialized"})
        collected: list[dict[str, object]] = []
        cursor: str | None = None
        request_id = 2
        for _ in range(8):
            params: dict[str, object] = {} if cursor is None else {"cursor": cursor}
            session.write({"jsonrpc": "2.0", "id": request_id, "method": "tools/list", "params": params})
            listed = session.read(timeout=timeout)
            if listed is None or listed.get("error") is not None:
                return collected if collected else None
            result = listed.get("result")
            if not isinstance(result, dict):
                return collected if collected else None
            tools = result.get("tools")
            if not isinstance(tools, list):
                return collected if collected else None
            collected.extend(item for item in tools if isinstance(item, dict))
            if len(collected) >= _MAX_TOOLS:
                return collected[:_MAX_TOOLS]
            next_cursor = result.get("nextCursor")
            if not isinstance(next_cursor, str) or not next_cursor.strip():
                return collected
            cursor = next_cursor.strip()
            request_id += 1
        return collected
    finally:
        _stop(process, session)


def _initialize_params() -> dict[str, object]:
    return {
        "protocolVersion": _PROTOCOL,
        "capabilities": {},
        "clientInfo": {"name": "hol-guard", "version": "3.0"},
    }


class _RpcSession:
    def __init__(self, process: subprocess.Popen[bytes]) -> None:
        self._process = process
        self._buffer = ""
        self._messages: list[dict[str, object]] = []
        self._lock = threading.Lock()
        self._closed = threading.Event()
        self._thread = threading.Thread(target=self._drain, daemon=True)
        self._thread.start()

    def write(self, message: dict[str, object]) -> None:
        stdin = self._process.stdin
        if stdin is None:
            return
        payload = (json.dumps(message, separators=(",", ":")) + "\n").encode("utf-8")
        os.write(stdin.fileno(), payload)

    def read(self, *, timeout: float) -> dict[str, object] | None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                if self._messages:
                    return self._messages.pop(0)
            if self._process.poll() is not None:
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
        stdout = self._process.stdout
        if stdout is None:
            return
        fd = stdout.fileno()
        while not self._closed.is_set():
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                return
            if chunk == b"":
                return
            with self._lock:
                self._buffer += chunk.decode("utf-8", errors="replace")
                if len(self._buffer) > _OUTPUT_LIMIT:
                    self._buffer = ""
                    return
                while True:
                    parsed = _pop_json_message(self._buffer)
                    if parsed is None:
                        break
                    message, rest = parsed
                    self._buffer = rest
                    if message is not None and ("result" in message or "error" in message):
                        self._messages.append(message)


def _pop_json_message(buffer: str) -> tuple[dict[str, object] | None, str] | None:
    if buffer.startswith("Content-Length:"):
        header, sep, rest = buffer.partition("\r\n\r\n")
        if not sep:
            header, sep, rest = buffer.partition("\n\n")
        if not sep:
            return None
        try:
            length = int(header.split(":", 1)[1].strip().splitlines()[0])
        except ValueError:
            return None
        raw = rest.encode("utf-8")
        if len(raw) < length:
            return None
        try:
            payload = json.loads(raw[:length].decode("utf-8"))
        except json.JSONDecodeError:
            return (None, raw[length:].decode("utf-8"))
        leftover = raw[length:].decode("utf-8")
        return (payload if isinstance(payload, dict) else None, leftover)
    line, sep, rest = buffer.partition("\n")
    if not sep:
        return None
    stripped = line.strip()
    if not stripped:
        return _pop_json_message(rest) if rest else None
    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError:
        return (None, rest)
    return (payload if isinstance(payload, dict) else None, rest)


def _resolve_launch_argv(tokens: Sequence[str], *, cwd: Path) -> tuple[str, ...] | None:
    first = tokens[0]
    if Path(first).is_absolute():
        resolved = first
    else:
        found = shutil.which(first)
        if found is None:
            candidate = cwd / first
            if not candidate.is_file():
                return None
            resolved = str(candidate)
        else:
            resolved = found
    arguments = [_absolute_existing_path(token, cwd=cwd) for token in tokens[1:]]
    return (resolved, *arguments)


def _absolute_existing_path(token: str, *, cwd: Path) -> str:
    if token.startswith("-") or token.startswith("@") or "://" in token:
        return token
    path = Path(token)
    if path.is_absolute():
        return token
    candidate = cwd / token
    try:
        if candidate.exists():
            return str(candidate.resolve())
    except OSError:
        return token
    return token


def _display_name(identity: McpServerIdentity, tokens: Sequence[str]) -> str:
    if identity.package_name:
        return identity.package_name
    return Path(tokens[0]).name or "mcp-server"


def _example_label(tokens: Sequence[str]) -> str:
    return " ".join(tokens)[:160]


def _tools_from_payload(raw_tools: Sequence[dict[str, object]], *, server_name: str) -> tuple[LocalCliCommand, ...]:
    discovered: list[LocalCliCommand] = []
    seen = {OTHER_COMMAND_ID}
    for item in raw_tools:
        name = item.get("name")
        if not isinstance(name, str) or not name.strip():
            continue
        command_id = slug_local_cli_command_id(name)
        if command_id in seen:
            continue
        seen.add(command_id)
        description = item.get("description")
        discovered.append(
            LocalCliCommand(
                command_id=command_id,
                name=name.strip()[:120],
                usage=name.strip()[:160],
                description=description.strip()[:240] if isinstance(description, str) else "",
            )
        )
        if len(discovered) >= _MAX_TOOLS - 1:
            break
    discovered.append(
        LocalCliCommand(
            command_id=OTHER_COMMAND_ID,
            name="Other tools",
            usage=f"{server_name} …",
            description="Any other tool this MCP server did not list.",
        )
    )
    return tuple(discovered)


def _probe_env(tmp: str) -> dict[str, str]:
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin:/opt/homebrew/bin:/usr/local/bin"),
        "HOME": tmp,
        "TMPDIR": tmp,
        "LANG": "C",
        "LC_ALL": "C",
        "TERM": "dumb",
        "NO_COLOR": "1",
        "PYTHONUNBUFFERED": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "npm_config_update_notifier": "false",
        "npm_config_fund": "false",
        "NPM_CONFIG_UPDATE_NOTIFIER": "false",
    }
    if os.name == "nt":
        system_root = os.environ.get("SYSTEMROOT")
        if system_root:
            env["SYSTEMROOT"] = system_root
    return env


def _executable_basename(value: str) -> str:
    name = Path(value).name.lower()
    if name.endswith(".exe") or name.endswith(".cmd"):
        return name.rsplit(".", 1)[0]
    return name


def _stop(process: subprocess.Popen[bytes], session: _RpcSession | None = None) -> None:
    if session is not None:
        session.close()
    if process.poll() is not None:
        return
    try:
        if os.name != "nt" and process.pid:
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except (ProcessLookupError, PermissionError, OSError):
        try:
            process.kill()
        except (ProcessLookupError, PermissionError, OSError):
            return
    with contextlib.suppress(subprocess.TimeoutExpired):
        process.wait(timeout=1)
