"""The context CLI and MCP tools only carry data to and from the native runtime."""

from __future__ import annotations

import io
import json
import queue
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_context, native_recovery_store
from codex_plugin_scanner.guard.cli import runtime_forward
from codex_plugin_scanner.guard.config import resolve_guard_home
from codex_plugin_scanner.guard.mcp import native_tools
from codex_plugin_scanner.guard.mcp.server import GuardMCPServer

_TOOL = {
    "name": "get_context_status",
    "description": "Read this connection's native context status.",
    "input_schema": {"type": "object", "properties": {}, "additionalProperties": False},
    "annotations": {"read_only": True, "destructive": False, "idempotent": True, "open_world": False},
}


class _Pipe:
    """The runtime process's stdin: answers each line on its stdout."""

    def __init__(self, process: _Process) -> None:
        self._process = process

    def write(self, data: bytes) -> None:
        self._process.lines.append(json.loads(data))
        self._process.answer(json.loads(data))

    def flush(self) -> None:
        pass

    def close(self) -> None:
        self._process.stdout.put(b"")


class _Out:
    def __init__(self) -> None:
        self._lines: queue.Queue[bytes] = queue.Queue()

    def put(self, line: bytes) -> None:
        self._lines.put(line)

    def readline(self) -> bytes:
        return self._lines.get()


class _Process:
    def __init__(self, argv: list[str], *, silent: bool = False) -> None:
        self.argv = argv
        self.lines: list[dict[str, object]] = []
        self.stdout = _Out()
        self.stdin = _Pipe(self)
        self.silent = silent
        self.killed = False

    def answer(self, message: dict[str, object]) -> None:
        if self.silent:
            self.stdout.put(b"")
            return
        op = message["op"]
        if op == "catalog" or op == "tools":
            reply: dict[str, object] = {"tools": [_TOOL]}
        elif op == "call":
            reply = {"known": True, "text": '{"ok":true}'}
        else:
            reply = {"closed": True}
        self.stdout.put(json.dumps(reply).encode() + b"\n")

    def wait(self, timeout: float | None = None) -> int:
        return 0

    def kill(self) -> None:
        self.killed = True


@pytest.fixture
def prerequisite(monkeypatch: pytest.MonkeyPatch) -> list[Path]:
    homes: list[Path] = []

    def ensure(home: Path, **_: object) -> bool:
        homes.append(home)
        return True

    monkeypatch.setattr(native_context, "ensure_resident_prerequisite", ensure)
    monkeypatch.setattr(native_recovery_store, "recovery_runtime_path", lambda feature: f"/runtime/{feature}")
    return homes


@pytest.fixture
def processes(monkeypatch: pytest.MonkeyPatch, prerequisite: list[Path]) -> list[_Process]:
    started: list[_Process] = []

    def popen(argv: list[str], **_: object) -> _Process:
        started.append(_Process(list(argv)))
        return started[-1]

    monkeypatch.setattr(subprocess, "Popen", popen)
    return started


def _args(forward_args: list[str], **overrides: object) -> SimpleNamespace:
    values: dict[str, object] = {
        "runtime_command": "context",
        "guard_home": None,
        "json": False,
        "forward_help": False,
        "forward_args": forward_args,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_cli_hands_every_argument_and_the_resolved_home_to_the_runtime(
    monkeypatch, prerequisite, tmp_path: Path
) -> None:
    calls: list[list[str]] = []

    def run(argv: list[str], **_: object) -> SimpleNamespace:
        calls.append(list(argv))
        return SimpleNamespace(returncode=3, stdout=b"from runtime\n")

    monkeypatch.setattr(subprocess, "run", run)
    out = io.StringIO()
    args = _args(["switch", "--guard-home", str(tmp_path), "--job-id", "j", "cigar-1"], json=True)
    assert runtime_forward.run_forward(args, output_stream=out) == 3
    assert out.getvalue() == "from runtime\n"
    home = str(resolve_guard_home(str(tmp_path)))
    runtime = f"/runtime/{runtime_forward.FEATURE}"
    assert calls == [[runtime, "context", "--guard-home", home, "--json", "switch", "--job-id", "j", "cigar-1"]]
    assert [str(path) for path in prerequisite] == [home]


_INCOMPLETE = [["off", "--guard-home"], ["off", "--guard-home", "--json"], ["--guard-home="]]


@pytest.mark.parametrize("forward_args", _INCOMPLETE)
def test_cli_rejects_a_guard_home_flag_without_a_folder(monkeypatch, prerequisite, forward_args) -> None:
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("ran the runtime"))
    out = io.StringIO()
    assert runtime_forward.run_forward(_args(forward_args), output_stream=out) == 2
    assert prerequisite == []


def test_cli_reports_a_missing_runtime_as_json_when_asked(monkeypatch, prerequisite, tmp_path: Path) -> None:
    def missing(feature: str) -> str:
        raise RuntimeError(feature)

    monkeypatch.setattr(native_recovery_store, "recovery_runtime_path", missing)
    out = io.StringIO()
    args = _args(["status", "--json"], guard_home=str(tmp_path))
    assert runtime_forward.run_forward(args, output_stream=out) == 1
    assert json.loads(out.getvalue()) == {
        "schema": "guard-context-assistance-cli.v1",
        "status": "unavailable",
        "code": "native_runtime_unavailable",
    }
    out = io.StringIO()
    assert runtime_forward.run_forward(_args(["status"], guard_home=str(tmp_path)), output_stream=out) == 1
    assert "native runtime is unavailable" in out.getvalue()


def test_mcp_keeps_one_runtime_process_for_the_connection(processes, tmp_path: Path) -> None:
    server = GuardMCPServer(tmp_path)
    tool = next(tool for tool in server.list_tools() if tool.name == "get_context_status")
    assert tool.description == _TOOL["description"] and tool.annotations.readOnlyHint
    assert server.call_tool("get_context_status", {"extra": 1}).text == '{"ok":true}'
    assert server.call_tool("get_context_status", {}).text == '{"ok":true}'
    server._native.close()
    assert len(processes) == 1
    process = processes[0]
    assert process.argv[1:] == ["context-mcp", "--guard-home", str(tmp_path)]
    assert [line["op"] for line in process.lines] == ["tools", "catalog", "call", "call", "close"]
    assert process.lines[2]["arguments"] == {"extra": 1}
    assert all("session" not in line for line in process.lines)


def test_mcp_never_replaces_a_runtime_that_may_have_paired(monkeypatch, prerequisite, tmp_path: Path) -> None:
    started: list[_Process] = []

    def popen(argv: list[str], **_: object) -> _Process:
        started.append(_Process(list(argv), silent=True))
        return started[-1]

    monkeypatch.setattr(subprocess, "Popen", popen)
    session = native_tools.NativeToolSession(tmp_path)
    assert session.allowed() == []
    assert started[0].killed
    assert json.loads(session.call("get_context_status", {}))["ok"] is False
    assert session.names() == frozenset()
    assert len(started) == 1


def test_mcp_waits_before_trying_a_missing_runtime_again(monkeypatch, prerequisite, tmp_path: Path) -> None:
    attempts: list[str] = []

    def broken(argv: list[str], **_: object) -> _Process:
        attempts.append(argv[0])
        raise OSError("gone")

    monkeypatch.setattr(subprocess, "Popen", broken)
    session = native_tools.NativeToolSession(tmp_path)
    assert session.allowed() == [] and session.names() == frozenset()
    assert json.loads(session.call("get_context_status", {}))["ok"] is False
    assert len(attempts) == 1


@pytest.mark.parametrize("command", ["context", "ctx"])
def test_ctx_is_a_short_name_for_context(monkeypatch, prerequisite, tmp_path: Path, command: str) -> None:
    from codex_plugin_scanner.cli import _build_parser
    from codex_plugin_scanner.guard.cli.commands_router import run_guard_command

    calls: list[list[str]] = []

    def run(argv: list[str], **_: object) -> SimpleNamespace:
        calls.append(list(argv))
        return SimpleNamespace(returncode=0, stdout=b"")

    monkeypatch.setattr(subprocess, "run", run)
    args = _build_parser("hol-guard", program_mode="hol-guard").parse_args(
        [command, "--guard-home", str(tmp_path), "status", "--json"]
    )
    assert run_guard_command(args, output_stream=io.StringIO()) == 0
    assert calls[0][1] == "context" and calls[0][-2:] == ["status", "--json"]
