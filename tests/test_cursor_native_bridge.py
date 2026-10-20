"""Cursor hooks run the generated client behind the native runtime."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import re
import shlex
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import codex_hook_command_line
from codex_plugin_scanner.guard.adapters._modules.cursor.cursor_hook_command_line import split_cursor_hook_command
from codex_plugin_scanner.guard.adapters._modules.cursor.cursor_hook_native import (
    NATIVE_CURSOR_HOOK_COMMAND,
    NATIVE_CURSOR_HOOK_FEATURE,
)
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.cursor_hook_config import (
    _is_managed_hook_command,
    _is_structured_managed_cursor_hook_command,
    _live_cursor_hook_script_path,
    _managed_hook_command,
)
from codex_plugin_scanner.guard.adapters.cursor_hooks import _HOOK_SCRIPT_TEMPLATE, cursor_hook_script_source
from codex_plugin_scanner.guard.adapters.native_hook_bridge import native_hook_bridge_executable

_POSIX_ONLY = pytest.mark.skipif(sys.platform == "win32", reason="asserts POSIX paths and hook command syntax")
_PYTHON = Path("/usr/bin/python3")
_NATIVE_SCRIPT = Path(__file__).resolve().parents[1] / "rust/crates/guard-runtime/src/cursor_hook_bridge_script.rs"
_ANSWERS = Path(__file__).resolve().parent / "fixtures" / "cursor_native_answers" / "vectors.json"
_AFTER_ANSWERS = _ANSWERS.with_name("after_vectors.json")
_AFTER_SCHEMA = "hol-guard-cursor-native-after-answers.v1"
_AFTER_INPUTS = (
    '{"hook_event_name": "afterShellExecution", "command": " ls -la ", "cwd": "/nonexistent-cursor-cwd",'
    ' "conversation_id": "c-1", "generation_id": "g-1", "output": "a\\nb", "duration": 12}',
    '{"hook_event_name": " AfterShellExecution ", "command": "pwd", "tool_input": {"command": "echo hi"}}',
    '{"hook_event_name": "afterMCPExecution", "tool_name": " lookup ", "tool_input": "{\\"q\\": 1}",'
    ' "result_json": "{}", "url": "https://example.invalid/mcp"}',
    '{"hook_event_name": "afterMCPExecution", "tool_input": ["a", 1]}',
    '{"hook_event_name": "AFTERMCPEXECUTION", "tool_name": "", "tool_input": "not json"}',
    '{"hookEventName": "afterShellExecution", "command": "ls", "workspace_roots": ["/nonexistent-root"]}',
    '{"hook_event_name": "after_shell_execution", "command": "ls"}',
    '{"hook_event_name": "after-mcp-execution", "tool_name": "x"}',
)
_AFTER_BODIES = ("{}", '{"policy_action": "block", "reason_code": "native_policy_block"}', ' {"x": [1]} ')
_CONSTANTS = (
    "GUARD_HOME",
    "GUARD_CLI",
    "GUARD_RECOVERY_COMMAND",
    "GUARD_HOOK_ARGV",
    "GUARD_INHERIT_ENV_KEYS",
    "GUARD_HOOK_TIMEOUT_SECONDS",
)


def _offer_native(monkeypatch: pytest.MonkeyPatch, runtime: Path) -> None:
    from codex_plugin_scanner.guard import native_runtime
    from codex_plugin_scanner.guard.native_runtime import (
        NativeRuntimeCapabilities,
        NativeRuntimeIdentity,
        NativeRuntimeStatus,
    )

    status = NativeRuntimeStatus(
        mode="auto",
        available=True,
        compatible=True,
        reason="ok",
        identity=NativeRuntimeIdentity(path=runtime, size=1, mtime_ns=1, sha256="0" * 64),
        capabilities=NativeRuntimeCapabilities(
            protocol_version=1,
            runtime_version="0",
            rule_digest="0" * 64,
            build_sha="0" * 40,
            target="test",
            features=(NATIVE_CURSOR_HOOK_FEATURE,),
        ),
    )
    monkeypatch.delenv("HOL_GUARD_CURSOR_HOOK_BRIDGE", raising=False)
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda *, deadline_monotonic=None: status)


def _script(tmp_path: Path) -> Path:
    script = tmp_path / "guard" / "managed" / "cursor" / "hol-guard-cursor-hook.py"
    script.parent.mkdir(parents=True)
    script.write_text("", encoding="utf-8")
    return script


@_POSIX_ONLY
def test_cursor_hook_runs_the_client_behind_the_native_runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = tmp_path / "hol-guard-runtime"
    _offer_native(monkeypatch, runtime)
    script = _script(tmp_path)

    command = _managed_hook_command(python_executable=_PYTHON, script_path=script, event_name="preToolUse")

    assert shlex.split(command) == [
        str(runtime),
        NATIVE_CURSOR_HOOK_COMMAND,
        str(_PYTHON),
        "-I",
        str(script.resolve()),
        "--cursor-hook-event",
        "preToolUse",
    ]
    assert _live_cursor_hook_script_path(command) == script.resolve()
    assert _is_structured_managed_cursor_hook_command(command) is True


@_POSIX_ONLY
def test_pinning_the_python_client_keeps_its_argv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _offer_native(monkeypatch, tmp_path / "hol-guard-runtime")
    monkeypatch.setenv("HOL_GUARD_CURSOR_HOOK_BRIDGE", "python")
    script = _script(tmp_path)

    command = _managed_hook_command(python_executable=_PYTHON, script_path=script, event_name="beforeReadFile")

    assert shlex.split(command)[:2] == [str(_PYTHON), "-I"]


def test_frozen_cursor_hook_keeps_its_launcher(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _offer_native(monkeypatch, tmp_path / "hol-guard-runtime")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.adapters.cursor_hook_config.isolated_cursor_hook_python", lambda: None
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.adapters.cursor_hook_config._frozen_cursor_hook_launcher", lambda: "/bin/hol-guard"
    )

    command = _managed_hook_command(python_executable=None, script_path=_script(tmp_path), event_name="preToolUse")

    assert shlex.split(command)[:2] == ["/bin/hol-guard", "__guard-cursor-hook"]


def test_native_bridge_is_offered_on_windows(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = tmp_path / "hol-guard-runtime.exe"
    _offer_native(monkeypatch, runtime)
    monkeypatch.setattr(os, "name", "nt")

    assert native_hook_bridge_executable(NATIVE_CURSOR_HOOK_FEATURE) == runtime


def test_frozen_builds_never_consult_the_native_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard import native_runtime

    def consulted(*, deadline_monotonic: float | None = None) -> object:
        raise AssertionError("native status consulted")

    monkeypatch.setattr(native_runtime, "native_runtime_status", consulted)
    monkeypatch.setattr(sys, "frozen", True, raising=False)

    assert native_hook_bridge_executable(NATIVE_CURSOR_HOOK_FEATURE) is None


_WINDOWS_PYTHON = r"C:\Program Files\Python312\python.exe"


def _use_windows_syntax(monkeypatch: pytest.MonkeyPatch, shorts: dict[str, str]) -> None:
    monkeypatch.setattr(
        codex_hook_command_line,
        "hook_commands_use_windows_syntax",
        lambda windows=None: True if windows is None else windows,
    )
    longs = {short: long for long, short in shorts.items()}
    monkeypatch.setattr(codex_hook_command_line, "_short_path", shorts.get)
    monkeypatch.setattr(codex_hook_command_line, "_long_path", longs.get)


def _assert_windows_native_command(command: str, runtime: str, script: Path) -> None:
    assert split_cursor_hook_command(command) == [
        runtime,
        NATIVE_CURSOR_HOOK_COMMAND,
        _WINDOWS_PYTHON,
        "-I",
        str(script.resolve()),
        "--cursor-hook-event",
        "preToolUse",
    ]
    assert _live_cursor_hook_script_path(command) == script.resolve()
    assert _is_structured_managed_cursor_hook_command(command) is True
    assert _is_managed_hook_command(command) is True


def test_windows_native_command_uses_short_names_as_plain_tokens(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = r"C:\Program Files\HOL Guard\hol-guard-runtime.exe"
    _offer_native(monkeypatch, Path(runtime))
    _use_windows_syntax(
        monkeypatch,
        {runtime: r"C:\PROGRA~1\HOLGUA~1\HOL-GU~1.EXE", _WINDOWS_PYTHON: r"C:\PROGRA~1\PYTHON~1\python.exe"},
    )
    script = _script(tmp_path)

    command = _managed_hook_command(
        python_executable=Path(_WINDOWS_PYTHON), script_path=script, event_name="preToolUse"
    )

    assert command.startswith("C:\\PROGRA~1\\HOLGUA~1\\HOL-GU~1.EXE cursor-hook-bridge C:\\PROGRA~1\\PYTHON~1")
    assert "'" not in command and '"' not in command
    _assert_windows_native_command(command, runtime, script)


def test_windows_native_command_falls_back_to_a_powershell_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = r"C:\Users\O'Neil\HOL Guard\hol-guard-runtime.exe"
    _offer_native(monkeypatch, Path(runtime))
    _use_windows_syntax(monkeypatch, {})
    script = _script(tmp_path)

    command = _managed_hook_command(
        python_executable=Path(_WINDOWS_PYTHON), script_path=script, event_name="preToolUse"
    )

    assert command.startswith("& 'C:\\Users\\O''Neil\\HOL Guard\\hol-guard-runtime.exe' 'cursor-hook-bridge' ")
    _assert_windows_native_command(command, runtime, script)


def test_legacy_posix_quoted_windows_command_still_parses(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _use_windows_syntax(monkeypatch, {})
    script = _script(tmp_path)
    runtime = r"C:\HOL Guard\hol-guard-runtime.exe"
    command = shlex.join([runtime, NATIVE_CURSOR_HOOK_COMMAND, _WINDOWS_PYTHON, "-I", str(script.resolve())])

    assert split_cursor_hook_command(command) == [
        runtime,
        NATIVE_CURSOR_HOOK_COMMAND,
        _WINDOWS_PYTHON,
        "-I",
        str(script.resolve()),
    ]
    assert _live_cursor_hook_script_path(command) == script.resolve()


def _native_digest() -> str:
    match = re.search(r'CURSOR_SCRIPT_SHA256: &str =\s*"([0-9a-f]{64})"', _NATIVE_SCRIPT.read_text(encoding="utf-8"))
    assert match is not None
    return match.group(1)


def test_native_bridge_was_ported_from_the_current_client() -> None:
    # A template change must be ported to cursor_hook_bridge.rs before the
    # digest is updated: the native bridge answers for every client it can
    # read, with no Python to hand a newer template to.
    digest = hashlib.sha256(_HOOK_SCRIPT_TEMPLATE.encode("utf-8")).hexdigest()

    assert digest == _native_digest()


def test_rendered_client_reads_back_as_the_template(tmp_path: Path) -> None:
    home = tmp_path / "home dir é"
    context = HarnessContext(home_dir=home, guard_home=home / ".hol-guard", workspace_dir=None)
    source = cursor_hook_script_source(context, guard_cli=["/bin/hol-guard"], recovery_command=["/bin/hol-guard"])

    lines = []
    for line in source.split("\n"):
        name = next((name for name in _CONSTANTS if line.startswith(f"{name} = ")), None)
        lines.append(line if name is None else f"{name} = __{name}__")

    assert "\n".join(lines) == _HOOK_SCRIPT_TEMPLATE


def _client(tmp_path: Path, timeout: str = "8") -> dict[str, object]:
    context = HarnessContext(home_dir=tmp_path, guard_home=tmp_path / "guard", workspace_dir=None)
    context.guard_home.mkdir()
    source = cursor_hook_script_source(context, guard_cli=[sys.executable], recovery_command=[sys.executable])
    source = source.replace("GUARD_HOOK_TIMEOUT_SECONDS = 42\n", f"GUARD_HOOK_TIMEOUT_SECONDS = {timeout}\n")
    namespace: dict[str, object] = {"__name__": "cursor_native_fixture"}
    exec(compile(source, "generated-cursor-hook", "exec"), namespace)
    return namespace


def test_native_answers_are_the_clients_own(tmp_path: Path) -> None:
    # The bridge prints these answers without running the client, so each
    # one must be what the client prints for the same daemon response.
    namespace = _client(tmp_path)
    emit = namespace["_emit_cursor_response"]
    vectors = json.loads(_ANSWERS.read_text(encoding="utf-8"))["vectors"]
    answered = [vector for vector in vectors if vector["stdout"] is not None]

    for vector in answered:
        payload = json.loads(vector["response"])
        response, exit_code = emit(
            hook_event_name=vector["event"],
            policy_action=payload["policy_action"],
            guard_payload=payload,
        )
        assert (json.dumps(response) + "\n", exit_code) == (vector["stdout"], vector["exit_code"])
    assert len(answered) >= 10


def test_client_takes_the_native_handoff_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOL_GUARD_BOUNDED_NATIVE_ELAPSED_MS", "1500")

    namespace = _client(tmp_path)

    budget = float(namespace["_HOOK_DEADLINE_MONOTONIC"]) - float(namespace["_HOOK_STARTED_MONOTONIC"])
    assert budget == pytest.approx(6.5)
    assert "HOL_GUARD_BOUNDED_NATIVE_ELAPSED_MS" not in namespace["os"].environ


@pytest.mark.parametrize("raw", ["-5", "1.5", "", " 7", "\u0661", "99999999"])
def test_client_never_gains_time_from_the_handoff(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, raw: str) -> None:
    monkeypatch.setenv("HOL_GUARD_BOUNDED_NATIVE_ELAPSED_MS", raw)

    namespace = _client(tmp_path)

    # `deadline - started` is not a stable <= 8: adding the integer timeout to
    # a monotonic float can round a few ulps high. The deadline itself is still
    # the start plus that timeout, or earlier when a real elapsed value is
    # removed. The 8 second cap stays the configured timeout.
    timeout = namespace["GUARD_HOOK_TIMEOUT_SECONDS"]
    assert timeout == 8
    started = namespace["_HOOK_STARTED_MONOTONIC"]
    deadline = namespace["_HOOK_DEADLINE_MONOTONIC"]
    assert started <= deadline <= started + timeout


@pytest.mark.parametrize(
    ("body", "taken"),
    [
        ('{"policy_action":"review","approval_url":"http://127.0.0.1:4781/approvals/req-1"}', True),
        ('{"policy_action":"block"}', True),
        ('{"policy_action":"allow"}', False),
        ('{"policy_action":"maybe"}', False),
        ("[]", False),
        ("{", False),
        (None, False),
    ],
)
def test_client_takes_only_a_restrictive_daemon_reply_from_the_bridge(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str | None, taken: bool
) -> None:
    namespace = _client(tmp_path)
    flag = namespace["_NATIVE_DAEMON_REPLY_FLAG"]
    argv = [sys.argv[0], "--cursor-hook-event", "beforeShellExecution", flag]
    monkeypatch.setattr(sys, "argv", argv if body is None else [*argv, body])

    reply = namespace["_native_daemon_reply_from_argv"]()

    assert reply == ((0, body, "") if taken else None)


def _run_after_client(tmp_path: Path, raw: str, body: str) -> tuple[dict[str, object], str, int]:
    tmp_path.mkdir()
    namespace = _client(tmp_path)
    sent: dict[str, object] = {}

    def daemon(payload_json: str, **_kwargs: object) -> tuple[tuple[int, str, str], None]:
        sent.update(json.loads(payload_json))
        return (0, body, ""), None

    namespace["_read_hook_input"] = lambda _deadline: raw
    namespace["_daemon_hook_result"] = daemon
    stdout = io.StringIO()
    with contextlib.redirect_stdout(stdout):
        exit_code = namespace["_main_inner"]()
    sent.pop("guard_execution_environment", None)
    return sent, stdout.getvalue(), exit_code


def _after_vectors(tmp_path: Path) -> dict[str, object]:
    # The client's own answer to each observer for every daemon body it
    # accepts; an input it answers with anything but `{}` is not an observer.
    vectors = []
    for index, raw in enumerate(_AFTER_INPUTS):
        answers = []
        sent: dict[str, object] = {}
        for number, body in enumerate(_AFTER_BODIES):
            sent, stdout, exit_code = _run_after_client(tmp_path / f"{index}-{number}", raw, body)
            answers.append({"daemon_body": body, "stdout": stdout, "exit_code": exit_code})
        observer = all((answer["stdout"], answer["exit_code"]) == ("{}\n", 0) for answer in answers)
        vectors.append({"input": raw, "observer": observer, "sent": sent, "answers": answers if observer else []})
    return {"schema": _AFTER_SCHEMA, "vectors": vectors}


@_POSIX_ONLY
def test_native_observer_answers_are_the_clients_own(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The bridge answers an observer with `{}` once the resident reviewed
    # it, so the client must print exactly that for every accepted body.
    monkeypatch.setattr(sys, "argv", ["hol-guard-cursor-hook.py"])
    monkeypatch.delenv("CURSOR_PROJECT_DIR", raising=False)
    generated = _after_vectors(tmp_path)

    assert generated == json.loads(_AFTER_ANSWERS.read_text(encoding="utf-8"))
    assert sum(1 for vector in generated["vectors"] if vector["observer"]) >= 6
