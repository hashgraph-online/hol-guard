"""Startup contracts for the daemon's Python children.

The native daemon starts the worker host and library children through a fast
path that must not load the full Guard command surface, and that resolves the
runtime status beside the child's imports.
"""

from __future__ import annotations

import contextlib
import io
import sys
from pathlib import Path

import pytest

import codex_plugin_scanner

_COMMANDS_HUB = "codex_plugin_scanner.guard.cli.commands"
_CLI_MODULE = "codex_plugin_scanner.cli"
_COMMANDS_PARSER = "codex_plugin_scanner.guard.cli.commands_parser"
_COMMANDS_SUPPORT = "codex_plugin_scanner.guard.cli.commands_support"


def _run_as_hol_guard(argv: list[str]) -> tuple[int, str]:
    from codex_plugin_scanner.cli import main

    previous_argv = sys.argv
    sys.argv = ["hol-guard", *argv]
    try:
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            code = main(argv)
        return code, captured.getvalue()
    finally:
        sys.argv = previous_argv


def test_daemon_workers_fast_path_argv_accepts_only_the_native_launch_shape() -> None:
    from codex_plugin_scanner.guard.cli.desktop_daemon_workers import is_daemon_workers_fast_path_argv

    assert is_daemon_workers_fast_path_argv(["desktop", "daemon-workers", "--guard-home", "/g"]) is True
    assert is_daemon_workers_fast_path_argv(["guard", "desktop", "daemon-workers", "--guard-home", "/g"]) is True
    assert is_daemon_workers_fast_path_argv(["desktop", "daemon-workers"]) is False
    assert is_daemon_workers_fast_path_argv(["desktop", "daemon-workers", "--guard-home"]) is False
    assert is_daemon_workers_fast_path_argv(["desktop", "daemon-workers", "--guard-home", "--help"]) is False
    assert is_daemon_workers_fast_path_argv(["desktop", "daemon-workers", "--help"]) is False
    assert is_daemon_workers_fast_path_argv(["desktop", "daemon-workers", "--guard-home", "/g", "--json"]) is False
    assert is_daemon_workers_fast_path_argv(["desktop", "library-serve", "--guard-home", "/g"]) is True
    assert is_daemon_workers_fast_path_argv(["desktop", "library-call", "--guard-home", "/g"]) is True
    assert is_daemon_workers_fast_path_argv(["desktop", "library-serve", "--guard-home", "/g", "--x"]) is False
    assert is_daemon_workers_fast_path_argv(["desktop", "converge", "--guard-home", "/g"]) is False
    assert is_daemon_workers_fast_path_argv(["desktop", "bootstrap", "--guard-home", "/g"]) is False


def test_hol_guard_daemon_workers_skips_command_surface(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from codex_plugin_scanner.guard import native_context
    from codex_plugin_scanner.guard.cli import desktop_daemon_workers
    from codex_plugin_scanner.guard.workers import host

    calls: list[tuple[str, Path | None]] = []
    checked: list[str] = []
    monkeypatch.setattr(desktop_daemon_workers, "_check_installed_bundle", lambda: checked.append("bundle"))
    monkeypatch.setattr(desktop_daemon_workers, "_resolve_runtime_status", lambda: checked.append("runtime"))
    monkeypatch.setattr(desktop_daemon_workers, "_runtime_status", None)

    def fake_bind(guard_home: Path | None, *, remember: bool = True) -> None:
        del remember
        calls.append(("bind", guard_home))

    def fake_host(guard_home: Path) -> int:
        calls.append(("host", guard_home))
        return 0

    monkeypatch.setattr(native_context, "bind_context_digest_home", fake_bind)
    monkeypatch.setattr(host, "run_worker_host", fake_host)
    monkeypatch.delitem(sys.modules, _COMMANDS_HUB, raising=False)
    monkeypatch.delitem(sys.modules, _COMMANDS_PARSER, raising=False)
    monkeypatch.delitem(sys.modules, _COMMANDS_SUPPORT, raising=False)
    monkeypatch.delitem(sys.modules, _CLI_MODULE, raising=False)
    monkeypatch.delattr(codex_plugin_scanner, "cli", raising=False)

    guard_home = tmp_path / "guard"
    code, _ = _run_as_hol_guard(["desktop", "daemon-workers", "--guard-home", str(guard_home)])

    assert code == 0
    # The digest home is bound before the host starts, as the command router does.
    assert calls == [("bind", guard_home.resolve()), ("host", guard_home.resolve())]
    # The host's bundle check started before the host, and the host's migration waits for it.
    assert desktop_daemon_workers.wait_for_early_bundle_check() is True
    # The runtime status the store's first native call needs also resolves beside the imports.
    assert desktop_daemon_workers.wait_for_early_runtime_status() is True
    assert sorted(checked) == ["bundle", "runtime"]
    assert desktop_daemon_workers.wait_for_early_bundle_check() is False
    # Every later caller waits on the same resolution instead of starting another.
    assert desktop_daemon_workers.wait_for_early_runtime_status() is True
    assert sorted(checked) == ["bundle", "runtime"]
    assert _COMMANDS_HUB not in sys.modules
    assert _COMMANDS_PARSER not in sys.modules
    assert _COMMANDS_SUPPORT not in sys.modules


@pytest.mark.parametrize(
    ("command", "handler"),
    [("library-serve", "serve_library_calls"), ("library-call", "run_library_call")],
)
def test_hol_guard_library_children_skip_command_surface(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    command: str,
    handler: str,
) -> None:
    from codex_plugin_scanner.guard.cli import desktop_daemon_workers, desktop_library_call

    served: list[Path] = []
    checked: list[str] = []
    monkeypatch.setattr(desktop_daemon_workers, "_check_installed_bundle", lambda: checked.append("bundle"))
    monkeypatch.setattr(desktop_daemon_workers, "_resolve_runtime_status", lambda: checked.append("runtime"))
    monkeypatch.setattr(desktop_daemon_workers, "_runtime_status", None)

    def fake_child(guard_home: Path) -> int:
        served.append(guard_home)
        return 0

    monkeypatch.setattr(desktop_library_call, handler, fake_child)
    monkeypatch.delitem(sys.modules, _COMMANDS_HUB, raising=False)
    monkeypatch.delitem(sys.modules, _COMMANDS_PARSER, raising=False)
    monkeypatch.delitem(sys.modules, _COMMANDS_SUPPORT, raising=False)
    monkeypatch.delitem(sys.modules, _CLI_MODULE, raising=False)
    monkeypatch.delattr(codex_plugin_scanner, "cli", raising=False)

    guard_home = tmp_path / "guard"
    code, _ = _run_as_hol_guard(["desktop", command, "--guard-home", str(guard_home)])

    assert code == 0
    assert served == [guard_home.resolve()]
    # A library child opens a store for its first call, and the reconcile the
    # daemon waits on before ready is one, so its launch resolves the runtime
    # status beside the imports too. It has no installed-bundle check.
    assert desktop_daemon_workers.wait_for_early_runtime_status() is True
    assert checked == ["runtime"]
    assert _COMMANDS_HUB not in sys.modules
    assert _COMMANDS_PARSER not in sys.modules
    assert _COMMANDS_SUPPORT not in sys.modules


def test_a_library_call_waits_for_the_early_runtime_status_before_it_runs(monkeypatch: pytest.MonkeyPatch) -> None:
    import threading

    from codex_plugin_scanner.guard import library_calls
    from codex_plugin_scanner.guard.cli import desktop_daemon_workers, desktop_library_call

    order: list[str] = []
    resolved = threading.Event()

    def resolve() -> None:
        resolved.wait(5)
        order.append("status")

    monkeypatch.setattr(desktop_daemon_workers, "_runtime_status", None)
    monkeypatch.setattr(desktop_daemon_workers, "_resolve_runtime_status", resolve)
    monkeypatch.setattr(library_calls, "run_library_call", lambda _home, _request: order.append("call") or {"ok": {}})
    desktop_daemon_workers._start_runtime_status()

    answers: list[bytes] = []
    callers = [
        threading.Thread(target=lambda: answers.append(desktop_library_call.answer_line(Path("guard"), b'{"id":1}')))
        for _ in range(2)
    ]
    for caller in callers:
        caller.start()
    callers[0].join(0.2)
    # Neither call opens its store while the status is still resolving.
    assert order == []
    resolved.set()
    for caller in callers:
        caller.join(5)
    assert order == ["status", "call", "call"]
    assert len(answers) == 2


def test_hol_guard_daemon_workers_fast_path_reports_a_host_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from codex_plugin_scanner.guard.cli import desktop_daemon_workers
    from codex_plugin_scanner.guard.workers import host

    monkeypatch.setattr(desktop_daemon_workers, "_check_installed_bundle", lambda: None)
    monkeypatch.setattr(desktop_daemon_workers, "_resolve_runtime_status", lambda: None)

    def failing_host(guard_home: Path) -> int:
        del guard_home
        raise RuntimeError("worker host could not start")

    monkeypatch.setattr(host, "run_worker_host", failing_host)

    code, _ = _run_as_hol_guard(["desktop", "daemon-workers", "--guard-home", str(tmp_path / "guard")])

    assert code == 1
    assert "worker host could not start" in capsys.readouterr().err
    assert desktop_daemon_workers.wait_for_early_bundle_check() is True
    assert desktop_daemon_workers.wait_for_early_runtime_status() is True
