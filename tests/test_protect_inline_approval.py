"""A paused package install can be approved in the terminal that ran it."""

from __future__ import annotations

import argparse
import io
import os
from collections.abc import Iterator
from pathlib import Path

import pytest

import codex_plugin_scanner.guard.cli.approval_commands as approval_commands
import codex_plugin_scanner.guard.cli.commands_dispatch_local as dispatch
import codex_plugin_scanner.guard.cli.protect_inline_approval as inline
from codex_plugin_scanner.guard.cli.render import _plain_text_protect
from codex_plugin_scanner.guard.package_shim_status import PACKAGE_SHIM_STATUS_FD_ENV_VAR

_REQUEST_ID = "12d6a20a310749ae8aa620ccc38ea801"


def _paused_payload() -> dict[str, object]:
    return {
        "policy_action": "block",
        "request": {"command": ["bun", "install", "-g", "@openai/codex"]},
        "verdict": {
            "action": "require-reapproval",
            "blocking": True,
            "reason": "HOL Guard's current package policy requires fresh approval for `@openai/codex@latest`.",
        },
        "approval_requests": [],
        "approval_resume": {"request_id": _REQUEST_ID, "poll_path": "/v1/requests/x"},
    }


class _Store:
    def __init__(self, home: Path, *, status: str = "pending", resolution: str | None = None) -> None:
        self.guard_home = home
        self.path = home / "guard.db"
        self.status = status
        self.resolution = resolution

    def get_approval_request(self, request_id: str) -> dict[str, object] | None:
        return {"request_id": request_id, "status": self.status, "resolution_action": self.resolution}

    def get_cloud_sync_profile(self) -> None:
        return None


class _Terminal:
    """A pseudo-terminal pair standing in for the shim's stdin and stderr."""

    def __init__(self) -> None:
        self.input_master, input_slave = os.openpty()
        self.output_master, self.output_slave = os.openpty()
        self.stdin = os.fdopen(input_slave, "r")

    def type(self, text: str) -> None:
        os.write(self.input_master, text.encode())

    def env(self) -> dict[str, str]:
        return {PACKAGE_SHIM_STATUS_FD_ENV_VAR: str(self.output_slave), "NO_COLOR": "1"}

    def shown(self) -> str:
        chunks: list[bytes] = []
        os.set_blocking(self.output_master, False)
        while True:
            try:
                chunk = os.read(self.output_master, 65536)
            except (BlockingIOError, OSError):
                break
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks).decode().replace("\r\n", "\n")

    def close(self) -> None:
        self.stdin.close()
        for descriptor in (self.input_master, self.output_master, self.output_slave):
            os.close(descriptor)


@pytest.fixture
def terminal() -> Iterator[_Terminal]:
    if os.name != "posix":
        pytest.skip("the shim hands Guard its terminal only on POSIX")
    pair = _Terminal()
    yield pair
    pair.close()


@pytest.fixture
def approvals(monkeypatch: pytest.MonkeyPatch) -> list[argparse.Namespace]:
    recorded: list[argparse.Namespace] = []

    def approve(args: argparse.Namespace, **_kwargs: object) -> dict[str, object]:
        recorded.append(args)
        return {"resolved": True, "request_id": args.request_id}

    monkeypatch.setattr(approval_commands, "run_approval_command", approve)
    return recorded


def _ask(terminal: _Terminal, store: _Store, **overrides: object) -> dict[str, object] | None:
    options: dict[str, object] = {"env": terminal.env(), "stdin": terminal.stdin, "timeout_seconds": 5}
    options.update(overrides)
    return inline.inline_package_approval(_paused_payload(), store=store, workspace=store.guard_home, **options)


@pytest.mark.parametrize(("typed", "remember"), [("y\n", False), ("a\n", True)])
def test_typed_answer_approves_the_queued_request(
    tmp_path: Path, terminal: _Terminal, approvals: list[argparse.Namespace], typed: str, remember: bool
) -> None:
    terminal.type(typed)
    result = _ask(terminal, _Store(tmp_path))
    assert result == {"resolved": True, "items": [{"request_id": _REQUEST_ID, "resolution_action": "allow"}]}
    assert [(item.request_id, item.approval_action, item.remember) for item in approvals] == [
        (_REQUEST_ID, "allow", remember)
    ]
    shown = terminal.shown()
    assert "HOL Guard paused this install before it ran." in shown
    assert "bun install -g @openai/codex" in shown
    assert "Allow this install? [y/a/N]" in shown


@pytest.mark.parametrize("typed", ["n\n", "\n", "maybe\n"])
def test_anything_but_yes_keeps_the_install_blocked(
    tmp_path: Path, terminal: _Terminal, approvals: list[argparse.Namespace], typed: str
) -> None:
    terminal.type(typed)
    result = _ask(terminal, _Store(tmp_path))
    assert result is not None and result["resolved"] is False
    assert approvals == []


def test_no_answer_before_the_deadline_keeps_the_install_blocked(
    tmp_path: Path, terminal: _Terminal, approvals: list[argparse.Namespace]
) -> None:
    ticks = iter([0.0, 0.0, 10.0])
    result = _ask(terminal, _Store(tmp_path), clock=lambda: next(ticks, 10.0))
    assert result is not None and result["resolved"] is False
    assert "No answer" in terminal.shown()
    assert approvals == []


@pytest.mark.parametrize(("resolution", "resolved"), [("allow", True), ("block", False)])
def test_decision_made_in_the_approval_center_ends_the_prompt(
    tmp_path: Path, terminal: _Terminal, approvals: list[argparse.Namespace], resolution: str, resolved: bool
) -> None:
    result = _ask(terminal, _Store(tmp_path, status="resolved", resolution=resolution))
    assert result is not None and result["resolved"] is resolved
    assert approvals == []


def test_agent_sessions_and_non_terminals_are_not_prompted(
    tmp_path: Path, terminal: _Terminal, approvals: list[argparse.Namespace]
) -> None:
    store = _Store(tmp_path)
    assert _ask(terminal, store, env={**terminal.env(), "CLAUDECODE": "1"}) is None
    assert _ask(terminal, store, env={}) is None
    assert _ask(terminal, store, stdin=io.StringIO("y\n")) is None
    assert approvals == []
    assert terminal.shown() == ""


def test_plain_output_names_the_commands_that_approve_the_install(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(inline, "approval_resolution_invoked_from_agent", lambda _env: False)
    payload = _paused_payload()
    payload["supply_chain"] = {"status": "synced", "bundle": {}}
    payload["primary_approval_url"] = f"http://127.0.0.1:5474/requests/{_REQUEST_ID}"
    text = _plain_text_protect(payload)
    assert f"Approve in the browser: http://127.0.0.1:5474/requests/{_REQUEST_ID}\n" in text
    assert f"hol-guard approvals approve {_REQUEST_ID}\n" in text
    assert f"hol-guard approvals approve {_REQUEST_ID} --remember" in text
    assert "Then run it again: bun install -g @openai/codex" in text
    assert "hol-guard connect" in text


def test_agent_output_keeps_the_agent_guidance(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(inline, "approval_resolution_invoked_from_agent", lambda _env: True)
    assert "hol-guard approvals approve" not in _plain_text_protect(_paused_payload())


def test_request_text_cannot_restyle_the_prompt(
    tmp_path: Path, terminal: _Terminal, approvals: list[argparse.Namespace]
) -> None:
    payload = _paused_payload()
    payload["request"] = {"command": ["bun", "add", "pkg\x1b[2Jcleared"]}
    terminal.type("n\n")
    inline.inline_package_approval(
        payload, store=_Store(tmp_path), workspace=tmp_path, env=terminal.env(), stdin=terminal.stdin, timeout_seconds=5
    )
    shown = terminal.shown()
    assert "\x1b[2J" not in shown
    assert "pkg?[2Jcleared" in shown


def test_retry_line_is_quoted_and_names_the_manager_the_shim_wraps() -> None:
    payload = _paused_payload()
    payload["request"] = {"command": ["/opt/real/bin/bun", "add", "left-pad; rm -rf ~"]}
    assert inline.protect_command_text(payload) == "bun add 'left-pad; rm -rf ~'"


def test_approval_made_elsewhere_while_answering_still_runs_the_install(
    tmp_path: Path, terminal: _Terminal, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _Store(tmp_path)

    def approve_after_center(args: argparse.Namespace, **_kwargs: object) -> dict[str, object]:
        store.status, store.resolution = "resolved", "allow"
        return {"resolved": False, "error": "already_resolved", "request_id": args.request_id}

    monkeypatch.setattr(approval_commands, "run_approval_command", approve_after_center)
    terminal.type("y\n")
    result = _ask(terminal, store)
    assert result is not None and result["resolved"] is True


def _run_shim_protect(
    tmp_path: Path, terminal: _Terminal, monkeypatch: pytest.MonkeyPatch, *, timeout_seconds: int
) -> tuple[int, int]:
    builds: list[int] = []

    def build(**_kwargs: object) -> tuple[dict[str, object], int]:
        builds.append(1)
        return _paused_payload(), 1

    for name, value in {
        "build_protect_payload": build,
        "_refresh_cloud_policy_bundle": lambda *_args, **_kwargs: None,
        "_queue_local_protect_approvals": lambda *_args, **_kwargs: None,
        "load_guard_config": lambda *_args, **_kwargs: argparse.Namespace(),
        "overlay_synced_guard_policy": lambda local, _synced: local,
        "_synced_policy_payload": lambda _store: None,
        "_emit": lambda *_args, **_kwargs: None,
        "_protect_payload_for_human_output": lambda payload, **_kwargs: payload,
    }.items():
        monkeypatch.setattr(dispatch, name, value)
    monkeypatch.setattr(inline, "approval_resolution_invoked_from_agent", lambda _env: False)
    monkeypatch.setattr(inline.sys, "stdin", terminal.stdin)
    for key, value in terminal.env().items():
        monkeypatch.setenv(key, value)
    terminal.type("y\n")
    exit_code = dispatch._run_guard_protect_command(
        argparse.Namespace(
            protect_command=["bun", "install", "-g", "@openai/codex"],
            package_shim_ui=True,
            json=False,
            dry_run=True,
        ),
        guard_home=tmp_path,
        workspace=tmp_path,
        store=_Store(tmp_path),
        config=argparse.Namespace(mode="enforce", approval_wait_timeout_seconds=timeout_seconds),
    )
    return exit_code, len(builds)


def test_package_shim_runs_the_install_after_an_approval_at_the_terminal(
    tmp_path: Path,
    terminal: _Terminal,
    approvals: list[argparse.Namespace],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert _run_shim_protect(tmp_path, terminal, monkeypatch, timeout_seconds=120) == (0, 2)
    assert [item.request_id for item in approvals] == [_REQUEST_ID]


def test_a_zero_approval_wait_never_holds_the_install_at_a_prompt(
    tmp_path: Path,
    terminal: _Terminal,
    approvals: list[argparse.Namespace],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert _run_shim_protect(tmp_path, terminal, monkeypatch, timeout_seconds=0) == (1, 1)
    assert approvals == []
    assert terminal.shown() == ""
