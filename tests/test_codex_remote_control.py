"""Tests for guarded Codex remote-control launches.

The runtime plans the launch and runs its processes; its Rust tests cover the sequence, the control socket
and the recorded pid. These tests cover what this client sends and how it reads the answer.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import codex_remote_client as codex_remote_control
from codex_plugin_scanner.guard import native_context


@pytest.fixture(autouse=True)
def _native_runtime_probed(_ambient_context_digest_home: None) -> None:
    native_context._native_runtime_status_memo()  # pyright: ignore[reportPrivateUsage]


def _socket(home_dir: Path) -> Path:
    return home_dir / ".codex" / "app-server-control" / "app-server-control.sock"


def test_guarded_codex_launch_candidates_are_side_effect_free(tmp_path: Path) -> None:
    candidates = codex_remote_control.guarded_codex_launch_command_candidates(
        executable="/usr/bin/codex",
        home_dir=tmp_path / "home",
        passthrough_args=["Fix it."],
    )

    assert candidates == (
        ["/usr/bin/codex", "--remote", f"unix://{_socket(tmp_path / 'home')}", "Fix it."],
        ["/usr/bin/codex", "Fix it."],
    )
    assert not (tmp_path / "home").exists()


def test_a_launch_asks_the_runtime_to_run_with_the_prefix_and_environment(tmp_path: Path, monkeypatch) -> None:
    requests: list[tuple[str, dict[str, object], float | None]] = []

    def scripted(op: str, fields: dict[str, object], budget: float | None = None) -> dict[str, object]:
        requests.append((op, dict(fields), budget))
        return {"argv": ["codex", "--remote", "unix:///x.sock", "Fix it."]}

    monkeypatch.setattr(codex_remote_control, "_ask", scripted)

    command = codex_remote_control.guarded_codex_launch_command_from_prefixes(
        executable_prefixes=(("/bin/sh", "/opt/codex"),),
        home_dir=tmp_path,
        passthrough_args=["Fix it."],
        environ={"PATH": "/usr/bin"},
    )

    assert command == ["codex", "--remote", "unix:///x.sock", "Fix it."]
    assert requests == [
        (
            "run",
            {
                "prefixes": [["/bin/sh", "/opt/codex"]],
                "home_dir": str(tmp_path),
                "args": ["Fix it."],
                "environ": {"PATH": "/usr/bin"},
            },
            codex_remote_control._RUN_BUDGET_SECONDS,  # pyright: ignore[reportPrivateUsage]
        )
    ]


@pytest.mark.parametrize("answer", [{}, {"argv": []}, {"argv": [1]}, {"argv": "codex"}])
def test_a_runtime_that_cannot_answer_leaves_the_ordinary_launch(tmp_path: Path, monkeypatch, answer) -> None:
    monkeypatch.setattr(codex_remote_control, "_ask", lambda *_args, **_kwargs: answer)

    command = codex_remote_control.guarded_codex_launch_command(
        executable="codex",
        home_dir=tmp_path / "home",
        passthrough_args=["Fix the failing test."],
        environ={},
    )

    assert command == ["codex", "Fix the failing test."]


@pytest.mark.parametrize(
    "args",
    [["exec", "Run tests."], ["--config", "model_reasoning_effort=high", "exec", "Run tests."]],
)
def test_guarded_codex_launch_does_not_wrap_unsupported_subcommands(tmp_path: Path, args: list[str]) -> None:
    command = codex_remote_control.guarded_codex_launch_command(
        executable="/nonexistent/codex",
        home_dir=tmp_path / "home",
        passthrough_args=args,
        environ={},
    )

    assert command == ["/nonexistent/codex", *args]
    assert not (tmp_path / "home").exists()


def test_guarded_codex_launch_preserves_explicit_remote_target(tmp_path: Path) -> None:
    command = codex_remote_control.guarded_codex_launch_command(
        executable="/nonexistent/codex",
        home_dir=tmp_path / "home",
        passthrough_args=["--remote", "unix:///custom/codex.sock"],
        environ={},
    )

    assert command == ["/nonexistent/codex", "--remote", "unix:///custom/codex.sock"]


def test_a_refused_launch_raises_the_resident_refusal(tmp_path: Path, monkeypatch) -> None:
    refusal = "Codex launch preparation requires a canonical executable prefix."
    monkeypatch.setattr(codex_remote_control, "_ask", lambda *_args, **_kwargs: {"refusal": refusal})

    with pytest.raises(ValueError, match="canonical executable prefix"):
        codex_remote_control.guarded_codex_launch_command(executable="", home_dir=tmp_path, passthrough_args=[])
    with pytest.raises(ValueError, match="canonical executable prefix"):
        codex_remote_control.guarded_codex_launch_command_candidates(
            executable="", home_dir=tmp_path, passthrough_args=[]
        )
