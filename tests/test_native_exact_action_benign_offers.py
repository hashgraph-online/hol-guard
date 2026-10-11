"""Benign repeatable actions get an exact-action Always; risky reviews never do."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.hook_native_saved_approval import native_exact_action_decision
from tests.test_native_review_exact_action_always import (
    _HARNESS,
    _native_package_intent,  # noqa: F401  (autouse fixture)
    _token,
    _verdict,
    _wrangler_workspace,
    _write_executable,
)


def _workspace(root: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    workspace = _wrangler_workspace(root, monkeypatch)
    # Resolve the programs through a pinned directory, as an installed toolchain would.
    for name in ("cargo", "python3", "node", "pytest", "rg"):
        _write_executable(root / "manager-bin" / name, name)
    return workspace


def _decide(
    tool: str, tool_input: dict[str, object], workspace: Path, **overrides: object
) -> tuple[str | None, str | None]:
    result, receipt = _verdict(**overrides)
    return native_exact_action_decision(
        harness=_HARNESS,
        tool_name=tool,
        payload={"tool_name": tool, "tool_input": tool_input, "cwd": str(workspace)},
        native_result=result,
        native_receipt=receipt,
        workspace=workspace,
        home_dir=workspace.parent / "home",
    )


@pytest.mark.parametrize("command", ["rg -V", "rg --version"])
def test_version_probe_of_a_plain_binary_is_eligible(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path, command: str
) -> None:
    workspace = _workspace(tmp_path, monkeypatch)
    assert _token(command, workspace) is not None


@pytest.mark.parametrize(
    "command",
    [
        "python3 test_calc.py",
        # pytest loads conftest.py and plugins before it handles --version, and
        # rustup resolves cargo from rust-toolchain.toml, so the launcher binary
        # alone does not bind what runs.
        "pytest --version",
        "cargo --version",
        # The resident gives an interpreter with no entrypoint a fresh nonce.
        "python3 --version",
        "node -V",
        "cargo --version --foo",
        "cargo build",
        "python3 --version script.py",
        "FOO=1 cargo --version",
        "sudo --version",
        "env --version",
        "python3 -c 'print(1)' --version",
    ],
)
def test_launchers_that_run_code_stay_once_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path, command: str
) -> None:
    workspace = _workspace(tmp_path, monkeypatch)
    assert _token(command, workspace) is None


@pytest.mark.parametrize("tool", ["todo", "todo_write", "TodoWrite"])
def test_state_only_tools_are_eligible(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path, tool: str
) -> None:
    workspace = _workspace(tmp_path, monkeypatch)
    token, reason = _decide(tool, {"ops": [{"op": "add", "text": "x"}]}, workspace)
    assert token is not None and reason is None
    other, _ = _decide(tool, {"ops": []}, workspace)
    # Content never changes what the tool can touch, so the identity is shared.
    assert other == token


@pytest.mark.parametrize("tool", ["eval", "write", "edit", "bash_background"])
def test_code_and_write_tools_stay_once_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path, tool: str
) -> None:
    workspace = _workspace(tmp_path, monkeypatch)
    token, reason = _decide(tool, {"path": "a.txt", "code": "1+1"}, workspace)
    assert token is None and reason == "no_command_identity"


@pytest.mark.parametrize(
    "reason_code",
    [
        "secret_read",
        "local_secret_read",
        "credential_exfiltration",
        "prompt_injection",
        "encoded_exfiltration",
        "native_sensitive_prompt",
        "native_sensitive_access_review",
    ],
)
@pytest.mark.parametrize(
    ("tool", "tool_input"), [("Bash", {"command": "cat README.md"}), ("todo", {"ops": []}), ("read", {"path": "a"})]
)
def test_risk_signal_reviews_never_offer_always(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    native_context_digest: Path,
    reason_code: str,
    tool: str,
    tool_input: dict[str, object],
) -> None:
    workspace = _workspace(tmp_path, monkeypatch)
    token, reason = _decide(tool, tool_input, workspace, reason_code=reason_code)
    assert token is None and reason == "non_overridable"


def test_first_seen_review_of_a_benign_command_keeps_its_offer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path
) -> None:
    workspace = _workspace(tmp_path, monkeypatch)
    (workspace / "README.md").write_text("x")
    for command in ("rg -n foo src", "cat README.md", "ls -la"):
        token, reason = _decide("Bash", {"command": command}, workspace)
        assert token is not None and reason is None, command
