"""Local fixtures and helpers for test_guard_approvals.py."""

from __future__ import annotations

from pathlib import Path

import pytest

_AGENT_CONTEXT_ENV_MARKERS = (
    "HOL_GUARD_HOOK_ARGV",
    "HOL_GUARD_MANAGED_CURSOR_HOOK",
    "HOL_GUARD_CURSOR_APPROVAL_BINDING",
    "HOL_GUARD_CURSOR_AFTER_SHELL_PROOF",
    "CURSOR_SESSION_ID",
    "CURSOR_TRACE_ID",
    "CURSOR_TRANSCRIPT_PATH",
    "CLAUDECODE",
    "OPENCODE_CONFIG_CONTENT",
    "CODEX_SANDBOX",
)


def _clear_agent_context(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in _AGENT_CONTEXT_ENV_MARKERS:
        monkeypatch.delenv(key, raising=False)


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _guard_json_headers(auth_token: str | None = None) -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if auth_token is not None:
        headers["X-Guard-Token"] = auth_token
    return headers


def _build_guard_fixture(home_dir: Path, workspace_dir: Path) -> None:
    _write_text(
        home_dir / ".codex" / "config.toml",
        """
approval_policy = "never"

[mcp_servers.global_tools]
command = "python"
args = ["-m", "http.server", "9000"]
""".strip()
        + "\n",
    )
    _write_text(
        workspace_dir / ".codex" / "config.toml",
        """
[mcp_servers.workspace_skill]
command = "node"
args = ["workspace-skill.js"]
""".strip()
        + "\n",
    )


@pytest.fixture(autouse=True)
def _disable_real_desktop_notification_setup(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOL_GUARD_DESKTOP_NOTIFICATIONS", "0")
