"""Shared harness configurations and file payload helpers for CLI tests."""

from __future__ import annotations

import json
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]


FIXTURES = Path(__file__).parent / "fixtures"


def _command_handler_argv(handler: dict[str, object]) -> tuple[str, ...]:
    command = handler.get("command")
    args = handler.get("args")
    assert isinstance(command, str)
    assert isinstance(args, list)
    assert all(isinstance(arg, str) for arg in args)
    return (command, *args)


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _read_codex_config(path: Path) -> dict[str, object]:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def _read_codex_hooks(config_path: Path) -> dict[str, object]:
    hooks = _read_codex_config(config_path).get("hooks")
    assert isinstance(hooks, dict)
    return hooks


def _write_codex_pre_tool_payload(path: Path, workspace_dir: Path, command: str) -> None:
    _write_text(
        path,
        json.dumps(
            {
                "session_id": "session-1",
                "turn_id": "turn-1",
                "cwd": str(workspace_dir),
                "hook_event_name": "PreToolUse",
                "model": "gpt-5.4",
                "permission_mode": "bypassPermissions",
                "tool_name": "Bash",
                "tool_input": {"command": command},
                "tool_use_id": "call-1",
            }
        ),
    )


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

    _write_json(
        home_dir / ".claude" / "settings.json",
        {
            "allowedMcpServers": ["global-tools"],
            "hooks": {"PreToolUse": [{"command": "python guard-pre.py"}]},
        },
    )
    _write_json(
        workspace_dir / ".mcp.json",
        {
            "mcpServers": {
                "workspace-tools": {"command": "python", "args": ["-m", "http.server", "9100"]},
            }
        },
    )
    _write_text(workspace_dir / ".claude" / "agents" / "reviewer.md", "# reviewer\n")

    _write_json(
        home_dir / ".cursor" / "mcp.json",
        {
            "mcpServers": {
                "cursor-browser": {"command": "npx", "args": ["@browser/mcp"]},
            }
        },
    )

    _write_json(
        home_dir / "Library" / "Application Support" / "Antigravity" / "User" / "settings.json",
        {
            "workbench.colorTheme": "Default Dark+",
        },
    )
    antigravity_extension_root = home_dir / ".antigravity" / "extensions" / "hashgraph.antigravity-tools-1.0.0"
    _write_json(
        home_dir / ".antigravity" / "extensions" / "extensions.json",
        [
            {
                "identifier": {"id": "hashgraph.antigravity-tools"},
                "location": {"path": str(antigravity_extension_root)},
                "metadata": {"publisherDisplayName": "Hashgraph"},
            }
        ],
    )
    _write_json(
        antigravity_extension_root / "package.json",
        {
            "name": "antigravity-tools",
            "publisher": "hashgraph",
            "displayName": "Antigravity Tools",
        },
    )
    _write_json(
        home_dir / ".gemini" / "antigravity" / "mcp_config.json",
        {
            "mcpServers": {
                "gravity-tools": {"command": "node", "args": ["gravity.js"]},
            }
        },
    )
    _write_text(
        home_dir / ".gemini" / "antigravity" / "skills" / "gravity-review" / "SKILL.md",
        "---\nname: gravity-review\ndescription: Gravity skill\n---\n",
    )

    _write_json(
        home_dir / ".gemini" / "settings.json",
        {
            "mcpServers": {
                "gemini-tools": {"command": "node", "args": ["gemini.js"]},
            },
            "hooks": {
                "PreToolUse": [
                    {
                        "hooks": [{"type": "command", "command": "python global-gemini-hook.py"}],
                    }
                ]
            },
        },
    )
    _write_text(
        home_dir / ".gemini" / "skills" / "gemini-review" / "SKILL.md",
        "---\nname: gemini-review\ndescription: Gemini skill\n---\n",
    )
    _write_json(
        home_dir / ".gemini" / "extensions" / "hashnet" / "gemini-extension.json",
        {
            "name": "hashnet",
            "version": "1.0.0",
            "description": "Hashnet extension",
            "mcpServers": {"hashnet": {"command": "node", "args": ["server.js"]}},
            "contextFileName": "GEMINI.md",
        },
    )
    _write_text(home_dir / ".gemini" / "extensions" / "hashnet" / "GEMINI.md", "context\n")
    _write_json(
        workspace_dir / ".gemini" / "settings.json",
        {
            "mcpServers": {
                "workspace-gemini": {"command": "node", "args": ["workspace-gemini.js"]},
            },
            "hooks": {
                "PreToolUse": [
                    {
                        "hooks": [{"type": "command", "command": "python workspace-gemini-hook.py"}],
                    }
                ]
            },
        },
    )
    _write_text(
        workspace_dir / ".gemini" / "skills" / "workspace-review" / "SKILL.md",
        "---\nname: workspace-review\ndescription: Workspace Gemini skill\n---\n",
    )

    _write_json(
        home_dir / ".config" / "opencode" / "opencode.json",
        {
            "mcp": {
                "playwright": {
                    "type": "local",
                    "command": ["pnpm", "dlx", "@playwright/mcp@latest"],
                    "enabled": True,
                }
            }
        },
    )
    _write_json(
        workspace_dir / "opencode.json",
        {
            "name": "workspace-opencode",
            "mcp": {"workspace": {"type": "local", "command": ["node", "server.js"]}},
        },
    )
    _write_text(workspace_dir / ".opencode" / "commands" / "triage.md", "# triage\n")


def _build_stable_guard_fixture(home_dir: Path, workspace_dir: Path) -> None:
    """Build the broad fixture with deterministic, non-network Codex servers."""

    _build_guard_fixture(home_dir, workspace_dir)
    global_server = home_dir / "guard-test-servers" / "global_tools.py"
    workspace_server = workspace_dir / "guard-test-servers" / "workspace_skill.py"
    _write_text(global_server, "raise SystemExit(0)\n")
    _write_text(workspace_server, "raise SystemExit(0)\n")
    _write_text(
        home_dir / ".codex" / "config.toml",
        (
            'approval_policy = "never"\n\n'
            "[mcp_servers.global_tools]\n"
            f"command = {json.dumps(sys.executable)}\n"
            f"args = [{json.dumps(str(global_server))}]\n"
        ),
    )
    _write_text(
        workspace_dir / ".codex" / "config.toml",
        (
            "[mcp_servers.workspace_skill]\n"
            f"command = {json.dumps(sys.executable)}\n"
            f"args = [{json.dumps(str(workspace_server))}]\n"
        ),
    )
