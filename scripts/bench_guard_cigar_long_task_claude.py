"""Claude Code arms for the long-task token benchmark.

An arm runs `claude -p` once per step, the first step with a fixed session id
and every later one resumed into it, so the six prompts share one chat as in
the Codex arms. The user's login is used as is (Claude Code keeps it in the
login keychain, which a different HOME cannot reach); everything else the
user has configured stays out: `--setting-sources project` drops user
settings, hooks and plugins, `--strict-mcp-config` drops MCP servers,
`--disable-slash-commands` drops skills, and two environment switches drop
the user's CLAUDE.md and auto-memory. The arm's own settings file is the only
configuration that differs between arms.

Claude Code's sandbox runs the agent's shell commands with writes limited to
the project and refuses writes under ~/.claude, so the bench work directory
for these arms must live outside ~/.claude.
"""

from __future__ import annotations

import collections
import json
from collections.abc import Callable
from pathlib import Path

MODEL = "claude-haiku-4-5-20251001"
HARNESS = "claude-code"
# The control arm: the sandbox on, no permission prompts, no hooks.
BASE_SETTINGS = {
    "sandbox": {"enabled": True, "autoAllowBashIfSandboxed": True, "allowUnsandboxedCommands": False},
    "permissions": {"defaultMode": "bypassPermissions", "deny": ["WebFetch", "WebSearch"]},
}
ISOLATION_ENV = {"CLAUDE_CODE_DISABLE_CLAUDE_MDS": "1", "CLAUDE_CODE_DISABLE_AUTO_MEMORY": "1"}
TOOL_KINDS = {
    "Read": "read",
    "Grep": "search",
    "Glob": "list",
    "LS": "list",
    "Edit": "edit",
    "MultiEdit": "edit",
    "Write": "edit",
    "NotebookEdit": "edit",
}


def settings_path(arm: Path) -> Path:
    return arm / "claude_settings.json"


def arm_init_base(arm: Path) -> Path:
    arm.mkdir(parents=True, exist_ok=True)
    (arm / "harness").write_text(HARNESS + "\n", encoding="utf-8")
    path = settings_path(arm)
    path.write_text(json.dumps(BASE_SETTINGS, indent=2) + "\n", encoding="utf-8")
    return path


def command(arm: Path, prompt: str, session_id: str, resume: bool) -> list[str]:
    return [
        "claude",
        "-p",
        prompt,
        "--model",
        MODEL,
        "--output-format",
        "json",
        "--setting-sources",
        "project",
        "--settings",
        str(settings_path(arm)),
        "--strict-mcp-config",
        "--disable-slash-commands",
        "--permission-mode",
        "bypassPermissions",
        "--resume" if resume else "--session-id",
        session_id,
    ]


def step_result(out: Path) -> dict:
    """The JSON result `claude -p` printed for one step; an error result fails the step."""
    text = out.read_text(encoding="utf-8").strip()
    try:
        result = json.loads(text.splitlines()[-1]) if text else {}
    except json.JSONDecodeError:
        result = {}
    if result.get("type") != "result" or result.get("is_error"):
        reason = result.get("result") or result.get("terminal_reason") or "no result"
        raise RuntimeError(f"claude -p did not finish the step: {str(reason)[:200]}")
    return result


def tool_output(paths: list[Path], kind: Callable[[str], str]) -> dict:
    """Tool-result characters and call counts by shape, from the session transcripts."""
    calls_by_id: dict[str, str] = {}
    chars = collections.Counter()
    calls = collections.Counter()
    for path in paths:
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.startswith("{"):
                continue
            content = (json.loads(line).get("message") or {}).get("content")
            if not isinstance(content, list):
                continue
            for block in content:
                if block.get("type") == "tool_use":
                    name = block.get("name", "")
                    shape = kind(block.get("input", {}).get("command", "")) if name == "Bash" else None
                    calls_by_id[block.get("id")] = shape or TOOL_KINDS.get(name, name.lower() or "other")
                elif block.get("type") == "tool_result":
                    shape = calls_by_id.get(block.get("tool_use_id"), "other")
                    chars[shape] += len(_text(block.get("content")))
                    calls[shape] += 1
    return {"chars": dict(chars), "calls": dict(calls)}


def _text(content: object) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(part.get("text", "") for part in content if isinstance(part, dict))
    return ""
