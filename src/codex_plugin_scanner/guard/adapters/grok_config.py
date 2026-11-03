"""Grok Build CLI config and hook JSON helpers for HOL Guard."""

from __future__ import annotations

from pathlib import Path

GROK_PRETOOL_HOOK_TIMEOUT_SECONDS = 90
GROK_HOOK_INTERNAL_TIMEOUT_SECONDS = 85
GROK_APPROVAL_WAIT_MAX_SECONDS = 80

GROK_DIR = ".grok"
GROK_CONFIG_FILE = "config.toml"
GROK_MANAGED_CONFIG_FILE = "managed_config.toml"
GROK_HOOKS_DIR = "hooks"
GUARD_MANAGED_BEGIN = "# BEGIN HOL GUARD MANAGED GROK"
GUARD_HOOK_PRETOOL_FILE = "hol-guard-pretooluse.json"
GUARD_HOOK_PROMPT_FILE = "hol-guard-prompt.json"
# Kept empty: a per-tool matcher list double-fired after Grok aliased Bash→run_terminal_command.
MANAGED_DENY_RULES = (
    "Bash(hol-guard apps disconnect grok*)",
    "Bash(hol-guard apps uninstall*)",
    "Bash(rm -rf **/.grok/hooks/hol-guard*)",
    "Edit(**/.grok/hooks/hol-guard*)",
    "Edit(**/.grok/managed_config.toml)",
    "Edit(**/.grok/config.toml)",
    "Read(**/.grok/auth/**)",
    "Read(**/.grok/auth.json)",
    "Read(**/.env)",
    "Read(**/.npmrc)",
    "Read(**/.ssh/**)",
    "Read(**/.hol-guard/secrets/**)",
    "Read(**/.hol-guard/totp-secrets/**)",
    "Read(**/.hol-guard/daemon-auth-token)",
)
OBSERVE_HOOK_EVENTS = ("UserPromptSubmit", "SubagentStart", "SessionStart")
SYSTEM_MANAGED_CONFIG = Path("/etc/grok/managed_config.toml")
SYSTEM_REQUIREMENTS = Path("/etc/grok/requirements.toml")


def _command_hook_entry(hook_command: str, *, timeout: int) -> dict[str, object]:
    return {
        "hooks": [
            {
                "type": "command",
                "command": hook_command,
                "timeout": timeout,
            }
        ]
    }


def build_pretool_hook_json(hook_command: str) -> dict[str, object]:
    """Install one catch-all PreToolUse handler.

    Grok matchers are regexes against the native tool name and also expand
    aliases, so listing both ``Bash`` and ``run_terminal_command`` ran Guard
    twice. An omitted matcher covers current and future tools, including
    ``spawn_subagent``, ``list_dir``, and ``server__tool`` MCP names.
    """

    return {"hooks": {"PreToolUse": [_command_hook_entry(hook_command, timeout=GROK_PRETOOL_HOOK_TIMEOUT_SECONDS)]}}


def build_observe_hook_json(hook_command: str) -> dict[str, object]:
    """Install the prompt gate alongside passive session and subagent hooks."""

    return {
        "hooks": {event_name: [_command_hook_entry(hook_command, timeout=15)] for event_name in OBSERVE_HOOK_EVENTS}
    }


FOREIGN_HOOK_COMPAT_VENDORS = ("claude", "cursor")
