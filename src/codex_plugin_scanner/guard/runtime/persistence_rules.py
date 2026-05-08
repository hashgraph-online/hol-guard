"""Persistence mechanism detection rules for Guard runtime shell actions."""

from __future__ import annotations

import re
from dataclasses import dataclass

_SHELL_PROFILE_FILES = re.compile(
    r"(?<![A-Za-z0-9_.-])"
    r"(?:\.bashrc|\.bash_profile|\.bash_login|\.profile|\.zshrc|\.zprofile|\.zlogin|"
    r"\.zshenv|\.kshrc|\.cshrc|\.tcshrc|/etc/profile(?:\.d/[^'\"]+)?|"
    r"/etc/bash\.bashrc|/etc/environment|"
    r"\.config/fish/config\.fish|\.config/fish/functions/[^'\"]+)"
    r"(?![A-Za-z0-9_.-])",
    re.IGNORECASE,
)

_GIT_HOOK_PATHS = re.compile(
    r"(?<![A-Za-z0-9_.-])"
    r"\.git/hooks/(?:pre-commit|post-commit|pre-push|post-merge|post-checkout|"
    r"pre-receive|post-receive|update|commit-msg|prepare-commit-msg)"
    r"(?![A-Za-z0-9_.-])",
    re.IGNORECASE,
)

_CRON_WRITE_PATTERN = re.compile(
    r"(?:^|[\s;&|])"
    r"(?:crontab\s+-[lr]*[^-]*|"
    r"(?:echo|printf|cat|tee)\b[^\r\n;&|]{0,200}(?:>|\|\s*tee)\s*/(?:var/spool/cron|etc/cron[^'\"]*?))",
    re.IGNORECASE,
)

_LAUNCH_AGENT_PATHS = re.compile(
    r"(?<![A-Za-z0-9_.-])"
    r"(?:~/Library/LaunchAgents/|/Library/LaunchAgents/|/Library/LaunchDaemons/|"
    r"/System/Library/LaunchAgents/|/System/Library/LaunchDaemons/)"
    r"[^'\"\\s]{3,}\.plist"
    r"(?![A-Za-z0-9_.-])",
    re.IGNORECASE,
)

_SYSTEMD_WRITE_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_.-])"
    r"(?:/etc/systemd/system/|/usr/lib/systemd/system/|/run/systemd/system/|"
    r"~?/\.config/systemd/user/)"
    r"[^'\"\\s]{3,}\.(?:service|timer|socket|path|mount|target)"
    r"(?![A-Za-z0-9_.-])",
    re.IGNORECASE,
)

_VSCODE_TASKS_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_.-])"
    r"\.vscode/(?:tasks|launch|settings)\.json"
    r"(?![A-Za-z0-9_.-])",
    re.IGNORECASE,
)

_REGISTRY_WRITE_PATTERN = re.compile(
    r"(?:^|[\s;&|])(?:reg\s+(?:add|import|copy)|regini)\b",
    re.IGNORECASE,
)

_AT_JOB_PATTERN = re.compile(
    r"(?:^|[\s;&|])at\b[^\r\n;&|]{0,200}",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class PersistenceMatch:
    """Describes a detected persistence mechanism."""

    mechanism: str
    plain_reason: str
    false_positive_hint: str


def detect_persistence_mechanisms(command: str) -> tuple[PersistenceMatch, ...]:
    """Return persistence mechanism matches found in *command*."""
    matches: list[PersistenceMatch] = []

    if _SHELL_PROFILE_WRITE.search(command):
        matches.append(
            PersistenceMatch(
                mechanism="shell_profile_write",
                plain_reason=(
                    "Command writes to a shell profile or startup file, which runs on every new terminal session."
                ),
                false_positive_hint="Allow if this is setting up a legitimate development environment or PATH entry.",
            )
        )

    if _GIT_HOOK_PATHS.search(command) and _is_write_operation(command):
        matches.append(
            PersistenceMatch(
                mechanism="git_hook_write",
                plain_reason="Command installs or modifies a git hook, which runs automatically on git events.",
                false_positive_hint="Allow if this is installing a project-standard code quality or signing hook.",
            )
        )

    if _CRON_WRITE_PATTERN.search(command):
        matches.append(
            PersistenceMatch(
                mechanism="cron_write",
                plain_reason=(
                    "Command modifies scheduled tasks (cron), allowing code to run automatically at set times."
                ),
                false_positive_hint="Allow if this is setting up a legitimate periodic maintenance task.",
            )
        )

    if _LAUNCH_AGENT_PATHS.search(command) and _is_write_operation(command):
        matches.append(
            PersistenceMatch(
                mechanism="launch_agent_write",
                plain_reason=(
                    "Command installs a macOS Launch Agent or Daemon, which runs automatically on login or boot."
                ),
                false_positive_hint="Allow if this is installing a known legitimate background service.",
            )
        )

    if _SYSTEMD_WRITE_PATTERN.search(command) and _is_write_operation(command):
        matches.append(
            PersistenceMatch(
                mechanism="systemd_unit_write",
                plain_reason="Command installs a systemd service unit, which can run automatically at boot or login.",
                false_positive_hint="Allow if this is installing a known legitimate system service.",
            )
        )

    if _VSCODE_TASKS_PATTERN.search(command) and _is_write_operation(command):
        matches.append(
            PersistenceMatch(
                mechanism="vscode_tasks_write",
                plain_reason=(
                    "Command modifies VS Code tasks or launch configuration, which run automatically in the IDE."
                ),
                false_positive_hint="Allow if this is setting up legitimate project build or debug tasks.",
            )
        )

    if _REGISTRY_WRITE_PATTERN.search(command):
        matches.append(
            PersistenceMatch(
                mechanism="registry_write",
                plain_reason=(
                    "Command writes to the Windows Registry, which can configure autostart or persistent settings."
                ),
                false_positive_hint="Allow if this is a known legitimate software installer or configuration step.",
            )
        )

    return tuple(matches)


_SHELL_PROFILE_WRITE = re.compile(
    r"(?:^|[\s;&|])"
    r"(?:echo|printf|cat|tee|append|heredoc)\b[^\r\n;&|]{0,300}"
    r"(?:>>|>\s*>?|\|\s*(?:tee\s+(?:-a\s+)?)?)\s*"
    r"~?/?(?:"
    r"\.bashrc|\.bash_profile|\.bash_login|\.profile|\.zshrc|\.zprofile|\.zlogin|"
    r"\.zshenv|\.kshrc|\.config/fish/config\.fish"
    r")",
    re.IGNORECASE,
)


def _is_write_operation(command: str) -> bool:
    """Return True if the command contains a write indicator (output redirect, tee, cp, mv, install)."""
    return bool(
        re.search(
            r"(?:>>?|tee\b|\bcp\b|\bmv\b|\binstall\b|\bwrite\b|\bcat\s*>)",
            command,
            re.IGNORECASE,
        )
    )
