"""Settings shapes the Muse and Devin hook settings recorder installs into and uninstalls from."""

from __future__ import annotations

DEVIN_TOOLS = (
    "^(exec|read|write|edit|apply_patch|notebook_read|notebook_edit|grep|glob|webfetch|mcp_call_tool|mcp__.*)$"
)
PARTS = {
    harness: ("/opt/guard/python", "-I", f"/var/guard-user/.hol-guard/managed/bounded-hooks/{harness}.py")
    for harness in ("muse", "devin")
}


def earlier_guard_commands(harness: str) -> list[str]:
    """Guard commands an earlier install wrote, in every shape the predicate recognizes."""

    marker = f"HOL_GUARD_MANAGED_{harness.upper()}"
    return [
        f"old-guard # {marker}",
        f"python3 -c \"from codex_plugin_scanner.cli import main; main(['guard', 'hook', '--harness', '{harness}'])\"",
        f'/usr/bin/python3 -m bounded_cli_hook_bridge \'{{"harness":"{harness}","timeout_seconds":25}}\'',
        f'/opt/guard/python __guard-bounded-hook {{"harness":"{harness}"}}',
        f'"C:\\Python\\python.exe" __guard-bounded-hook "{{\\"harness\\":\\"{harness}\\"}}"',
        f"/opt/python -I /var/guard-user/.hol-guard/managed/bounded-hooks/{harness}.py",
        f"C:\\Python\\python.exe -I C:\\Users\\guard-user\\.hol-guard\\managed\\bounded-hooks\\{harness}.py",
    ]


def other_commands(harness: str) -> list[object]:
    """Commands and values near the predicate's shapes, owned by another harness or by no one."""

    other = "devin" if harness == "muse" else "muse"
    return [
        *earlier_guard_commands(other)[2:],
        f"HOL_GUARD_MANAGED_{harness.upper()}_X".lower(),
        f"codex_plugin_scanner.cli 'guard', 'hook' --harness {harness}",
        f"python3 -c \"main(['guard', 'scan', '--harness', '{harness}'])\" codex_plugin_scanner.cli",
        f'__guard-bounded-hook {{"harness": "{harness}"}}',
        f'bounded_cli_hook_bridge {{"harness":"{harness.upper()}"}}',
        f"/opt/python -I /var/guard-user/managed/bounded-hooks/{harness}.pyc.bak/../x",
        f"/opt/python -I /var/guard-user/managed/bounded_hooks/{harness}.py",
        "echo user-pretool",
        "/usr/local/bin/größe ☃ --雪",
        "",
        None,
        42,
        True,
        ["old-guard", f"HOL_GUARD_MANAGED_{harness.upper()}"],
        {"command": f"HOL_GUARD_MANAGED_{harness.upper()}"},
    ]


USER = {"type": "command", "command": "echo user-pretool", "timeout": 10}
USER_UNICODE = {"type": "command", "command": "/usr/local/bin/größe ☃ --雪", "timeout": 3, "statusMessage": "检查"}
USER_WINDOWS = {"type": "command", "command": r"C:\Users\guard-user\tools\audit.exe --log=C:\Users\gü\a.log"}


def guard(harness: str, index: int = 0) -> dict[str, object]:
    return {"type": "command", "command": earlier_guard_commands(harness)[index], "timeout": 30}


def install_shapes(harness: str) -> dict[str, object]:
    """Named `hooks` values (or a missing key) for one harness; `...` leaves the key out."""

    tools = DEVIN_TOOLS if harness == "devin" else ".*"
    stale = [guard(harness, index) for index in range(len(earlier_guard_commands(harness)))]
    return {
        "missing": ...,
        "null": None,
        "empty": {},
        "list": [],
        "text": "hooks",
        "number": 3,
        "event-text": {"PreToolUse": "x"},
        "event-object": {"Notification": [], "Custom": {"hooks": []}, "PreToolUse": None},
        "event-null": {"PreToolUse": None, "Stop": None},
        "event-number-after-list": {"PreToolUse": [{"hooks": [USER]}], "Weird": 5},
        "user-no-matcher": {"PreToolUse": [{"hooks": [USER]}]},
        "user-star-matcher": {"PreToolUse": [{"matcher": ".*", "hooks": [USER]}]},
        "user-tools-matcher": {"PreToolUse": [{"matcher": f"  {tools}\t", "hooks": [USER]}]},
        "user-blank-matcher": {"PostToolUse": [{"matcher": "   ", "hooks": [USER_UNICODE], "extra": "é"}]},
        "user-number-matcher": {"UserPromptSubmit": [{"matcher": 5, "hooks": [USER]}]},
        "user-null-matcher": {"PermissionRequest": [{"matcher": None, "hooks": [USER_WINDOWS]}]},
        "only-stale": {"PreToolUse": [{"hooks": [stale[0]]}], "Stop": [{"hooks": stale[1:3]}]},
        "every-stale-shape": {"PreToolUse": [{"matcher": tools, "hooks": [USER, *stale]}]},
        "stale-mid-order": {
            "SessionEnd": [{"hooks": [USER]}],
            "PreToolUse": [{"hooks": [stale[3]]}],
            "Notification": [{"hooks": [stale[4]]}],
            "PostToolUse": [{"hooks": [USER, stale[5]]}],
        },
        "entry-command-stale": {"PreToolUse": [{"type": "command", "command": stale[6]}, {"hooks": [USER]}]},
        "entry-command-with-hooks": {"PreToolUse": [{"command": stale[0], "hooks": [USER]}]},
        "entry-command-user": {"PreToolUse": [{"type": "command", "command": "echo flat"}]},
        "non-object-entries": {"PreToolUse": ["text", 5, None, [USER], {"hooks": [USER]}]},
        "hooks-text": {"PreToolUse": [{"hooks": "x"}, {"matcher": "Bash", "hooks": [USER]}]},
        "hooks-missing": {"PreToolUse": [{"matcher": tools}], "Stop": [{"note": "é"}]},
        "hooks-empty": {"PreToolUse": [{"hooks": []}], "Stop": [{"matcher": "x", "hooks": []}]},
        "non-object-handlers": {"PreToolUse": [{"hooks": ["text", None, 7, USER, stale[1]]}]},
        "handler-command-number": {"PreToolUse": [{"hooks": [{"type": "command", "command": 9}, stale[2]]}]},
        "two-unmatched-groups": {"PreToolUse": [{"matcher": "Bash", "hooks": [USER]}, {"hooks": [USER_UNICODE]}]},
        "second-group-matches": {
            "PreToolUse": [{"matcher": "Bash", "hooks": [USER]}, {"matcher": tools, "hooks": [stale[0], USER]}]
        },
        "other-harness-guard": {
            "PreToolUse": [{"hooks": [guard("devin" if harness == "muse" else "muse", 3)]}],
        },
        "non-ascii-events": {"Événement": [{"hooks": [USER_UNICODE]}], "雪": [{"hooks": [stale[0]]}]},
        "every-event": {
            event: [{"hooks": [USER]}]
            for event in ("Stop", "SessionStart", "PostToolUse", "UserPromptSubmit", "PermissionRequest", "PreToolUse")
        },
    }


INSTALL_WAITS = (120, 0, -5, 600, 601, 10**6, 37)
REINSTALLS = ("missing", "user-no-matcher", "user-tools-matcher", "every-stale-shape", "non-object-entries")
UNINSTALL_SHAPES = (
    "empty",
    "event-text",
    "event-object",
    "event-null",
    "user-no-matcher",
    "only-stale",
    "every-stale-shape",
    "stale-mid-order",
    "entry-command-stale",
    "entry-command-with-hooks",
    "non-object-entries",
    "hooks-text",
    "hooks-empty",
    "non-object-handlers",
    "handler-command-number",
    "other-harness-guard",
    "non-ascii-events",
)
OTHER_KEYS = {"model": "größe", "mcpServers": {"x": {"command": "npx"}}}
