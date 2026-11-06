#!/usr/bin/env python3
"""Record `copilot_hook_config` replay vectors from the ORIGINAL Python helpers.

Run against a checkout that still plans Copilot hook entries in Python (the
base of the commit that introduced the native `copilot_hook_config`
runner-authority kind), never from Rust output:

    cd <base-worktree>
    PYTHONPATH=$PWD/src python3 <this-file> <output copilot_hook_config_vectors.json>

Each case pins one `plan` request and, per job, Guard's shell spellings and the
hooks object `_merge_hook_entries` and `_remove_hook_entries` left behind
(`_managed_hook_payload` first for the workspace file). The native
`copilot-hook-commands` answer the old helpers asked for is stubbed from a
fixed table of commands whose ownership the Rust predicate's own tests pin;
any other command fails the recording.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from codex_plugin_scanner.guard.adapters import copilot, cursor_hook_config
from codex_plugin_scanner.guard.adapters.bounded_cli_hook_bridge import bounded_hook_script_path
from codex_plugin_scanner.guard.mdm import runtime_request

GUARD_HOME = Path("/nonexistent-guard/home")
INTERPRETER = "/nonexistent-guard/bin/python3"
SCRIPT = str(bounded_hook_script_path(GUARD_HOME, "copilot"))
CONFIG = '{"harness":"copilot","cli_args":["guard","hook","--harness","copilot"]}'
CLAUDE_CONFIG = '{"harness":"claude-code","cli_args":["guard","hook","--harness","claude-code"]}'

LEGACY = "python -m codex_plugin_scanner.cli guard hook --harness copilot"
FROZEN = f"/opt/hol/hol-guard __guard-bounded-hook '{CONFIG}'"
ISOLATED = f"{INTERPRETER} -I {SCRIPT}"
INLINE = f"python3 -I -c 'import bounded_cli_hook_bridge' '{CONFIG}'"
NATIVE = f"/opt/hol/guard-native bounded-hook-bridge /opt/hol/hol-guard __guard-bounded-hook '{CONFIG}'"
# Guard's commands as the Rust predicate reads them: `True` when Guard wrote it.
OWNERSHIP = {
    LEGACY: True,
    LEGACY.upper(): True,
    FROZEN: True,
    ISOLATED: True,
    INLINE: True,
    NATIVE: True,
    "user hook": False,
    "echo guard hook": False,
    "": False,
    "python -m codex_plugin_scanner.cli guard hook --harness claude-code": False,
    f"/opt/hol/hol-guard __guard-bounded-hook '{CLAUDE_CONFIG}'": False,
    f"{INTERPRETER} -I /nonexistent-guard/other/copilot.py": False,
    "ünïcode hook ✓": False,
    "pwsh -File C:\\Users\\me\\hook.ps1": False,
}

POSIX_PARTS = [INTERPRETER, "-I", SCRIPT]
QUOTED_PARTS = [
    "C:\\Program Files\\Python\\python.exe",
    "-c",
    'print("a b")',
    "",
    "tail\\",
    "spaced tail\\\\",
    'x\\"y',
    "it's",
    "tab\there",
    "plain-._/:=,+@%",
    "ünïcode",
]


def _stub_answer(feature: str, command: str, request: dict[str, object], **_: object) -> dict[str, object]:
    assert feature == "native-copilot-hook-commands-v1" and command == "copilot-hook-commands"
    assert request["interpreter"] in {INTERPRETER, None} and request["script"] == SCRIPT
    commands = request["commands"]
    assert isinstance(commands, list)
    return {"managed": [OWNERSHIP[str(item)] for item in commands]}


def _shells(parts: list[str]) -> tuple[str, str]:
    original = copilot._hook_command_parts
    copilot._hook_command_parts = lambda *_args, **_kwargs: tuple(parts)  # type: ignore[assignment]
    try:
        return copilot._hook_shell_commands(object(), include_workspace=False)  # type: ignore[arg-type]
    finally:
        copilot._hook_command_parts = original


def _merged(hooks: dict[str, object], bash: str, powershell: str) -> dict[str, object]:
    hooks = dict(hooks)
    managed = copilot._managed_hook_commands(copilot._hooks_commands(hooks), guard_home=GUARD_HOME)
    entry: dict[str, object] = {"type": "command", "bash": bash, "powershell": powershell, "guard": True}
    for event in copilot._MANAGED_HOOK_EVENTS:
        hooks[event] = copilot._merge_hook_entries(hooks.get(event), entry, managed=managed)
    return hooks


def _pruned(hooks: dict[str, object], bash: str, powershell: str) -> dict[str, object]:
    hooks = dict(hooks)
    managed = copilot._managed_hook_commands(copilot._hooks_commands(hooks), guard_home=GUARD_HOME)
    for event in copilot._MANAGED_HOOK_EVENTS:
        kept = copilot._remove_hook_entries(hooks.get(event), bash, powershell, managed=managed)
        if kept:
            hooks[event] = kept
        else:
            hooks.pop(event, None)
    return hooks


def _config_job(hooks: dict[str, object], parts: list[str]) -> tuple[dict[str, object], dict[str, object]]:
    bash, powershell = _shells(parts)
    normalized = copilot._inline_hooks_payload({"hooks": hooks})
    expect = {
        "bash": bash,
        "powershell": powershell,
        "install": _merged(normalized, bash, powershell),
        "uninstall": _pruned(normalized, bash, powershell),
    }
    return {"parts": parts, "hooks": hooks}, expect


def _workspace_job(payload: dict[str, object], parts: list[str]) -> tuple[dict[str, object], dict[str, object]]:
    bash, powershell = _shells(parts)
    normalized = copilot._managed_hook_payload(payload)
    hooks = normalized["hooks"]
    expect = {
        "bash": bash,
        "powershell": powershell,
        "payload": normalized,
        "install": _merged(hooks, bash, powershell),
        "uninstall": _pruned(hooks, bash, powershell),
    }
    return {"parts": parts, "payload": payload, "keys": list(payload)}, expect


def _user(command: str, **extra: object) -> dict[str, object]:
    return {"type": "command", "bash": command, "timeoutSec": 5, **extra}


def _current(parts: list[str]) -> dict[str, object]:
    bash, powershell = _shells(parts)
    return {"type": "command", "bash": bash, "powershell": powershell, "cwd": "/old", "env": {"Z": "1", "A": "2"}}


def _config_hooks() -> list[tuple[str, dict[str, object], list[str]]]:
    current = _current(POSIX_PARTS)
    quoted_bash, quoted_powershell = _shells(QUOTED_PARTS)
    return [
        ("config-empty", {}, POSIX_PARTS),
        ("config-user-only", {"preToolUse": [_user("user hook", z=1, a=2)]}, POSIX_PARTS),
        (
            "config-every-guard-shape",
            {
                "userPromptSubmitted": [{"command": LEGACY}, _user("user hook")],
                "preToolUse": [{"bash": FROZEN, "powershell": "user hook"}, {"powershell": ISOLATED}],
                "postToolUse": [{"command": INLINE}, {"command": NATIVE}, {"command": LEGACY.upper()}],
                "permissionRequest": [current, current],
                "permissionRequestV2": [_user("ünïcode hook ✓")],
            },
            POSIX_PARTS,
        ),
        (
            "config-near-misses-stay",
            {
                "preToolUse": [
                    {"command": "python -m codex_plugin_scanner.cli guard hook --harness claude-code"},
                    {"bash": f"/opt/hol/hol-guard __guard-bounded-hook '{CLAUDE_CONFIG}'"},
                    {"bash": f"{INTERPRETER} -I /nonexistent-guard/other/copilot.py"},
                    {"command": "echo guard hook"},
                    {"command": ""},
                ],
            },
            POSIX_PARTS,
        ),
        (
            "config-shell-pair-and-single-shell",
            {
                "preToolUse": [
                    {"bash": quoted_bash, "powershell": quoted_powershell, "x": 1},
                    {"bash": "user hook", "powershell": quoted_powershell},
                    {"command": quoted_bash},
                    {"bash": quoted_powershell, "powershell": "pwsh -File C:\\Users\\me\\hook.ps1"},
                    _user("user hook"),
                ],
            },
            QUOTED_PARTS,
        ),
        (
            "config-odd-values",
            {
                "preToolUse": ["user hook", 7, None, [LEGACY], {"command": 3, "bash": None}, {"command": LEGACY}],
                "postToolUse": "not a list",
                "permissionRequest": {"command": LEGACY},
                "sessionStart": [{"command": LEGACY}],
                "agentStop": "kept as is",
            },
            POSIX_PARTS,
        ),
        (
            "config-duplicate-user-entries",
            {
                "preToolUse": [_user("user hook"), _user("user hook"), {"command": LEGACY}, _user("user hook")],
                "permissionRequestV2": [],
            },
            ["hol-guard", "guard", "hook", "--harness", "copilot"],
        ),
    ]


def _workspace_payloads() -> list[tuple[str, dict[str, object]]]:
    return [
        ("workspace-empty", {}),
        ("workspace-nested", {"version": 1, "hooks": {"preToolUse": [{"command": LEGACY}, _user("user hook")]}}),
        (
            "workspace-nested-odd",
            {
                "z": 1,
                "hooks": {
                    "sessionStart": [{"command": LEGACY}],
                    "postToolUse": "not a list",
                    "preToolUse": [{"bash": ISOLATED}, "user hook", _user("ünïcode hook ✓")],
                },
                "version": 2,
            },
        ),
        (
            "workspace-top-level-lists",
            {
                "sessionStart": [_user("user hook")],
                "version": 3,
                "preToolUse": [{"command": LEGACY}],
                "agentStop": [{"command": FROZEN}],
                "notes": "not a list",
                "empty": [],
            },
        ),
        ("workspace-hooks-list", {"hooks": [{"command": LEGACY}], "zeta": [1], "alpha": [2], "version": [1]}),
        ("workspace-version-float", {"version": 1.5, "hooks": {}}),
        ("workspace-version-string", {"version": "3", "hooks": {"preToolUse": []}}),
        ("workspace-version-bool", {"version": True, "hooks": {"permissionRequestV2": [{"command": NATIVE}]}}),
        ("workspace-version-big", {"version": 12345678901234567890, "hooks": {}}),
        ("workspace-version-negative", {"version": -4, "hooks": {"preToolUse": [{"powershell": INLINE}]}}),
        ("workspace-version-null", {"version": None}),
    ]


def main(output: Path) -> None:
    runtime_request.runtime_answer = _stub_answer  # type: ignore[assignment]
    cursor_hook_config.isolated_cursor_hook_python = lambda: INTERPRETER  # type: ignore[assignment]
    workspace_parts = [*POSIX_PARTS, "--workspace", "/work space"]
    OWNERSHIP.update(dict.fromkeys(_shells(QUOTED_PARTS), False))
    cases: list[dict[str, object]] = []
    payloads = _workspace_payloads()
    for index, (name, hooks, parts) in enumerate(_config_hooks()):
        config_request, config_expect = _config_job(hooks, parts)
        jobs, expect = [config_request], [config_expect]
        if index < len(payloads):
            name = f"{name}+{payloads[index][0]}"
            workspace_request, workspace_expect = _workspace_job(payloads[index][1], workspace_parts)
            jobs.append(workspace_request)
            expect.append(workspace_expect)
        request = {"op": "plan", "interpreter": INTERPRETER, "script": SCRIPT, "jobs": jobs}
        cases.append({"name": name, "request": request, "expect": expect})
    for name, payload in payloads[len(cases) :]:
        config_request, config_expect = _config_job({}, POSIX_PARTS)
        workspace_request, workspace_expect = _workspace_job(payload, QUOTED_PARTS)
        request = {
            "op": "plan",
            "interpreter": INTERPRETER,
            "script": SCRIPT,
            "jobs": [config_request, workspace_request],
        }
        cases.append({"name": name, "request": request, "expect": [config_expect, workspace_expect]})
    # Without an isolated interpreter no `python -I` command is Guard's.
    cursor_hook_config.isolated_cursor_hook_python = lambda: None  # type: ignore[assignment]
    OWNERSHIP[ISOLATED] = False
    config_request, config_expect = _config_job({"preToolUse": [{"bash": ISOLATED}, {"command": LEGACY}]}, ["guard"])
    request = {"op": "plan", "interpreter": None, "script": SCRIPT, "jobs": [config_request]}
    cases.append({"name": "no-isolated-bridge", "request": request, "expect": [config_expect]})
    document = {"schema": "guard-copilot-hook-config-vectors.v1", "cases": cases}
    output.write_text(json.dumps(document, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
