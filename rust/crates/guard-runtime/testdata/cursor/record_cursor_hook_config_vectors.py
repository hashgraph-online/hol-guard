#!/usr/bin/env python3
"""Record `cursor_hook_config` replay vectors from the ORIGINAL Python helpers.

Run against a checkout that still decides Cursor hook ownership in Python (the
base of the commit that introduced the native `cursor_hook_config`
runner-authority kind), never from Rust output:

    cd <base-worktree>
    PYTHONPATH=$PWD/src python3 <this-file> <output cursor_hook_config_vectors.json>

Each case pins one op's request and the answer the Python helpers gave. Steps
that stay in Python (the live-script path checks and the preToolUse matcher
regex) are recorded as `existing` and `guards`, so the Rust replay can apply
them the way the Python shim does.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from codex_plugin_scanner.guard import codex_hook_command_line
from codex_plugin_scanner.guard.adapters import cursor_hook_config as config
from codex_plugin_scanner.guard.adapters._modules.cursor.cursor_hook_events import (
    CURSOR_FILE_MUTATION_TOOL_MATCHER,
    cursor_entry_guards_file_mutations,
)

SCRIPT = "/var/guard-user/.cursor/hooks/hol-guard-cursor-hook.py"
WIN_SCRIPT = r"C:\Users\guard-user\.cursor\hooks\hol-guard-cursor-hook.py"
NATIVE = "/opt/guard/bin/guard-native"
LONG_PATHS = {
    r"C:\PROGRA~1\HOLGUA~1\guard-native.exe": r"C:\Program Files\HOL Guard\guard-native.exe",
    r"C:\PYTHON~1\python.exe": r"C:\Python 312\python.exe",
    r"C:\Users\GUARD-~1\.cursor\hooks\HOL-GU~1.PY": r"C:\Users\guard user\.cursor\hooks\hol-guard-cursor-hook.py",
    r"C:\Users\GUARD-~1\bin\CURREN~1.EXE": r"C:\Users\guard user\bin\current-hol-guard.exe",
}
POSIX_COMMANDS = [
    f"{NATIVE} cursor-hook-bridge /usr/bin/python3 -I {SCRIPT} --cursor-hook-event beforeShellExecution",
    f"/usr/bin/python3 -I {SCRIPT} --cursor-hook-event preToolUse",
    "'/var/guard user/bin/current-hol-guard' __guard-cursor-hook "
    "'/var/guard user/.cursor/hooks/hol-guard-cursor-hook.py' --cursor-hook-event beforeReadFile",
    f"/var/guard-user/bin/hol-guard __guard-cursor-hook {SCRIPT} --cursor-hook-event beforeMCPExecution",
    f"/var/guard-user/bin/guard __guard-cursor-hook {SCRIPT}",
    "hol-guard __guard-cursor-hook /var/guard-user/.cursor/hooks/other.py",
    SCRIPT,
    "/var/guard-user/managed/cursor/hol-guard-cursor-hook.py --cursor-hook-event stop",
    "/usr/bin/python3 -m codex_plugin_scanner.cli hol-guard-hook-argv --harness cursor",
    "/usr/bin/python3 -m codex_plugin_scanner.cli hol_guard_hook_argv --harness Cursor --json",
    "node /opt/tools/hol-guard-hook-argv.js --harness cursor",
    "python3 -m tool hol-guard-hook-argv --harness claude",
    "node /opt/tools/audit.js --event beforeShellExecution",
    "echo ok",
    "npx some-tool --harness cursor",
    "'/var/unclosed",
    "",
    "   ",
    'python3 -c "print(1)" hol-guard-cursor-hook.py',
    "python3 -X dev -I /var/guard-user/managed/cursor/hol-guard-cursor-hook.py",
    "python3 -I -B",
    "python3",
    "/usr/bin/python3 -I '/var/gúard-üser/.cursor/hooks/HOL-GUARD-CURSOR-HOOK.PY'",
    "/usr/bin/PYTHON3.12 -I /var/guard-user/.cursor/hooks/hol-guard-cursor-hoo\u212a.py",
    "env /usr/bin/python3 -I /var/guard-user/.cursor/hooks/hol-guard-cursor-hook.py",
    "'' cursor-hook-bridge /usr/bin/python3 -I /var/guard-user/.cursor/hooks/hol-guard-cursor-hook.py",
    f"{NATIVE} cursor-hook-bridge",
    f"{NATIVE} cursor-hook-bridge /var/guard-user/bin/current-hol-guard __guard-cursor-hook {SCRIPT}",
    "python3\x1c-I\u00a0/var/guard-user/.cursor/hooks/hol-guard-cursor-hook.py 'unclosed",
    "python3 -I /var/guard-user/./.cursor/hooks/./hol-guard-cursor-hook.py/",
    'python3 -I "/var/guard user/.cursor/hooks/hol-guard-cursor-hook.py" \\',
    'python3 -I "/var/guard \\"user\\"/x/hol-guard-cursor-hook.py"',
    "\tpython3  -I\n/var/guard-user/.cursor/hooks/hol-guard-cursor-hook.py",
]
WINDOWS_COMMANDS = [
    r"C:\PROGRA~1\HOLGUA~1\guard-native.exe cursor-hook-bridge C:\PYTHON~1\python.exe -I "
    + WIN_SCRIPT
    + " --cursor-hook-event beforeShellExecution",
    r"C:\Python312\python.exe -I C:\Users\GUARD-~1\.cursor\hooks\HOL-GU~1.PY --cursor-hook-event preToolUse",
    r"C:\Python312\python.exe -I C:\Users\GUARD-~2\.cursor\hooks\HOL-GU~2.PY",
    r"C:\Users\GUARD-~1\bin\CURREN~1.EXE __guard-cursor-hook " + WIN_SCRIPT,
    r"& 'C:\Program Files\HOL Guard\current-hol-guard.exe' __guard-cursor-hook "
    r"'C:\Users\O''Neil\.cursor\hooks\hol-guard-cursor-hook.py' --cursor-hook-event preToolUse",
    r"  &'C:\Program Files\guard-native.exe' cursor-hook-bridge 'C:\Python 312\python.exe' -I " + WIN_SCRIPT,
    r"& 'C:\x.exe' ;rm",
    r"&'C:\a.exe'x",
    "&",
    r"& 'C:\a.exe' bare-token  ",
    r"'C:\Python 312\python.exe' -I 'C:\Users\guard-user\.cursor\hooks\hol-guard-cursor-hook.py'",
    r"  'C:\Python 312\python.exe' -I C:\Users\guard-user\managed\cursor\hol-guard-cursor-hook.py",
    r'"C:\Program Files\Python\python.exe" -I "C:\Users\guard user\managed\cursor\hol-guard-cursor-hook.py"'
    " --cursor-hook-event afterShellExecution",
    r"C:/Python312/python.exe -I C:/Users/guard-user/.cursor/hooks/hol-guard-cursor-hook.py",
    r"\\server\share\Python\python.exe -I \\server\share\guard\.cursor\hooks\hol-guard-cursor-hook.py",
    r"python.exe -I \\?\UNC\server\share\hol-guard-cursor-hook.py",
    r"python.exe -I \\?\unc\server\share\x\hol-guard-cursor-hook.py",
    r"python.exe -I \\.\C:\x\hol-guard-cursor-hook.py",
    r"python.exe -I \\server",
    r"python.exe -I \\server\share",
    r"python.exe -I //server/share/hol-guard-cursor-hook.py",
    r"C:\Users\guard-user\bin\hol-guard.exe __guard-cursor-hook " + WIN_SCRIPT,
    r"C:\Users\guard-user\bin\current-hol-guard.cmd __guard-cursor-hook " + WIN_SCRIPT,
    r"C:\Users\guard-user\bin\HOL-GUARD.EXE __guard-cursor-hook C:\x\HOL-GUARD-CURSOR-HOOK.PY",
    "python.exe -I C:hol-guard-cursor-hook.py",
    "python.exe -I C:",
    r"python.exe -I \hol-guard-cursor-hook.py",
    r'"C:\Program Files\python.exe -I x',
    r'"" -I C:\x\hol-guard-cursor-hook.py',
    r'C:\a\\\"b c "d\\" e\\\\"f g" h\\',
    r"C:\Python312\python.exe -m codex_plugin_scanner.cli hol-guard-hook-argv --harness cursor",
    r"C:\Windows\py.exe -3 -I " + WIN_SCRIPT,
    r"C:\Users\x~y\python.exe -I C:\~1\hol-guard-cursor-hook.py",
    "pythonw.exe\u3000-I " + WIN_SCRIPT,
]


class _FakeScriptPath:
    def __init__(self, text: str) -> None:
        self._text = text

    def resolve(self) -> _FakeScriptPath:
        return self

    def __str__(self) -> str:
        return self._text


class _RawToken(str):
    existing: frozenset[str] = frozenset()

    def is_file(self) -> bool:
        return str(self) in _RawToken.existing


@contextmanager
def _mode(windows: bool, short_tokens: set[str], existing: frozenset[str] = frozenset()) -> Iterator[None]:
    def long_path(token: str) -> str | None:
        short_tokens.add(token)
        return LONG_PATHS.get(token)

    saved = (
        codex_hook_command_line.hook_commands_use_windows_syntax,
        codex_hook_command_line._long_path,
        config.Path,
        config._accepted_live_cursor_hook_script,
    )
    codex_hook_command_line.hook_commands_use_windows_syntax = lambda value=None: windows if value is None else value
    codex_hook_command_line._long_path = long_path
    config.Path = _RawToken  # type: ignore[misc]
    config._accepted_live_cursor_hook_script = lambda path: path
    _RawToken.existing = existing
    try:
        yield
    finally:
        (
            codex_hook_command_line.hook_commands_use_windows_syntax,
            codex_hook_command_line._long_path,
            config.Path,
            config._accepted_live_cursor_hook_script,
        ) = saved
        _RawToken.existing = frozenset()


def _case(name: str, op: str, windows: bool, request: dict[str, object], expect: dict[str, object], short: set[str]):
    return {
        "name": name,
        "op": op,
        "windows": windows,
        "long_paths": LONG_PATHS if windows else {},
        "request": request,
        "expect": expect,
        "short_tokens": sorted(short),
    }


def _command_cases() -> Iterator[dict[str, object]]:
    commands: list[object] = [*POSIX_COMMANDS, *WINDOWS_COMMANDS]
    for index, command in enumerate(commands):
        for windows in (False, True):
            short: set[str] = set()
            with _mode(windows, short):
                script = config._live_cursor_hook_script_path(command)  # type: ignore[arg-type]
                expect = {
                    "managed": config._is_managed_hook_command(command),
                    "structured": config._is_structured_managed_cursor_hook_command(command),  # type: ignore[arg-type]
                    "script": None if script is None else str(script),
                }
            mode = "windows" if windows else "posix"
            yield _case(f"command-{index}-{mode}", "command", windows, {"command": command}, expect, short)
    for index, command in enumerate([None, 7, ["python3"], {"command": SCRIPT}]):
        expect = {"managed": config._is_managed_hook_command(command), "structured": False, "script": None}
        yield _case(f"command-non-string-{index}", "command", False, {"command": command}, expect, set())


def _entry_cases() -> Iterator[dict[str, object]]:
    guard = f"/usr/bin/python3 -I {SCRIPT} --cursor-hook-event preToolUse"
    mixed: list[object] = [
        {"command": "node /opt/tools/audit.js"},
        {"command": guard, "timeout": 45},
        {"command": "/opt/plain-tool"},
        "hol-guard-cursor-hook.py",
        None,
        ["command", guard],
        {"command": 7},
        {"timeout": 45},
        {"command": "/usr/bin/python3 -m codex_plugin_scanner.cli hol-guard-hook-argv --harness cursor"},
        {"command": "echo ok", "matcher": "Shell"},
    ]
    cases: list[tuple[str, bool, object, str]] = [
        ("mixed-script", False, mixed, SCRIPT),
        ("mixed-command", False, mixed, guard),
        ("exact-plain-command", False, mixed, "/opt/plain-tool"),
        ("exact-plain-windows", True, [{"command": r"C:\tools\plain.exe"}], r"C:\tools\plain.exe"),
        ("not-a-list-string", False, "hol-guard-cursor-hook.py", SCRIPT),
        ("not-a-list-object", False, {"command": guard}, SCRIPT),
        ("not-a-list-null", False, None, SCRIPT),
        ("empty", False, [], SCRIPT),
        (
            "windows-short",
            True,
            [
                {"command": r"C:\Python312\python.exe -I C:\Users\GUARD-~1\.cursor\hooks\HOL-GU~1.PY"},
                {"command": r"C:\tools\GUARD-~1\audit.exe --x"},
            ],
            WIN_SCRIPT,
        ),
    ]
    for name, windows, entries, command in cases:
        short: set[str] = set()
        with _mode(windows, short):
            managed = (
                [config._is_managed_hook_entry(entry, command=command) for entry in entries]
                if isinstance(entries, list)
                else []
            )
            stripped = config._strip_managed_hook_entries(entries, script_path=_FakeScriptPath(command))  # type: ignore[arg-type]
        kept = [entry for entry, flag in zip(entries, managed, strict=True) if not flag] if managed else []
        assert stripped == kept, name
        yield _case(
            f"entries-{name}", "entries", windows, {"entries": entries, "command": command}, {"managed": managed}, short
        )


def _guarded_pre_tool(command: str) -> dict[str, object]:
    return {"command": command, "failClosed": True, "matcher": CURSOR_FILE_MUTATION_TOOL_MATCHER}


def _healthy_hooks(script: str = SCRIPT) -> dict[str, object]:
    def command(event: str) -> str:
        return f"{NATIVE} cursor-hook-bridge /usr/bin/python3 -I {script} --cursor-hook-event {event}"

    return {
        "beforeShellExecution": [{"command": command("beforeShellExecution"), "failClosed": True}],
        "beforeMCPExecution": [{"command": command("beforeMCPExecution"), "failClosed": True}],
        "beforeReadFile": [{"command": command("beforeReadFile"), "failClosed": True}],
        "preToolUse": [_guarded_pre_tool(command("preToolUse"))],
        "afterShellExecution": [{"command": command("afterShellExecution")}],
        "afterMCPExecution": [{"command": command("afterMCPExecution")}],
    }


def _hook_sets() -> list[tuple[str, bool, object, list[str]]]:
    frozen = f"/var/guard-user/bin/current-hol-guard __guard-cursor-hook {SCRIPT} --cursor-hook-event stop"
    managed_other = "/usr/bin/python3 -I /var/guard-user/managed/cursor/hol-guard-cursor-hook.py"
    healthy = _healthy_hooks()
    with_foreign = {
        "stop": [{"command": "node /opt/tools/audit.js"}],
        **{event: [{"command": "echo foreign"}, *entries] for event, entries in healthy.items()},  # type: ignore[misc]
    }
    unguarded = dict(healthy)
    unguarded["preToolUse"] = [{"command": f"/usr/bin/python3 -I {SCRIPT}", "failClosed": False}]
    mixed_pre = dict(healthy)
    mixed_pre["preToolUse"] = [
        {"command": f"/usr/bin/python3 -I {SCRIPT}", "failClosed": False},
        "noise",
        {"command": "   "},
        _guarded_pre_tool(f"/usr/bin/python3 -I {SCRIPT}"),
    ]
    missing_file = dict(healthy)
    missing_file["beforeReadFile"] = [
        {"command": f"/usr/bin/python3 -I {managed_other}"},
        {"command": f"/usr/bin/python3 -I {SCRIPT}"},
    ]
    missing_event = {key: value for key, value in healthy.items() if key != "beforeMCPExecution"}
    not_list = dict(healthy)
    not_list["beforeShellExecution"] = {"command": f"/usr/bin/python3 -I {SCRIPT}"}
    retired = {**healthy, "beforeWriteFile": [{"command": f"/usr/bin/python3 -I {SCRIPT}"}]}
    commands = {
        "stop": [
            {"command": frozen},
            {"command": frozen},
            {"command": f"/usr/bin/python3 -I {SCRIPT}", "enabled": False},
            {"command": f"/usr/bin/python3 -I {SCRIPT}", "enabled": "false"},
            {"command": f"/usr/bin/python3 -I {SCRIPT} --x", "disabled": True},
            {"command": f"/usr/bin/python3 -I {SCRIPT} --y", "disabled": 1},
            {"command": f"/usr/bin/python3 -I {managed_other}"},
            {"command": "node /opt/tools/audit.js"},
            {"command": ["python3"]},
            None,
        ],
        "sessionStart": "not a list",
        "afterFileEdit": [{"command": frozen}, {"command": f"python3 -I {SCRIPT}"}],
        "beforeShellExecution": [{"command": f"/usr/bin/hol-guard __guard-cursor-hook {SCRIPT}"}],
    }
    windows_hooks = {
        event: [
            {
                "command": r"C:\PROGRA~1\HOLGUA~1\guard-native.exe cursor-hook-bridge C:\PYTHON~1\python.exe -I "
                r"C:\Users\GUARD-~1\.cursor\hooks\HOL-GU~1.PY --cursor-hook-event " + event,
                "failClosed": True,
            }
        ]
        for event in healthy
    }
    windows_frozen = {
        "stop": [
            {"command": r"C:\Users\GUARD-~1\bin\CURREN~1.EXE __guard-cursor-hook " + WIN_SCRIPT},
            {"command": r"& 'C:\Program Files\HOL Guard\hol-guard.exe' __guard-cursor-hook '" + WIN_SCRIPT + "'"},
        ]
    }
    long_script = LONG_PATHS[r"C:\Users\GUARD-~1\.cursor\hooks\HOL-GU~1.PY"]
    return [
        ("healthy", False, healthy, [SCRIPT]),
        ("healthy-no-file", False, healthy, []),
        ("foreign", False, with_foreign, [SCRIPT]),
        ("unguarded-pre-tool", False, unguarded, [SCRIPT]),
        ("mixed-pre-tool", False, mixed_pre, [SCRIPT]),
        ("missing-file-fallback", False, missing_file, [SCRIPT]),
        ("missing-file-only", False, missing_file, ["/var/guard-user/managed/cursor/hol-guard-cursor-hook.py"]),
        ("missing-event", False, missing_event, [SCRIPT]),
        ("not-list", False, not_list, [SCRIPT]),
        ("retired-event", False, retired, [SCRIPT]),
        ("commands", False, commands, [SCRIPT]),
        ("commands-no-file", False, commands, []),
        ("windows-short", True, windows_hooks, [long_script]),
        ("windows-short-unmapped-file", True, windows_hooks, [r"C:\Users\GUARD-~1\.cursor\hooks\HOL-GU~1.PY"]),
        ("windows-frozen", True, windows_frozen, [WIN_SCRIPT]),
        ("not-a-dict", False, [healthy], [SCRIPT]),
        ("null", False, None, [SCRIPT]),
        ("empty", False, {}, [SCRIPT]),
    ]


def _pairs(hooks: object) -> list[list[object]] | None:
    return [[str(name), value] for name, value in hooks.items()] if isinstance(hooks, dict) else None


def _hooks_cases() -> Iterator[dict[str, object]]:
    for name, windows, hooks, existing in _hook_sets():
        request = {"hooks": _pairs(hooks)}
        short: set[str] = set()
        with _mode(windows, short, frozenset(existing)):
            commands = list(config.managed_cursor_hook_commands(hooks))
            frozen = config.live_cursor_hooks_use_frozen_control_plane(hooks)
        expect = {"commands": commands, "frozen": frozen}
        extra = {"existing": existing}
        yield {**_case(f"commands-{name}", "commands", windows, request, expect, short), **extra}
        short = set()
        with _mode(windows, short, frozenset(existing)):
            intercept = config.live_guard_cursor_hooks_intercept(hooks)
        pre_tool = hooks.get("preToolUse") if isinstance(hooks, dict) else None
        guards = [
            index
            for index, entry in enumerate(pre_tool if isinstance(pre_tool, list) else [])
            if isinstance(entry, dict) and cursor_entry_guards_file_mutations(entry)
        ]
        extra = {"existing": existing, "guards": guards}
        yield {**_case(f"intercept-{name}", "intercept", windows, request, {"intercept": intercept}, short), **extra}


def _managed_entries(script: str, windows: bool) -> list[list[object]]:
    entries: list[list[object]] = []
    for event in config._MANAGED_HOOK_EVENTS:
        if windows:
            command = r"C:\PYTHON~1\python.exe -I " + script + " --cursor-hook-event " + event
        else:
            command = f"{NATIVE} cursor-hook-bridge /usr/bin/python3 -I {script} --cursor-hook-event {event}"
        entry: dict[str, object] = {"command": command, "timeout": 45, "failClosed": event != "afterShellExecution"}
        if event == "preToolUse":
            entry["matcher"] = "^(Write|Shell)$"
        entries.append([event, entry])
    return entries


def _payloads() -> list[tuple[str, bool, dict[str, object]]]:
    old = f"/usr/bin/python3 -I {SCRIPT} --cursor-hook-event preToolUse"
    legacy = "/usr/bin/python3 -m codex_plugin_scanner.cli hol-guard-hook-argv --harness cursor"
    return [
        ("empty", False, {}),
        (
            "foreign-preserved",
            False,
            {
                "$schema": "https://cursor.example/hooks.json",
                "hooks": {
                    "stop": [{"command": "node /opt/tools/audit.js"}],
                    "beforeShellExecution": [{"command": "echo before"}, {"command": old}, {"command": "echo after"}],
                    "preToolUse": [{"command": legacy}, {"command": old}, {"command": old, "timeout": 5}],
                    "sessionStart": "not a list",
                    "afterFileEdit": [],
                    "beforeReadFile": {"command": old},
                },
                "version": 2,
                "zeta": True,
            },
        ),
        ("retired-managed-only", False, {"version": 1, "hooks": {"beforeWriteFile": [{"command": old}], "stop": []}}),
        ("retired-not-list", False, {"hooks": {"beforeWriteFile": "x", "afterFileEdit": [{"command": "echo"}]}}),
        (
            "retired-foreign",
            False,
            {"hooks": {"beforeWriteFile": [{"command": old}, {"command": "echo foreign"}], "zeta": [], "alpha": [old]}},
        ),
        (
            "flat",
            False,
            {
                "beforeShellExecution": [{"command": "echo flat"}, {"command": old}],
                "version": 3,
                "note": "dropped",
                "stop": {"command": "dropped"},
                "afterFileEdit": [{"command": "echo edit"}],
            },
        ),
        ("flat-hooks-list-managed", False, {"hooks": [{"command": old}], "stop": [{"command": "x"}]}),
        ("flat-hooks-list-foreign", False, {"hooks": [{"command": "x"}]}),
        ("flat-hooks-null", False, {"hooks": None, "version": None}),
        ("version-bool", False, {"version": True}),
        ("version-false", False, {"version": False, "hooks": {}}),
        ("version-float", False, {"version": 1.5}),
        ("version-float-integral", False, {"version": 2.0}),
        ("version-string", False, {"version": "2"}),
        ("version-big", False, {"version": 123456789012345678901234567890}),
        ("version-negative", False, {"version": -3}),
        (
            "non-ascii",
            False,
            {"hooks": {"sessionEnd": [{"command": "echo größe ☃"}], "beforeShellExecution": [{"command": "écho"}]}},
        ),
        (
            "windows",
            True,
            {
                "version": 1,
                "hooks": {
                    "beforeShellExecution": [
                        {"command": r"C:\Python312\python.exe -I C:\Users\GUARD-~1\.cursor\hooks\HOL-GU~1.PY"},
                        {"command": r"C:\tools\audit.exe"},
                    ],
                    "beforeWriteFile": [{"command": r"& 'C:\Python 312\python.exe' -I '" + WIN_SCRIPT + "'"}],
                },
            },
        ),
    ]


def _install_cases() -> Iterator[dict[str, object]]:
    for name, windows, payload in _payloads():
        script = WIN_SCRIPT if windows else SCRIPT
        managed = _managed_entries(script, windows)
        hooks_value = payload.get("hooks")
        request = {
            "payload": payload,
            "top_keys": list(payload),
            "hooks_keys": list(hooks_value) if isinstance(hooks_value, dict) else None,
            "managed": [[event, entry["command"]] for event, entry in managed],  # type: ignore[index]
            "script": script,
        }
        short: set[str] = set()
        with _mode(windows, short):
            normalized = config._managed_hooks_payload(json.loads(json.dumps(payload)))
            hooks = config._inline_hooks(normalized)
            for event, entry in managed:
                hooks[event] = config._merge_hook_entries(hooks.get(event), entry, event_name=event)  # type: ignore[arg-type]
            try:
                config._retire_managed_hook_events(hooks, script_path=_FakeScriptPath(script))  # type: ignore[arg-type]
            except RuntimeError as error:
                expect: dict[str, object] = {"error": str(error)}
            else:
                expect = {"version": normalized["version"], "hooks": [[event, value] for event, value in hooks.items()]}
        case = _case(f"install-{name}", "install", windows, request, expect, short)
        yield {**case, "managed_entries": managed}


def _script_cases() -> Iterator[dict[str, object]]:
    docstring = config._MANAGED_CURSOR_HOOK_DOCSTRING
    full = f"#!/usr/bin/env python3\n{docstring}\nimport json\nGUARD_CLI = []\nGUARD_RECOVERY_COMMAND = ''\n"
    sources = {
        "full": full,
        "crlf": full.replace("\n", "\r\n"),
        "no-recovery": full.replace("GUARD_RECOVERY_COMMAND", "RECOVERY"),
        "no-cli": full.replace("\nGUARD_CLI =", "\nGUARD_CLI="),
        "docstring-only": docstring,
        "mention-only": "# Managed by HOL Guard\nGUARD_CLI = []\nGUARD_RECOVERY_COMMAND = ''\n",
        "first-line-cli": f"GUARD_CLI = []\n{docstring}\nGUARD_RECOVERY_COMMAND = ''\n",
        "non-ascii": f"# größe ☃\n{docstring}\nGUARD_CLI = ['é']\nGUARD_RECOVERY_COMMAND = 'ü'\n",
        "empty": "",
    }
    for name, source in sources.items():
        expect = {"managed": config._is_managed_hook_script(source)}
        yield _case(f"script-{name}", "script", False, {"source": source}, expect, set())


def main() -> None:
    output = Path(sys.argv[1])
    cases = [*_command_cases(), *_entry_cases(), *_hooks_cases(), *_install_cases(), *_script_cases()]
    names = [case["name"] for case in cases]
    assert len(names) == len(set(names))
    vectors = {"schema": "guard-cursor-hook-config-vectors.v1", "cases": cases}
    with output.open("w", encoding="utf-8") as handle:
        json.dump(vectors, handle, ensure_ascii=False, indent=1)
        handle.write("\n")


if __name__ == "__main__":
    main()
