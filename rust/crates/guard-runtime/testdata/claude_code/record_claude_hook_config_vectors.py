#!/usr/bin/env python3
"""Record `claude_hook_config` replay vectors from the ORIGINAL Python helpers.

Run against a checkout that still decides Claude hook ownership in Python (the
base of the commit that introduced the native `claude_hook_config`
runner-authority kind), never from Rust output:

    cd <base-worktree>
    PYTHONPATH=$PWD/src python3 <this-file> <output claude_hook_config_vectors.json>

Each case pins one op's request and the answer the Python helpers gave. Lists
the helpers rebuild are recorded as the rebuilt JSON, so the Rust replay
applies its index plan to the request and compares the result. A `TypeError`
from an unhashable handler type is recorded as the native error answer.
"""

from __future__ import annotations

import copy
import json
import sys
from collections.abc import Callable, Iterator
from pathlib import Path

from codex_plugin_scanner.guard.adapters import claude_hook_config as config

ROOT = Path(__file__).resolve().parents[5]
FIXTURE = ROOT / "tests" / "fixtures" / "claude_session_start" / "settings-current.v1.json"
UNHASHABLE = "claude_hook_handler_type_unhashable"
DAEMON = config.CLAUDE_GUARD_DAEMON_HOOK_MARKER
SESSION = config.CLAUDE_GUARD_SESSION_START_HOOK_MARKER
CONTEXT = config.CLAUDE_GUARD_SESSION_START_CONTEXT
TOOLS = config.CLAUDE_GUARD_TOOL_MATCHER

ARGV = ("/opt/guard/native", "claude-hook-bridge", DAEMON, '{"query":"guard-home=x"}')
WIN_ARGV = (
    r"C:\Program Files\HOL Guard\guard-native.exe",
    "claude-hook-bridge",
    DAEMON,
    '{"query":"guard-home=C:\\\\Users\\\\gü ser\\\\.hol-guard"}',
)
SESSION_ARGV = ("/opt/guard/native", "claude-hook-bridge", "session-start", SESSION, "{}")
GUARD = config.guard_command_handler(ARGV, timeout=30, status_message="HOL Guard is checking this tool use")
WIN_GUARD = config.guard_command_handler(WIN_ARGV, timeout=10)
SESSION_GUARD = config.guard_command_handler(SESSION_ARGV, timeout=10)
STALE = {"type": "command", "command": "/old/python", "args": ["-c", DAEMON, "{}"], "timeout": 5}
LEGACY_SHELL = {"type": "command", "command": "python3 -m codex_plugin_scanner.cli guard hook --harness claude-code"}
LEGACY_LIST = {"command": "python3 -c \"from codex_plugin_scanner.cli import main; main(['guard', 'hook'])\""}
LEGACY_ENSURE = {"type": None, "command": f"python3 -c \"ensure_guard_daemon(); print('{CONTEXT}')\""}
GUARD_HTTP = {"type": "http", "url": "http://127.0.0.1:5371/v1/hooks/claude-code?guard-home=%2Fx", "timeout": 30}
USER = {"type": "command", "command": "/usr/bin/true", "args": [], "timeout": 3}
USER_SHELL = {"type": "command", "command": "npm run lint", "shell": "bash"}
USER_HTTP = {"type": "http", "url": "https://hooks.example/v1/hooks/claude-code"}
USER_UNICODE = {"type": "command", "command": "/usr/local/bin/größe ☃", "args": ["—flag", "雪"]}
USER_WIN = {"type": "command", "command": r"C:\Tools\audit.exe", "args": [r"--log=C:\Users\gü\audit.log"]}
UNHASHABLE_LIST = {"type": ["command"], "command": DAEMON}
UNHASHABLE_DICT = {"type": {"kind": "command"}, "command": "/usr/bin/true"}

TEXTS: list[object] = [
    DAEMON,
    f"/opt/guard/native claude-hook-bridge {DAEMON}",
    SESSION,
    f"prefix-{SESSION}-suffix",
    "hol_guard_claude_daemon_hook",
    "python -m codex_plugin_scanner.cli guard hook --harness claude-code",
    "python -m codex_plugin_scanner.cli guard scan",
    "python -c \"main(['guard', 'hook'])\" codex_plugin_scanner.cli",
    'python -c \'main(["guard", "hook"])\' codex_plugin_scanner.cli',
    "python -c \"main(['guard','hook'])\" codex_plugin_scanner.cli",
    "guard hook",
    f"ensure_guard_daemon(); print('{CONTEXT}')",
    "ensure_guard_daemon()",
    CONTEXT,
    "http://127.0.0.1:5371/v1/hooks/claude-code",
    "http://127.0.0.1:5371/v1/hooks/claude-code?guard-home=%2Fhome%2F%E9%9B%AA",
    "http://127.0.0.1:/v1/hooks/claude-code",
    "http://127.0.0.1:5371/v1/hooks/claude-code-extra/x",
    "http://127.0.0.1:5371/v1/hooks/other",
    "https://127.0.0.1:5371/v1/hooks/claude-code",
    "http://localhost:5371/v1/hooks/claude-code",
    "HTTP://127.0.0.1:5371/v1/hooks/claude-code",
    " http://127.0.0.1:5371/v1/hooks/claude-code",
    r"C:\Program Files\HOL Guard\guard-native.exe " + DAEMON,
    "größe ☃ 雪",
    "",
    None,
    7,
    True,
    ["guard hook"],
    {"command": DAEMON},
]

HANDLERS: list[object] = [
    GUARD,
    WIN_GUARD,
    SESSION_GUARD,
    STALE,
    LEGACY_SHELL,
    LEGACY_LIST,
    LEGACY_ENSURE,
    GUARD_HTTP,
    USER,
    USER_SHELL,
    USER_HTTP,
    USER_UNICODE,
    USER_WIN,
    UNHASHABLE_LIST,
    UNHASHABLE_DICT,
    {"type": "command", "command": "/usr/bin/true", "args": ["ok", 5, DAEMON]},
    {"type": "command", "command": DAEMON, "args": ["ok", None]},
    {"type": "command", "command": "/usr/bin/env", "args": "HOL_GUARD_CLAUDE_DAEMON_HOOK"},
    {"type": "command", "command": 5, "args": [DAEMON]},
    {"type": "command", "args": [DAEMON]},
    {"type": "command", "command": DAEMON, "shell": ""},
    {"type": "command", "command": "echo hi", "shell": 7},
    {"type": "command", "command": "echo hi", "shell": "powershell"},
    {"type": "command", "command": ["echo", DAEMON]},
    {"type": "command", "command": {"run": "echo 'hi' \"there\""}},
    {"type": "prompt", "prompt": DAEMON, "command": DAEMON},
    {"type": "http", "url": 5371},
    {"type": "http"},
    {"type": "HTTP", "url": "http://127.0.0.1:5371/v1/hooks/claude-code"},
    {"type": 1, "command": DAEMON},
    {"type": 1.5, "command": "x"},
    {"type": 1e16, "command": "x"},
    {"type": 1e-07, "command": "x"},
    {"type": -0.0, "command": "x"},
    {"type": 12345678901234567890123, "command": "x"},
    {"type": True, "command": DAEMON},
    {"type": False, "url": "http://127.0.0.1:1/v1/hooks/claude-code"},
    {"type": "", "command": DAEMON},
    {"type": "command", "url": 'it\'s "quoted"\n\ttab\\'},
    {"type": "shell", "command": ["it's", None, True, 2.5, {"k": "v\x01"}]},
    {"type": "shell", "command": "don't"},
    {"command": "echo ok"},
    {},
    "not-a-handler",
    None,
    [DAEMON],
]


def _entries_corpus() -> dict[str, list[object]]:
    tools = TOOLS
    return {
        "empty": [],
        "guard-only": [{"matcher": tools, "hooks": [GUARD]}],
        "user-and-guard": [{"matcher": tools, "hooks": [USER]}, {"matcher": tools, "hooks": [GUARD]}],
        "mixed-entry": [{"matcher": tools, "hooks": [USER, STALE, USER_SHELL, GUARD_HTTP]}],
        "duplicate-guard-groups": [
            {"matcher": tools, "hooks": [GUARD]},
            {"matcher": tools, "hooks": [GUARD, GUARD]},
            {"matcher": tools, "hooks": [STALE]},
        ],
        "legacy-commands": [
            {"hooks": [LEGACY_SHELL]},
            {"matcher": "Bash", "hooks": [LEGACY_LIST, USER]},
            {"matcher": "startup", "hooks": [LEGACY_ENSURE]},
        ],
        "url-handlers": [
            {"matcher": "Bash", "hooks": [GUARD_HTTP, USER_HTTP]},
            {"hooks": [{"type": "http", "url": "http://localhost:5371/v1/hooks/claude-code"}]},
        ],
        "flat-guard-entry": [STALE, {"matcher": "Bash", "hooks": [USER]}],
        "flat-guard-hides-unhashable": [{**STALE, "hooks": [UNHASHABLE_LIST]}, {"hooks": [USER]}],
        "non-dict-entries": ["text", 5, None, [GUARD], {"matcher": "Bash", "hooks": [GUARD]}, True],
        "hooks-shapes": [
            {"matcher": "Bash"},
            {"matcher": "Read", "hooks": "x"},
            {"matcher": "Grep", "hooks": {"type": "command", "command": DAEMON}},
            {"matcher": "Edit", "hooks": ["x", 3, None, GUARD]},
            {"matcher": "Write", "hooks": []},
        ],
        "matcher-shapes": [
            {"matcher": "  Bash|Read  ", "hooks": [USER]},
            {"matcher": "", "hooks": [USER_SHELL]},
            {"matcher": "   ", "hooks": [GUARD]},
            {"matcher": 5, "hooks": [USER]},
            {"matcher": None, "hooks": [USER_HTTP]},
            {"matcher": "\u3000startup\u2028", "hooks": [USER]},
            {"matcher": "\x1cresume\x1f", "hooks": [USER]},
        ],
        "non-ascii": [
            {"matcher": "Bash|Lesen☃", "hooks": [USER_UNICODE, GUARD]},
            {"matcher": "雪", "hooks": [{"type": "command", "command": "/opt/雪/bin/hook", "shell": "zsh"}]},
        ],
        "windows-paths": [
            {"matcher": tools, "hooks": [USER_WIN, WIN_GUARD]},
            {"matcher": "Bash", "hooks": [{"type": "command", "command": r"C:\Python 312\python.exe -c " + DAEMON}]},
        ],
        "session-start": [
            {"matcher": "startup", "hooks": [SESSION_GUARD, USER]},
            {"matcher": "resume", "hooks": [SESSION_GUARD]},
            {"matcher": "clear", "hooks": [LEGACY_ENSURE]},
            {"matcher": "compact", "hooks": [USER_SHELL]},
        ],
        "unhashable-item": [{"matcher": "Bash", "hooks": [USER, UNHASHABLE_LIST]}],
        "unhashable-after-guard": [{"matcher": "Bash", "hooks": [GUARD, UNHASHABLE_DICT]}],
        "unhashable-entry": [{"matcher": "Bash", "hooks": [USER]}, {"type": ["x"], "hooks": [GUARD]}],
        "identity-matches": [
            {"matcher": tools, "hooks": [USER, dict(GUARD, timeout=99), USER_SHELL]},
            {"matcher": "Bash", "hooks": [dict(GUARD)]},
        ],
        "identity-shell-form": [
            {"matcher": tools, "hooks": [{"type": "command", "command": " ".join(ARGV)}]},
        ],
    }


def _call(function: Callable[[], object]) -> object:
    try:
        return function()
    except TypeError:
        return {"error": UNHASHABLE}


def _case(name: str, op: str, request: dict[str, object], expect: object) -> dict[str, object]:
    return {"name": name, "op": op, "request": request, "expect": expect}


def _text_cases() -> Iterator[dict[str, object]]:
    for index, value in enumerate(TEXTS):
        expect = {"command": config.is_guard_hook_command(value), "url": config.is_guard_hook_url(value)}
        yield _case(f"text-{index}", "text", {"value": value}, expect)


def _handler_cases() -> Iterator[dict[str, object]]:
    for index, handler in enumerate(HANDLERS):
        is_dict = isinstance(handler, dict)
        guard = _call(lambda handler=handler: config.is_guard_hook_handler(handler))
        argv = config.command_handler_argv(handler) if is_dict else None
        identity = list(config.handler_identity(handler)) if is_dict else None
        expect = {
            "guard": None if isinstance(guard, dict) else guard,
            "argv": None if argv is None else list(argv),
            "identity": identity,
        }
        yield _case(f"handler-{index}", "handler", {"handler": handler}, expect)


def _prune(entries: list[object]) -> object:
    return config.prune_guard_hook_entries(copy.deepcopy(entries))


def _prune_cases() -> Iterator[dict[str, object]]:
    corpus = _entries_corpus()
    for name, entries in corpus.items():
        result = _call(lambda entries=entries: _prune(entries))
        expect = result if isinstance(result, dict) else {"lists": [result]}
        yield _case(f"prune-{name}", "prune", {"lists": [entries]}, expect)
    batch = [corpus["guard-only"], corpus["mixed-entry"], corpus["non-ascii"], []]
    yield _case("prune-batch", "prune", {"lists": batch}, {"lists": [_prune(entries) for entries in batch]})
    failing = [corpus["guard-only"], corpus["unhashable-item"]]
    yield _case("prune-batch-unhashable", "prune", {"lists": failing}, {"error": UNHASHABLE})
    yield _case("prune-no-lists", "prune", {"lists": []}, {"lists": []})


def _merged(job: dict[str, object]) -> object:
    entries = copy.deepcopy(job["entries"])
    if job["prune"]:
        entries = config.prune_guard_hook_entries(entries)
    for matcher in job["matchers"]:
        entries = config.merge_hook_group(entries, matcher, copy.deepcopy(job["handler"]))
    return entries


def _merge_cases() -> Iterator[dict[str, object]]:
    corpus = _entries_corpus()
    session = list(config.CLAUDE_GUARD_SESSION_START_MATCHERS)
    variants: list[tuple[str, list[object], dict[str, object]]] = [
        ("tools", [TOOLS], GUARD),
        ("bash-spaced", ["  Bash  "], GUARD),
        ("bash", ["Bash"], dict(GUARD, timeout=12)),
        ("none", [None], GUARD),
        ("blank", ["   "], GUARD),
        ("non-str", [5], GUARD),
        ("session", session, SESSION_GUARD),
        ("session-twice", [*session, "startup"], SESSION_GUARD),
        ("http", ["Bash"], GUARD_HTTP),
        ("shell", [TOOLS], {"type": "command", "command": " ".join(ARGV)}),
        ("windows", [TOOLS], WIN_GUARD),
        ("unicode", ["Bash|Lesen☃"], USER_UNICODE),
        ("no-matchers", [], GUARD),
    ]
    focus = ("empty", "non-dict-entries", "hooks-shapes", "matcher-shapes", "session-start", "identity-matches")
    for name, entries in corpus.items():
        for variant, matchers, handler in variants if name in focus else variants[:1]:
            for prune in (False, True) if variant in ("tools", "session") else (False,):
                job = {"entries": entries, "prune": prune, "matchers": matchers, "handler": handler}
                result = _call(lambda job=job: _merged(job))
                expect = result if isinstance(result, dict) else {"jobs": [result]}
                label = "prune-merge" if prune else "merge"
                yield _case(f"{label}-{name}-{variant}", "merge", {"jobs": [job]}, expect)


def _hooks_corpus() -> dict[str, dict[str, object]]:
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    corpus = _entries_corpus()
    return {
        "empty": {},
        "fixture-seed": fixture["seed_hooks"],
        "fixture-current": fixture["settings"]["hooks"],
        "legacy-http": {
            "PreToolUse": [{"matcher": "Bash|Read", "hooks": [GUARD_HTTP]}],
            "PermissionRequest": [{"matcher": "Bash|Read", "hooks": [GUARD_HTTP]}],
            "PermissionDenied": [{"hooks": [GUARD_HTTP]}],
        },
        "user-everywhere": {
            "PreToolUse": corpus["user-and-guard"],
            "PostToolUse": corpus["mixed-entry"],
            "Notification": corpus["non-dict-entries"],
            "Stop": corpus["hooks-shapes"],
            "UserPromptSubmit": corpus["matcher-shapes"],
            "PermissionDenied": [{"hooks": [USER, STALE]}],
        },
        "non-list-events": {"PreToolUse": "x", "Stop": {"hooks": []}, "PermissionRequest": None},
        "windows-unicode": {"PreToolUse": corpus["windows-paths"], "Stop": corpus["non-ascii"]},
        "unhashable": {"PreToolUse": [], "Stop": corpus["unhashable-item"]},
    }


def _sync_cases() -> Iterator[dict[str, object]]:
    for name, hooks in _hooks_corpus().items():
        for argv_name, argv in (("posix", ARGV), ("windows", WIN_ARGV)):
            jobs = []
            for group in config.CLAUDE_RUNTIME_HOOK_GROUPS:
                existing = hooks.get(group.event)
                jobs.append(
                    {
                        "entries": existing if isinstance(existing, list) else [],
                        "prune": True,
                        "matchers": [group.matcher],
                        "handler": config.guard_command_handler(
                            argv, timeout=group.timeout_seconds, status_message=group.status_message
                        ),
                    }
                )
            synced = copy.deepcopy(hooks)
            result = _call(lambda synced=synced, argv=argv: config.sync_runtime_hook_groups(synced, argv))
            if isinstance(result, dict):
                expect: object = result
            else:
                expect = {"jobs": [synced[group.event] for group in config.CLAUDE_RUNTIME_HOOK_GROUPS]}
            yield _case(f"sync-{name}-{argv_name}", "merge", {"jobs": jobs}, expect)
        lists = [hooks[key] for key in config.CLAUDE_GUARD_PRUNED_HOOK_EVENTS if isinstance(hooks.get(key), list)]
        retired = copy.deepcopy(hooks)
        result = _call(lambda retired=retired: config.remove_unsupported_guard_hook_groups(retired))
        if isinstance(result, dict):
            expect = result
        else:
            expect = {
                "lists": [
                    retired.get(key, [])
                    for key in config.CLAUDE_GUARD_PRUNED_HOOK_EVENTS
                    if isinstance(hooks.get(key), list)
                ]
            }
        yield _case(f"retire-{name}", "prune", {"lists": lists}, expect)


def _missing(payload: dict[str, object], events: tuple[str, ...], matcher: str) -> object:
    saved = (config.CLAUDE_GUARD_REQUIRED_HOOK_EVENTS, config.CLAUDE_GUARD_TOOL_MATCHER)
    config.CLAUDE_GUARD_REQUIRED_HOOK_EVENTS, config.CLAUDE_GUARD_TOOL_MATCHER = events, matcher
    try:
        return _call(lambda: config.missing_guard_hook_events(copy.deepcopy(payload)))
    finally:
        config.CLAUDE_GUARD_REQUIRED_HOOK_EVENTS, config.CLAUDE_GUARD_TOOL_MATCHER = saved


def _missing_cases() -> Iterator[dict[str, object]]:
    required = config.CLAUDE_GUARD_REQUIRED_HOOK_EVENTS
    covering = {"matcher": TOOLS, "hooks": [USER, GUARD]}
    payloads: dict[str, dict[str, object]] = {
        "empty": {},
        "hooks-list": {"hooks": []},
        "hooks-null": {"hooks": None},
        "covered": {"hooks": {"PreToolUse": [covering], "PermissionRequest": [covering]}},
        "permission-missing": {"hooks": {"PreToolUse": [covering]}},
        "older-matcher": {
            "hooks": {
                "PreToolUse": [
                    {"matcher": "Bash|Read|Grep|Write|Edit|MultiEdit|WebFetch|WebSearch|mcp__.*", "hooks": [GUARD]}
                ],
                "PermissionRequest": [{"matcher": TOOLS + "|Extra", "hooks": [GUARD_HTTP]}],
            }
        },
        "matcher-omitted-or-null": {
            "hooks": {"PreToolUse": [{"hooks": [STALE]}], "PermissionRequest": [{"matcher": None, "hooks": [STALE]}]}
        },
        "matcher-spaced": {
            "hooks": {
                "PreToolUse": [{"matcher": " | ".join(TOOLS.split("|")) + " |", "hooks": [GUARD]}],
                "PermissionRequest": [{"matcher": 5, "hooks": [GUARD]}],
            }
        },
        "flat-guard-entry": {"hooks": {"PreToolUse": [dict(STALE, matcher=TOOLS)], "PermissionRequest": [STALE]}},
        "user-only": {"hooks": {"PreToolUse": [{"matcher": TOOLS, "hooks": [USER]}], "PermissionRequest": "x"}},
        "non-dict-entries": {"hooks": {"PreToolUse": ["x", None, covering], "PermissionRequest": [[covering]]}},
        "unhashable": {"hooks": {"PreToolUse": [{"matcher": TOOLS, "hooks": [UNHASHABLE_DICT, GUARD]}]}},
        "unhashable-after-cover": {
            "hooks": {"PreToolUse": [covering, {"hooks": [UNHASHABLE_LIST]}], "PermissionRequest": [covering]}
        },
        "unhashable-entry-type": {"hooks": {"PreToolUse": [{"type": {"a": 1}}]}},
        "non-ascii": {
            "hooks": {
                "PreToolUse": [{"matcher": TOOLS + "|Lesen☃", "hooks": [USER_UNICODE, WIN_GUARD]}],
                "PermissionRequest": [{"matcher": "雪", "hooks": [GUARD]}],
            }
        },
    }
    variants = (
        ("required", required, TOOLS),
        ("repeated", ("PreToolUse", "PreToolUse", "Stop"), TOOLS),
        ("narrow", required, "Bash| Read |"),
    )
    for name, payload in payloads.items():
        for variant, events, matcher in variants:
            result = _missing(payload, events, matcher)
            expect = result if isinstance(result, dict) else {"missing": result}
            request = {"payload": payload, "events": list(events), "matcher": matcher}
            yield _case(f"missing-{name}-{variant}", "missing", request, expect)


def main() -> None:
    output = Path(sys.argv[1])
    cases = [
        *_text_cases(),
        *_handler_cases(),
        *_prune_cases(),
        *_merge_cases(),
        *_sync_cases(),
        *_missing_cases(),
    ]
    names = [case["name"] for case in cases]
    assert len(names) == len(set(names))
    vectors = {"schema": "guard-claude-hook-config-vectors.v1", "cases": cases}
    with output.open("w", encoding="utf-8") as handle:
        json.dump(vectors, handle, ensure_ascii=False, indent=1)
        handle.write("\n")


if __name__ == "__main__":
    main()
