#!/usr/bin/env python3
# pyright: reportAttributeAccessIssue=false
"""Record replay vectors for the native `cursor_hook_state` runner-authority kind.

Run against a checkout whose `cursor_hooks.cursor_native_hook_state` still
decides the verdict in Python (the base of the commit that introduced the
native kind), never from Rust output:

    cd <base-worktree>
    PYTHONPATH=$PWD/src python3 <this-file> <output cursor_hook_state_vectors.json>

Each case plants real state, script and hooks.json files, runs the original
function with the bridge check, CLI attestation, script render and managed
entry render replaced by fixed values, and records its verdict next to the
request a native caller sends for the same files. A case where the original
raised records the label of the read or render that raised.
"""

from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
from collections.abc import Callable
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

from codex_plugin_scanner.guard.adapters import cursor_hooks
from codex_plugin_scanner.guard.adapters._modules.cursor.cursor_hook_events import CURSOR_SHELL_ROUTE_TOOL_MATCHER
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.cursor_hook_config import (
    _BLOCKING_MANAGED_HOOK_EVENTS,
    _MANAGED_HOOK_EVENTS,
    _hooks_state_path,
)

SOURCE = (
    '#!/usr/bin/env python3\n"""Managed by HOL Guard. Re-run `hol-guard install cursor` after moving Guard home."""\n'
    'GUARD_HOME = "/home/\\u65e5\\u672c/.hol-guard"\nGUARD_CLI = ["/opt/hol-guard"]\n'
    'GUARD_RECOVERY_COMMAND = ["/opt/hol-guard"]\nGUARD_HOOK_TIMEOUT_SECONDS = 42\n'
)
IDENTITY: dict[str, object] = {
    "command": ["/opt/hol-guard", "-I"],
    "guard_version": "3.0.0",
    "schema_version": 1,
    "interpreter": {"target_path": "/usr/bin/python3", "target_sha256": "ab" * 32, "size": 4096},
    "label": "Guard 日本",
}
# The planted script lives under a temporary home; entries name a fixed path so
# the recorded hooks.json text does not depend on where the case ran.
BRIDGE = "/opt/guard-runtime cursor-hook-bridge /usr/bin/python3"
SCRIPT = "/home/user/.cursor/hooks/hol-guard-cursor-hook.py"
Mutate = Callable[[dict[str, Path], dict[str, object]], None]


def _entry(event_name: str) -> dict[str, object]:
    entry: dict[str, object] = {
        "command": f"{BRIDGE} -I {SCRIPT} --cursor-hook-event {event_name}",
        "timeout": 45,
        "failClosed": event_name in _BLOCKING_MANAGED_HOOK_EVENTS,
    }
    if event_name == "preToolUse":
        entry["matcher"] = CURSOR_SHELL_ROUTE_TOOL_MATCHER
    return entry


def _observe(read: Callable[[], object]) -> object:
    try:
        return read()
    except Exception:
        return False


def _read_script(path: Path) -> object:
    try:
        regular = stat.S_ISREG(path.lstat().st_mode)
        return {"regular": regular, "text": path.read_text(encoding="utf-8")}
    except OSError:
        return None


def _read_hooks(path: Path) -> object:
    if not path.is_file():
        return None
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def _case(
    name: str,
    *,
    mutate: Mutate | None = None,
    raises: str | None = None,
    failing_entry: str | None = None,
) -> dict[str, object]:
    with tempfile.TemporaryDirectory() as directory:
        base = Path(directory)
        context = HarnessContext(home_dir=base / "home", guard_home=base / "guard", workspace_dir=None)
        hooks_path = cursor_hooks.cursor_hooks_path(context)
        paths = {
            "hooks": hooks_path,
            "script": cursor_hooks.cursor_hook_script_path(context),
            "managed_script": cursor_hooks.managed_hook_script_path(context),
            "state": _hooks_state_path(hooks_path, context),
        }
        for path in paths.values():
            path.parent.mkdir(parents=True, exist_ok=True)
        documents: dict[str, object] = {
            "state": {"guard_cli_identity": IDENTITY, "hook_script_sha256": sha256(SOURCE.encode()).hexdigest()},
            "hooks": {
                "version": 1,
                "hooks": {event: [_entry(event)] for event in _MANAGED_HOOK_EVENTS},
            },
        }
        paths["script"].write_bytes(SOURCE.encode())
        paths["managed_script"].write_bytes(SOURCE.encode())
        if mutate is not None:
            mutate(paths, documents)
        for key in ("state", "hooks"):
            document = documents[key]
            if isinstance(document, bytes):
                paths[key].write_bytes(document)
            elif document is not None:
                paths[key].write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

        def entry(_context: object, *, script_path: Path, event_name: str, python_executable: object) -> object:
            assert python_executable is None
            if event_name == failing_entry:
                raise RuntimeError("guard_cursor_native_bridge_unavailable")
            return _entry(event_name)

        guard_cli = SimpleNamespace(command=("/opt/hol-guard",), python=None, manifest_payload=lambda: IDENTITY)
        saved = (
            cursor_hooks.require_cursor_hook_bridge,
            cursor_hooks.resolve_attested_guard_cli,
            cursor_hooks.cursor_hook_script_source,
            cursor_hooks._managed_hook_entry,
        )
        cursor_hooks.require_cursor_hook_bridge = lambda _home: None
        cursor_hooks.resolve_attested_guard_cli = lambda _context: guard_cli
        cursor_hooks.cursor_hook_script_source = lambda _context, **_kwargs: SOURCE
        cursor_hooks._managed_hook_entry = entry
        try:
            try:
                verdict: object = cursor_hooks.cursor_native_hook_state(context)
            except Exception as error:
                verdict = {"raises": type(error).__name__}
        finally:
            (
                cursor_hooks.require_cursor_hook_bridge,
                cursor_hooks.resolve_attested_guard_cli,
                cursor_hooks.cursor_hook_script_source,
                cursor_hooks._managed_hook_entry,
            ) = saved
        assert ("raises" in verdict) == (raises is not None), (name, verdict)  # type: ignore[operator]
        try:
            state_text: str | None = paths["state"].read_text(encoding="utf-8")
        except OSError:
            state_text = None
        args = {
            "source": SOURCE,
            "identity": IDENTITY,
            "state_text": state_text,
            "scripts": [_observe(lambda path=paths[key]: _read_script(path)) for key in ("script", "managed_script")],
            "hooks_text": _observe(lambda: _read_hooks(paths["hooks"])),
            "entries": {
                event: _observe(
                    lambda event=event: entry(
                        context, script_path=paths["script"], event_name=event, python_executable=None
                    )
                )
                for event in _MANAGED_HOOK_EVENTS
            },
        }
        recorded = {"raise": raises} if raises is not None else verdict
    return {"name": name, "args": args, "verdict": recorded}


def _set(key: str, value: object) -> Mutate:
    def mutate(_paths: dict[str, Path], documents: dict[str, object]) -> None:
        documents[key] = value

    return mutate


def _state(**fields: object) -> Mutate:
    def mutate(_paths: dict[str, Path], documents: dict[str, object]) -> None:
        state = documents["state"]
        assert isinstance(state, dict)
        documents["state"] = {key: value for key, value in {**state, **fields}.items() if value is not _DROP}

    return mutate


def _hooks(change: Callable[[dict[str, object]], None]) -> Mutate:
    def mutate(_paths: dict[str, Path], documents: dict[str, object]) -> None:
        payload = documents["hooks"]
        assert isinstance(payload, dict)
        hooks = payload["hooks"]
        assert isinstance(hooks, dict)
        change(hooks)

    return mutate


def _script(key: str, change: Callable[[Path], None]) -> Mutate:
    def mutate(paths: dict[str, Path], _documents: dict[str, object]) -> None:
        change(paths[key])

    return mutate


def _both(*mutations: Mutate) -> Mutate:
    def mutate(paths: dict[str, Path], documents: dict[str, object]) -> None:
        for mutation in mutations:
            mutation(paths, documents)

    return mutate


_DROP = object()


def _replace_with_directory(path: Path) -> None:
    path.unlink()
    path.mkdir()


def _replace_with_symlink(path: Path) -> None:
    target = path.with_name("target.py")
    target.write_bytes(path.read_bytes())
    path.unlink()
    os.symlink(target, path)


def _dangling_symlink(path: Path) -> None:
    path.unlink()
    os.symlink(path.with_name("absent.py"), path)


def _cases() -> list[dict[str, object]]:
    blocking_entry = "beforeShellExecution"
    float_identity = {**IDENTITY, "schema_version": 1.0, "interpreter": {**IDENTITY["interpreter"], "size": 4096.0}}  # type: ignore[dict-item]
    return [
        _case("healthy install"),
        _case(
            "third-party entries and supported events sit beside Guard",
            mutate=_hooks(
                lambda hooks: (
                    hooks["beforeShellExecution"].insert(0, {"command": "lean-ctx hook", "matcher": "Shell"}),  # type: ignore[union-attr]
                    hooks.update({"stop": [{"command": "notify"}], "sessionStart": "not a list"}),
                )
            ),
        ),
        _case("missing state file", mutate=_set("state", None)),
        _case("state file is not json", mutate=_set("state", b"{not json")),
        _case("state file is empty", mutate=_set("state", b"")),
        _case("state file is a list", mutate=_set("state", [IDENTITY])),
        _case("state file is null", mutate=_set("state", b"null")),
        _case("state file is an empty object inside whitespace", mutate=_set("state", b"\n \t{}\r\n")),
        _case("state identity differs", mutate=_state(guard_cli_identity={**IDENTITY, "guard_version": "0.0.0"})),
        _case("state identity absent", mutate=_state(guard_cli_identity=_DROP)),
        _case("state identity is null", mutate=_state(guard_cli_identity=None)),
        _case("state identity spells integers as floats", mutate=_state(guard_cli_identity=float_identity)),
        _case(
            "state identity spells one as true", mutate=_state(guard_cli_identity={**IDENTITY, "schema_version": True})
        ),
        _case(
            "state identity spells one as 1.5", mutate=_state(guard_cli_identity={**IDENTITY, "schema_version": 1.5})
        ),
        _case(
            "state identity spells one as a string",
            mutate=_state(guard_cli_identity={**IDENTITY, "schema_version": "1"}),
        ),
        _case(
            "state identity with an extra key",
            mutate=_state(guard_cli_identity={**IDENTITY, "extra": None}),
        ),
        _case(
            "state identity with a reordered list",
            mutate=_state(guard_cli_identity={**IDENTITY, "command": ["-I", "/opt/hol-guard"]}),
        ),
        _case("state script digest is stale", mutate=_state(hook_script_sha256="0" * 64)),
        _case("state script digest is absent", mutate=_state(hook_script_sha256=_DROP)),
        _case("state script digest is a number", mutate=_state(hook_script_sha256=7)),
        _case(
            "state script digest in upper case",
            mutate=_state(hook_script_sha256=sha256(SOURCE.encode()).hexdigest().upper()),
        ),
        _case("live script missing", mutate=_script("script", Path.unlink)),
        _case("managed script missing", mutate=_script("managed_script", Path.unlink)),
        _case("live script is a directory", mutate=_script("script", _replace_with_directory)),
        _case("live script is a symlink to the same text", mutate=_script("script", _replace_with_symlink)),
        _case("managed script is a symlink to the same text", mutate=_script("managed_script", _replace_with_symlink)),
        _case("live script is a dangling symlink", mutate=_script("script", _dangling_symlink)),
        _case(
            "live script text differs",
            mutate=_script("script", lambda path: path.write_bytes(SOURCE.encode() + b"# extra\n")),
        ),
        _case(
            "managed script text differs",
            mutate=_script("managed_script", lambda path: path.write_bytes(b"tampered")),
        ),
        _case(
            "live script with CRLF line endings reads back as the source",
            mutate=_script("script", lambda path: path.write_bytes(SOURCE.replace("\n", "\r\n").encode())),
        ),
        _case(
            "live script is not utf-8",
            mutate=_script("script", lambda path: path.write_bytes(b"\xff\xfe")),
            raises="script",
        ),
        _case(
            "managed script is not utf-8 after a tampered live script",
            mutate=_both(
                _script("script", lambda path: path.write_bytes(b"tampered")),
                _script("managed_script", lambda path: path.write_bytes(b"\xff\xfe")),
            ),
        ),
        _case(
            "live script is not utf-8 behind a stale digest",
            mutate=_both(
                _state(hook_script_sha256="0" * 64),
                _script("script", lambda path: path.write_bytes(b"\xff\xfe")),
            ),
        ),
        _case("hooks file missing", mutate=_set("hooks", None)),
        _case(
            "hooks file is a directory",
            mutate=_both(_set("hooks", None), lambda paths, _documents: paths["hooks"].mkdir()),
        ),
        _case("hooks file is not json", mutate=_set("hooks", b"{")),
        _case("hooks file is a list", mutate=_set("hooks", [])),
        _case("hooks file is not utf-8", mutate=_set("hooks", b"\xff{}"), raises="hooks"),
        _case(
            "hooks file is not utf-8 behind a missing managed script",
            mutate=_both(_set("hooks", b"\xff{}"), _script("managed_script", Path.unlink)),
        ),
        _case(
            "hooks registered at the top level",
            mutate=_set("hooks", {event: [_entry(event)] for event in _MANAGED_HOOK_EVENTS}),
        ),
        _case("hooks key is a list", mutate=_set("hooks", {"version": 1, "hooks": []})),
        _case("hooks key is empty", mutate=_set("hooks", {"version": 1, "hooks": {}})),
        _case(
            "retired beforeWriteFile event",
            mutate=_hooks(lambda hooks: hooks.update({"beforeWriteFile": [{"command": "x"}]})),
        ),
        _case(
            "unsupported event ahead of a missing Guard event",
            mutate=_hooks(lambda hooks: (hooks.pop("beforeReadFile"), hooks.update({"BeforeShellExecution": []}))),
        ),
        _case("Guard event missing", mutate=_hooks(lambda hooks: hooks.pop("afterMCPExecution"))),
        _case("Guard event is not a list", mutate=_hooks(lambda hooks: hooks.update({"beforeReadFile": {}}))),
        _case(
            "Guard entry registered twice",
            mutate=_hooks(lambda hooks: hooks["preToolUse"].append(hooks["preToolUse"][0])),  # type: ignore[union-attr,index]
        ),
        _case(
            "Guard entry with another timeout",
            mutate=_hooks(lambda hooks: hooks["beforeReadFile"][0].update({"timeout": 30})),  # type: ignore[index,union-attr]
        ),
        _case(
            "Guard entry spelling its numbers as floats and booleans as integers",
            mutate=_hooks(
                lambda hooks: hooks[blocking_entry][0].update({"timeout": 45.0, "failClosed": 1}),  # type: ignore[index,union-attr]
            ),
        ),
        _case(
            "Guard observer entry spelling failClosed false as zero",
            mutate=_hooks(lambda hooks: hooks["afterShellExecution"][0].update({"failClosed": 0})),  # type: ignore[index,union-attr]
        ),
        _case(
            "Guard entry with timeout true",
            mutate=_hooks(lambda hooks: hooks[blocking_entry][0].update({"timeout": True})),  # type: ignore[index,union-attr]
        ),
        _case(
            "Guard entry with an extra key",
            mutate=_hooks(lambda hooks: hooks["beforeMCPExecution"][0].update({"enabled": True})),  # type: ignore[index,union-attr]
        ),
        _case(
            "Guard entry without the preToolUse matcher",
            mutate=_hooks(lambda hooks: hooks["preToolUse"][0].pop("matcher")),  # type: ignore[index,union-attr]
        ),
        _case(
            "Guard entry keys in another order",
            mutate=_hooks(
                lambda hooks: hooks.update(
                    {"beforeReadFile": [dict(reversed(list(hooks["beforeReadFile"][0].items())))]}  # type: ignore[index,union-attr]
                )
            ),
        ),
        _case("entry render raises", failing_entry="beforeMCPExecution", raises="beforeMCPExecution"),
        _case(
            "entry render raises behind an earlier mismatch",
            mutate=_hooks(lambda hooks: hooks.pop("beforeShellExecution")),
            failing_entry="beforeMCPExecution",
        ),
        _case(
            "entry render raises behind a later mismatch",
            mutate=_hooks(lambda hooks: hooks.pop("afterMCPExecution")),
            failing_entry="beforeMCPExecution",
            raises="beforeMCPExecution",
        ),
        _case(
            "entry render raises behind a stale digest",
            mutate=_state(hook_script_sha256="0" * 64),
            failing_entry="beforeShellExecution",
        ),
    ]


def main() -> None:
    output = Path(sys.argv[1])
    document = {"schema": "guard-cursor-hook-state-vectors.v1", "cases": _cases()}
    with output.open("w", encoding="utf-8") as handle:
        json.dump(document, handle, ensure_ascii=False, indent=1)
        handle.write("\n")


if __name__ == "__main__":
    main()
