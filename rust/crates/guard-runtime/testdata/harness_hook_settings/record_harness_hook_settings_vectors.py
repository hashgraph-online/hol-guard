#!/usr/bin/env python3
"""Record `harness_hook_settings` replay vectors from the ORIGINAL Python adapters.

Run against a checkout that still rewrites Muse and Devin hook settings in
Python (the base of the commit that introduced the native
`harness_hook_settings` runner-authority kind), never from Rust output:

    cd <base-worktree>
    PYTHONPATH=$PWD/src python3 <this-file> <output harness_hook_settings_vectors.json>

Install and uninstall cases run the adapters' own `prepare_install` and
`uninstall` against a temporary home, with the launcher shim, the bridge
command and the configured approval wait stubbed, and record the `hooks`
object they wrote as ordered `[event, value]` pairs. A refused install is
recorded as the native error answer. Devin's JSONC parse is stubbed with a
strict JSON parse: only the hooks rewrite is under test here.
"""

from __future__ import annotations

import copy
import json
import re
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace

from codex_plugin_scanner.guard.adapters import devin, devin_config, muse, muse_config
from codex_plugin_scanner.guard.adapters.base import HarnessContext, _shell_command
from codex_plugin_scanner.guard.adapters.devin_config import DevinJsonDocument

sys.path.insert(0, str(Path(__file__).resolve().parent))
from record_harness_hook_settings_inputs import (
    INSTALL_WAITS,
    OTHER_KEYS,
    PARTS,
    REINSTALLS,
    UNINSTALL_SHAPES,
    earlier_guard_commands,
    install_shapes,
    other_commands,
)

ADAPTERS = {"muse": muse.MuseHarnessAdapter, "devin": devin.DevinHarnessAdapter}
PREDICATES = {
    "muse": muse_config.is_guard_managed_hook_command,
    "devin": devin_config.is_guard_managed_hook_command,
}
NOT_OBJECT = "harness_hook_settings_hooks_not_object"
NOT_LIST = "harness_hook_settings_event_not_list"
_EVENT = re.compile(r"non-list hooks\.(.*) value; Guard will not rewrite it\. Fix the file", re.DOTALL)


def _strict_document(text: str) -> DevinJsonDocument:
    return DevinJsonDocument(payload=json.loads(text), had_comments=False, parse_failed=False, exists=True)


def _load_strict(path: Path) -> DevinJsonDocument:
    return _strict_document(path.read_text(encoding="utf-8"))


def _stub(wait: int) -> None:
    config = SimpleNamespace(approval_wait_timeout_seconds=wait)
    for module in (muse, devin):
        module.load_guard_config = lambda *_args, **_kwargs: config  # type: ignore[attr-defined]
        module.prepare_guard_shim = lambda *_args, **_kwargs: SimpleNamespace(manifest={}, files=())  # type: ignore[attr-defined]
        module.remove_guard_shim = lambda *_args, **_kwargs: {}  # type: ignore[attr-defined]
    devin.parse_devin_jsonc = _strict_document  # type: ignore[attr-defined]
    devin.load_devin_jsonc = _load_strict  # type: ignore[attr-defined]
    for harness, adapter in ADAPTERS.items():
        parts = PARTS[harness]
        adapter._hook_command_parts = staticmethod(lambda _context, *, prepared_files=None, parts=parts: parts)  # type: ignore[method-assign]


def _context(root: Path) -> HarnessContext:
    return HarnessContext(home_dir=root / "home", workspace_dir=None, guard_home=root / "guard")


def _settings_path(harness: str, context: HarnessContext) -> Path:
    if harness == "muse":
        return muse.MuseHarnessAdapter._user_settings_path(context)
    return devin.DevinHarnessAdapter._user_config_path(context)


def _timing(harness: str, context: HarnessContext, wait: int) -> dict[str, int]:
    if harness == "muse":
        return {"bridge_seconds": muse.MuseHarnessAdapter._bridge_timeout_seconds(context)}
    return {"wait_seconds": wait}


def _hooks_request(payload: dict[str, object]) -> dict[str, object]:
    hooks = payload.get("hooks")
    return {"hooks": copy.deepcopy(hooks), "hooks_keys": list(hooks) if isinstance(hooks, dict) else None}


def _pairs(payload: dict[str, object]) -> list[list[object]]:
    hooks = payload.get("hooks", {})
    assert isinstance(hooks, dict)
    return [[event, value] for event, value in hooks.items()]


def _install(harness: str, root: Path, raw: str | None) -> tuple[dict[str, object], str | None]:
    """Run the original install over `raw` settings; answer the expectation and the written text."""

    context = _context(root)
    path = _settings_path(harness, context)
    if raw is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(raw, encoding="utf-8")
    try:
        prepared = ADAPTERS[harness]().prepare_install(context)
    except ValueError as error:
        message = str(error)
        if "non-object hooks value" in message:
            return {"error": NOT_OBJECT, "event": None}, None
        match = _EVENT.search(message)
        assert match is not None, message
        return {"error": NOT_LIST, "event": match.group(1)}, None
    (written,) = [change for change in prepared.files if change.path == path.resolve(strict=False)]
    assert written.after is not None
    text = written.after.decode("utf-8")
    return {"hooks": _pairs(json.loads(text))}, text


def _install_case(
    name: str, harness: str, wait: int, payload: dict[str, object] | None, *, reinstall: bool
) -> dict[str, object]:
    _stub(wait)
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        raw = None if payload is None else json.dumps(payload, ensure_ascii=False)
        if reinstall:
            _expect, raw = _install(harness, root, raw)
            assert raw is not None
        request: dict[str, object] = {
            "harness": harness,
            **_hooks_request(json.loads(raw) if raw is not None else {}),
            **_timing(harness, _context(root), wait),
        }
        expect, _text = _install(harness, root, raw)
    command = _shell_command(PARTS[harness])
    return {"name": name, "op": "install", "request": request, "command": command, "expect": expect}


def _install_cases() -> Iterator[dict[str, object]]:
    for harness in ADAPTERS:
        yield _install_case(f"install-{harness}-no-file", harness, 120, None, reinstall=False)
        for index, (shape, hooks) in enumerate(install_shapes(harness).items()):
            wait = INSTALL_WAITS[index % len(INSTALL_WAITS)]
            payload = dict(OTHER_KEYS) if hooks is ... else {**OTHER_KEYS, "hooks": hooks}
            yield _install_case(f"install-{harness}-{shape}", harness, wait, payload, reinstall=False)
            if shape in REINSTALLS:
                name = f"reinstall-{harness}-{shape}"
                yield _install_case(name, harness, wait, payload, reinstall=True)


def _uninstall_case(name: str, harness: str, payload: dict[str, object], *, installed: bool) -> dict[str, object]:
    _stub(120)
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        context = _context(root)
        path = _settings_path(harness, context)
        raw = json.dumps(payload, ensure_ascii=False)
        if installed:
            _expect, written = _install(harness, root, raw)
            assert written is not None
            raw = written
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(raw, encoding="utf-8")
        request = {"harness": harness, **_hooks_request(json.loads(raw))}
        ADAPTERS[harness]().uninstall(context)
        expect = {"hooks": _pairs(json.loads(path.read_text(encoding="utf-8")))}
    return {"name": name, "op": "prune", "request": request, "expect": expect}


def _uninstall_cases() -> Iterator[dict[str, object]]:
    for harness in ADAPTERS:
        shapes = install_shapes(harness)
        for shape in UNINSTALL_SHAPES:
            payload = {**OTHER_KEYS, "hooks": shapes[shape]}
            yield _uninstall_case(f"uninstall-{harness}-{shape}", harness, payload, installed=False)
        for shape in REINSTALLS:
            hooks = shapes[shape]
            payload = dict(OTHER_KEYS) if hooks is ... else {**OTHER_KEYS, "hooks": hooks}
            yield _uninstall_case(f"uninstall-{harness}-installed-{shape}", harness, payload, installed=True)


def _managed_cases() -> Iterator[dict[str, object]]:
    for harness, predicate in PREDICATES.items():
        other = "devin" if harness == "muse" else "muse"
        commands = [*earlier_guard_commands(harness), *other_commands(harness), *earlier_guard_commands(other)[:2]]
        commands.append(_shell_command(PARTS[harness]))
        commands.append(_shell_command(PARTS[harness], windows=True))
        expect = {"managed": [predicate(command) for command in commands]}
        request = {"harness": harness, "commands": commands}
        yield {"name": f"managed-{harness}", "op": "managed", "request": request, "expect": expect}


def main() -> None:
    output = Path(sys.argv[1])
    cases = [*_managed_cases(), *_install_cases(), *_uninstall_cases()]
    names = [case["name"] for case in cases]
    assert len(names) == len(set(names))
    vectors = {"schema": "guard-harness-hook-settings-vectors.v1", "cases": cases}
    with output.open("w", encoding="utf-8") as handle:
        json.dump(vectors, handle, ensure_ascii=False, indent=1)
        handle.write("\n")


if __name__ == "__main__":
    main()
