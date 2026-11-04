"""Keep long Codex sessions lean by having Codex sum up older turns sooner.

Codex re-sends the whole conversation on every model call, so a session that
runs for dozens of tool calls keeps paying for everything it has already seen.
Codex's own ``model_auto_compact_token_limit`` setting makes it summarize the
conversation once it passes that size. Guard can turn that on for the user and
turn it off again, and it never touches a value the user set themselves: Guard
records the value it wrote and only removes that exact value.
"""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path
from typing import TextIO

from .codex_config import dump_toml

tomllib = importlib.import_module("tomllib" if sys.version_info >= (3, 11) else "tomli")

KEY = "model_auto_compact_token_limit"
LIMIT = 30_000
SCHEMA = "guard-codex-lean-sessions.v1"
_RECORD_NAME = "codex-lean-sessions.json"


class LeanSessionsError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def config_path(home_dir: Path) -> Path:
    return home_dir / ".codex" / "config.toml"


def status(home_dir: Path, guard_home: Path) -> dict[str, object]:
    path = config_path(home_dir)
    _text, payload = _read_config(path)
    return _view(path, payload.get(KEY), _recorded(guard_home))


def enable(home_dir: Path, guard_home: Path) -> dict[str, object]:
    path = config_path(home_dir)
    with _locked(guard_home, path):
        text, payload = _read_config(path)
        current, recorded = payload.get(KEY), _recorded(guard_home)
        if current is not None:
            return _view(path, current, recorded)
        # The record goes first: if Guard stops between the two writes, the
        # config is untouched and status reads "off", never a value nobody owns.
        _write_record(guard_home, LIMIT)
        payload[KEY] = LIMIT
        _write_config(path, payload, text)
        return _view(path, LIMIT, LIMIT)


def disable(home_dir: Path, guard_home: Path) -> dict[str, object]:
    path = config_path(home_dir)
    with _locked(guard_home, path):
        text, payload = _read_config(path)
        current, recorded = payload.get(KEY), _recorded(guard_home)
        if recorded is not None and current == recorded:
            del payload[KEY]
            _write_config(path, payload, text)
            current = None
        _clear_record(guard_home)
        return _view(path, current, None)


def render(state: dict[str, object], output: TextIO) -> None:
    limit = state["limit"]
    if state["state"] == "on":
        print(
            f"Lean Codex sessions: on. Codex sums up older turns once a session passes {limit:,} tokens.",
            file=output,
        )
        print("Turn it off with: hol-guard context lean off", file=output)
    elif state["state"] == "yours":
        print(f"Your Codex config already sets {KEY} = {limit}. Guard left it as it is.", file=output)
    else:
        print("Lean Codex sessions: off. Codex uses its own default for long sessions.", file=output)
        print("Turn it on with: hol-guard context lean on", file=output)


def _view(path: Path, current: object, recorded: int | None) -> dict[str, object]:
    if current is None:
        state = "off"
    elif recorded is not None and current == recorded:
        state = "on"
    else:
        state = "yours"
    return {"schema": SCHEMA, "state": state, "limit": current, "config_path": str(path)}


def _read_config(path: Path) -> tuple[str | None, dict[str, object]]:
    """The config text and its parsed form. A file Guard cannot read stops the
    change: writing a fresh file over it would lose the user's settings."""

    if not path.exists():
        return None, {}
    if path.is_symlink() or not path.is_file():
        raise LeanSessionsError("codex_config_not_regular_file")
    try:
        text = path.read_text(encoding="utf-8")
        payload = tomllib.loads(text)
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise LeanSessionsError("codex_config_unreadable") from error
    return text, payload


def _write_config(path: Path, payload: dict[str, object], original: str | None) -> None:
    from .codex_hook_integrity import atomic_write_text

    atomic_write_text(path, dump_toml(payload, original=original), mode=0o600)


def _record_path(guard_home: Path) -> Path:
    return guard_home / _RECORD_NAME


def _recorded(guard_home: Path) -> int | None:
    try:
        value = json.loads(_record_path(guard_home).read_text(encoding="utf-8")).get("value")
    except (OSError, ValueError, AttributeError):
        return None
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _write_record(guard_home: Path, value: int) -> None:
    from .codex_hook_integrity import atomic_write_text

    atomic_write_text(_record_path(guard_home), json.dumps({"value": value}) + "\n", mode=0o600)


def _clear_record(guard_home: Path) -> None:
    _record_path(guard_home).unlink(missing_ok=True)


def _locked(guard_home: Path, path: Path):
    """Hold the same lock Guard's Codex install takes, so the two never write
    the config file at the same time."""

    from .codex_install_transaction import codex_install_transaction

    return codex_install_transaction(guard_home, path, actor="lean-sessions")
