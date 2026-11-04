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
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
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


def config_path(home_dir: Path, environ: Mapping[str, str] | None = None) -> Path:
    """The config file Codex reads: `CODEX_HOME` when the environment sets
    it, as Codex does, else `~/.codex`."""

    base = (environ or {}).get("CODEX_HOME", "").strip()
    return (Path(base).expanduser() if base else home_dir / ".codex") / "config.toml"


def status(home_dir: Path, guard_home: Path, environ: Mapping[str, str] | None = None) -> dict[str, object]:
    path = config_path(home_dir, environ)
    _text, payload = _read_config(path)
    return _view(path, payload.get(KEY), _recorded(guard_home, path))


def enable(home_dir: Path, guard_home: Path, environ: Mapping[str, str] | None = None) -> dict[str, object]:
    path = config_path(home_dir, environ)
    with _locked(guard_home, path):
        text, payload = _read_config(path)
        current, recorded = payload.get(KEY), _recorded(guard_home, path)
        if current is not None:
            return _view(path, current, recorded)
        # The record goes first: if Guard stops between the two writes, the
        # config is untouched and status reads "off", never a value nobody owns.
        _write_record(guard_home, path, LIMIT)
        payload[KEY] = LIMIT
        try:
            _write_config(path, payload, text)
        except BaseException:
            _write_record(guard_home, path, None)
            raise
        return _view(path, LIMIT, LIMIT)


def disable(home_dir: Path, guard_home: Path, environ: Mapping[str, str] | None = None) -> dict[str, object]:
    path = config_path(home_dir, environ)
    with _locked(guard_home, path):
        text, payload = _read_config(path)
        current, recorded = payload.get(KEY), _recorded(guard_home, path)
        if recorded is None or current != recorded:
            _write_record(guard_home, path, None)
            return _view(path, current, None)
        del payload[KEY]
        _write_config(path, payload, text)
        # A record left behind would claim a value the user sets later, so a
        # failed removal puts the config back as it was.
        try:
            _write_record(guard_home, path, None)
        except BaseException:
            _restore_config(path, text)
            raise
        return _view(path, None, None)


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


def _restore_config(path: Path, original: str | None) -> None:
    from .codex_hook_integrity import atomic_write_text

    if original is not None:
        atomic_write_text(path, original, mode=0o600)


def _record_path(guard_home: Path) -> Path:
    return guard_home / _RECORD_NAME


def _records(guard_home: Path) -> dict[str, int]:
    """The value Guard wrote to each Codex config, keyed by the config's
    path: with `CODEX_HOME`, one Guard home can edit more than one."""

    try:
        configs = json.loads(_record_path(guard_home).read_text(encoding="utf-8")).get("configs")
    except (OSError, ValueError, AttributeError):
        return {}
    if not isinstance(configs, dict):
        return {}
    return {
        key: value
        for key, value in configs.items()
        if isinstance(key, str) and isinstance(value, int) and not isinstance(value, bool)
    }


def _record_key(path: Path) -> str:
    return str(path.expanduser().absolute())


def _recorded(guard_home: Path, path: Path) -> int | None:
    return _records(guard_home).get(_record_key(path))


def _write_record(guard_home: Path, path: Path, value: int | None) -> None:
    """Record `value` for this config, or forget it when `value` is None."""

    from .codex_hook_integrity import atomic_write_text

    records = _records(guard_home)
    if value is None:
        records.pop(_record_key(path), None)
    else:
        records[_record_key(path)] = value
    record = _record_path(guard_home)
    if not records:
        record.unlink(missing_ok=True)
        return
    atomic_write_text(record, json.dumps({"configs": records}, sort_keys=True) + "\n", mode=0o600)


@contextmanager
def _locked(guard_home: Path, path: Path) -> Iterator[None]:
    """Hold the same lock Guard's Codex install takes, so the two never write
    the config file at the same time, and finish an interrupted hook install
    first: its recovery checks the config is as it left it."""

    from .codex_hook_file_integrity import CodexHookIntegrityError
    from .codex_hook_recovery import recover_hook_publication
    from .codex_install_transaction import codex_install_transaction

    with codex_install_transaction(guard_home, path, actor="lean-sessions"):
        try:
            recover_hook_publication(guard_home)
        except CodexHookIntegrityError as error:
            raise LeanSessionsError("codex_hooks_need_recovery") from error
        yield
