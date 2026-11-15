"""Codex hook trust for Guard's own hooks, computed by the native runtime.

Codex (codex-rs/hooks/src/engine/discovery.rs ``hook_hash`` and
codex-rs/config/src/fingerprint.rs ``version_for_toml``) only runs a user-layer hook
when ``[hooks.state."<key>"].trusted_hash`` equals the hash of the hook's normalized
identity. Guard's frozen runtime binds hook commands to a versioned executable, so every
install or update invalidates trust until the user trusts the hooks again in Codex.

The runtime's ``codex-hook-trust`` command hashes handlers and answers which state keys
are stale. Install records trust and moves state in the native adapter; this module
only reads the answer doctor needs.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

from .codex_hook_registration import is_live_guard_codex_hook_command
from .mdm.runtime_request import runtime_answer

CODEX_HOOK_TRUST_WARNING = (
    "Codex has not trusted the current HOL Guard hooks, so Codex skips them. "
    "Open Codex, run /hooks, and press t to trust them."
)

_FEATURE = "native-codex-hook-trust-v1"
_COMMAND = "codex-hook-trust"
_SCHEMA = "codex-hook-trust.v1"
_OUTPUT_LIMIT = 4 * 1024 * 1024
_TIMEOUT_SECONDS = 10.0
_OPAQUE = ["opaque"]


def codex_command_hook_hash(event_name: str, matcher: object, handler: Mapping[str, object]) -> str | None:
    """Return Codex's ``current_hash`` for one command handler, or None if not hashable."""

    answer = _ask({"op": "hash", "event": event_name, "matcher": _jsonable(matcher), "handler": _jsonable(handler)})
    digest = answer.get("hash") if answer is not None else None
    return digest if isinstance(digest, str) else None


def stale_guard_hook_coordinates(payload: Mapping[str, object], config_path: Path) -> list[str]:
    """Return state keys of Guard-managed hooks whose stored trust is missing or stale.

    Raises ``RuntimeError`` when the runtime cannot answer.
    """

    hooks = payload.get("hooks")
    if not isinstance(hooks, Mapping):
        return []
    answer = _ask(_table_request("stale", hooks, config_path))
    stale = answer.get("stale") if answer is not None else None
    if not isinstance(stale, list):
        raise RuntimeError("codex_hook_trust_unavailable")
    return [str(key) for key in stale]


def codex_hook_trust_stale(payload: object, config_path: Path) -> bool:
    if not isinstance(payload, Mapping):
        return False
    try:
        return bool(stale_guard_hook_coordinates(payload, config_path))
    except RuntimeError:
        # Unknown trust reads as stale: doctor must not call the hooks active.
        return True


def apply_codex_hook_trust_doctor(payload: dict[str, object], hook_state: Mapping[str, object]) -> None:
    """Warn about untrusted Guard hooks and stop doctor from calling them active."""

    if not hook_state.get("hook_trust_stale"):
        return
    warnings = payload.get("warnings")
    payload["warnings"] = [*(warnings if isinstance(warnings, list) else []), CODEX_HOOK_TRUST_WARNING]
    if payload.get("setup_status") == "active":
        payload["setup_status"] = "partial"


def _table_request(op: str, hooks: Mapping[str, object], config_path: Path) -> dict[str, object]:
    state = hooks.get("state")
    request: dict[str, object] = {
        "op": op,
        "events": _events(hooks),
        "state": [[str(key), _jsonable(entry)] for key, entry in state.items()] if isinstance(state, Mapping) else [],
        # Codex keys hook state by the canonical config path.
        "prefixes": list(dict.fromkeys((str(_resolved(config_path)), str(config_path)))),
        "guard_commands": sorted(_guard_commands(hooks)),
    }
    return request


def _events(hooks: Mapping[str, object]) -> list[list[object]]:
    return [[str(name), _jsonable(groups)] for name, groups in hooks.items() if isinstance(groups, list)]


def _guard_commands(hooks: Mapping[str, object]) -> set[str]:
    found: set[str] = set()
    for groups in hooks.values():
        for group in groups if isinstance(groups, list) else []:
            handlers = group.get("hooks") if isinstance(group, Mapping) else None
            for handler in handlers if isinstance(handlers, list) else []:
                command = handler.get("command") if isinstance(handler, Mapping) else None
                if isinstance(command, str) and is_live_guard_codex_hook_command(command):
                    found.add(str(command))
    return found


def _jsonable(value: object) -> object:
    """A JSON form of a TOML value that keeps every distinction trust reads.

    Strings, booleans and integers keep their exact value. Floats, dates and
    anything else turn into an opaque list, which no check mistakes for a table,
    string, integer or boolean.
    """

    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, str):
        return str(value)
    if isinstance(value, int):
        return int(value)
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_jsonable(item) for item in value]
    return _OPAQUE


def _ask(request: dict[str, object]) -> dict[str, object] | None:
    return runtime_answer(
        _FEATURE,
        _COMMAND,
        json.dumps({"schema": _SCHEMA, **request}, ensure_ascii=False),
        output_limit=_OUTPUT_LIMIT,
        timeout_seconds=_TIMEOUT_SECONDS,
    )


def _resolved(path: Path) -> Path:
    try:
        return path.resolve()
    except (OSError, RuntimeError):
        return path
