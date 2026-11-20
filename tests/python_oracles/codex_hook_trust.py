"""Codex hook trust for Guard's own hooks, computed by the native runtime.

Codex (codex-rs/hooks/src/engine/discovery.rs ``hook_hash`` and
codex-rs/config/src/fingerprint.rs ``version_for_toml``) only runs a user-layer hook
when ``[hooks.state."<key>"].trusted_hash`` equals the hash of the hook's normalized
identity. Guard's frozen runtime binds hook commands to a versioned executable, so every
install or update invalidates trust until the user trusts the hooks again in Codex.

The runtime's ``codex-hook-trust`` command hashes handlers and answers which state keys
are stale. Install records trust and moves state, and the hook state doctor reads says
whether Codex still trusts Guard's hooks, and doctor's trust warning, in the native
adapter; this module only asks for a handler's hash.
"""

from __future__ import annotations

import json
from collections.abc import Mapping

from codex_plugin_scanner.guard.mdm.runtime_request import runtime_answer

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
