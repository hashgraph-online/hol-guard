"""Honor custom-extension grants for native PreToolUse answers.

The resident derives the command's local CLI identity, reads its grant and
decides (``hook_local_cli_rule``); this module asks it and renders the verdict.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from collections.abc import Mapping
from pathlib import Path
from uuid import uuid4

from .. import store_storage_gate
from ..native_context import ensure_resident_prerequisite
from ..native_execution import _resident_request
from .hook_fail_closed import render_accepted_allow
from .hook_native_saved_approval import _saved_block_response, store_guard_home

_LOGGER = logging.getLogger(__name__)
HOOK_LOCAL_CLI_RULE_FEATURE = "hook-local-cli-rule-v1"
_REQUEST_SCHEMA = "guard-hook-local-cli-rule-request.v1"
_RESULT_SCHEMA = "guard-hook-local-cli-rule-result.v1"
_RESULT_FIELDS = frozenset({"schema", "request_id", "status", "verdict", "name"})
_VERDICTS = frozenset({"none", "blocked", "unverified", "allowed"})
_TIMEOUT_SECONDS = 5.0
_BLOCK_RULES_TTL_SECONDS = 2.0
_block_rules_lock = threading.Lock()
_block_rules_cache: dict[int, tuple[float, bool]] = {}


def native_local_cli_block_response(
    store: object,
    *,
    harness: str,
    payload: Mapping[str, object],
    native_result: Mapping[str, object],
    workspace: Path | None,
    home_dir: Path | None,
) -> dict[str, object] | None:
    """Apply a custom-extension block to a native PreToolUse that Rust allowed.

    The Python hook path applies custom blocks at every action, so the native
    path does too. The resident is asked only while some custom block exists,
    and a command it cannot check against that rule is blocked as unverified.
    """

    if native_result.get("minimum_action") != "allow" or not _has_block_rules(store):
        return None
    answer = _rule_verdict(store, "allowed", payload, native_result, workspace, home_dir)
    verdict, name = answer if answer is not None else ("unverified", None)
    if verdict == "blocked" and name is not None:
        return _custom_block_response(harness, native_result, name, store_guard_home(store))
    if verdict == "unverified":
        return _saved_block_response(
            harness,
            native_result,
            reason_code="local_cli_extension_unverified",
            reason="Guard could not check this command against your custom extension rules.",
            guard_home=store_guard_home(store),
        )
    return None


def _has_block_rules(store: object) -> bool:
    probe = getattr(store, "has_local_cli_block_rules", None)
    if not callable(probe):
        return False
    now = time.monotonic()
    key = id(store)
    with _block_rules_lock:
        cached = _block_rules_cache.get(key)
        if cached is not None and now - cached[0] < _BLOCK_RULES_TTL_SECONDS:
            return cached[1]
    try:
        present = bool(probe())
    except Exception:
        _LOGGER.warning("custom extension block probe failed", exc_info=True)
        # Fail toward checking: the resident reads the rule rows itself.
        present = True
    with _block_rules_lock:
        _block_rules_cache[key] = (now, present)
    return present


def native_local_cli_grant_response(
    store: object,
    *,
    harness: str,
    payload: Mapping[str, object],
    native_result: Mapping[str, object],
    workspace: Path | None,
    home_dir: Path | None,
) -> tuple[bool, dict[str, object]] | None:
    """Return ``(blocked, response)`` for a native review with a custom rule, or ``None``.

    A custom block applies to any review. A custom allow only lifts an
    overridable review that is due to non-recognition alone, so it never
    weakens a block, a critical floor or a risk signal on the operands.
    Callers must let a saved exact-action block win over a custom allow.
    A rule the resident cannot read leaves the review standing.
    """

    if native_result.get("policy_action") not in {"review", "require-reapproval"}:
        return None
    answer = _rule_verdict(store, "review", payload, native_result, workspace, home_dir)
    if answer is None:
        return None
    verdict, name = answer
    if verdict == "blocked" and name is not None:
        return True, _custom_block_response(harness, native_result, name, store_guard_home(store))
    if verdict != "allowed":
        return None
    allowed = dict(native_result)
    allowed.update(decision="allow", minimum_action="allow", policy_action="allow")
    return False, render_accepted_allow(harness, allowed, guard_home=store_guard_home(store))


def _rule_verdict(
    store: object,
    mode: str,
    payload: Mapping[str, object],
    native_result: Mapping[str, object],
    workspace: Path | None,
    home_dir: Path | None,
) -> tuple[str, str | None] | None:
    """The resident's ``(verdict, name)`` for this rule check, or ``None`` without one."""

    guard_home = store_guard_home(store)
    store_path = getattr(store, "path", None)
    if guard_home is None or not isinstance(store_path, Path) or home_dir is None:
        return None
    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"hook-local-cli-rule-{uuid4().hex}",
        "store_path": str(store_path),
        "guard_home": str(guard_home),
        "mode": mode,
        "payload": dict(payload),
        "native_result": dict(native_result),
        "workspace": None if workspace is None else str(workspace),
        "home_dir": str(home_dir),
        # The launch resolves against the daemon's environment, not the resident's.
        "user_home": str(Path.home()),
        "env": dict(os.environ),
    }
    try:
        if not ensure_resident_prerequisite(guard_home):
            return None
        with store_storage_gate.hold_storage_gate(guard_home, exclusive=False):
            response = _resident_request(
                operation="hook_local_cli_rule",
                request=request,
                guard_home=guard_home,
                timeout_seconds=_TIMEOUT_SECONDS,
                required_feature=HOOK_LOCAL_CLI_RULE_FEATURE,
                response_schema=_RESULT_SCHEMA,
            )
    except Exception:
        _LOGGER.warning("custom extension rule check failed", exc_info=True)
        return None
    if (
        response is None
        or not set(response) <= _RESULT_FIELDS
        or response.get("request_id") != request["request_id"]
        or not isinstance(response.get("verdict"), str)
        or response["verdict"] not in _VERDICTS
    ):
        return None
    name = response.get("name")
    if response["verdict"] == "blocked" and not (isinstance(name, str) and name):
        return None
    return str(response["verdict"]), name if isinstance(name, str) else None


def _custom_block_response(
    harness: str, native_result: Mapping[str, object], name: str, guard_home: Path | None = None
) -> dict[str, object]:
    return _saved_block_response(
        harness,
        native_result,
        reason_code="local_cli_extension_blocked",
        reason=f"Your custom extension rules block this {name} command.",
        guard_home=guard_home,
    )


__all__ = ["native_local_cli_block_response", "native_local_cli_grant_response"]
