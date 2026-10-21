"""Honor custom-extension grants for paused native PreToolUse reviews."""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING

from ..native_local_cli_identity import LocalCliIdentityUnavailableError
from .hook_fail_closed import render_accepted_allow
from .hook_native_exact_action import launch_cwd as _launch_cwd
from .hook_native_saved_approval import _native_review_is_overridable, _saved_block_response, store_guard_home
from .hook_request_parsing import pre_tool_command

if TYPE_CHECKING:
    from ..models import GuardAction
    from ..runtime.local_cli_identity import UnlistedCliIdentity

_LOGGER = logging.getLogger(__name__)
# The one review a custom allow lifts: Rust did not recognise the program. Any
# other review carries a risk signal of its own (a secret operand, a network
# target), and the outside-roots review runs in the grant's sandbox instead.
_GRANT_LIFTABLE_REASON = "native_command_review_required"
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
    path does too. The identity lookup only runs while some custom block exists.
    """

    if native_result.get("minimum_action") != "allow" or not _has_block_rules(store):
        return None
    try:
        match = _matching_grant(store, payload=payload, workspace=workspace, home_dir=home_dir, current_action="allow")
    except LocalCliIdentityUnavailableError:
        # A block rule exists and this command's identity cannot be checked.
        return _saved_block_response(
            harness,
            native_result,
            reason_code="local_cli_extension_unverified",
            reason="Guard could not check this command against your custom extension rules.",
            guard_home=store_guard_home(store),
        )
    if match is None or match[1] != "blocked":
        return None
    return _custom_block_response(harness, native_result, match[0].name, store_guard_home(store))


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
        # Fail toward checking: the grant lookup itself is still bounded.
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
    """

    if native_result.get("policy_action") not in {"review", "require-reapproval"}:
        return None
    try:
        match = _matching_grant(store, payload=payload, workspace=workspace, home_dir=home_dir, current_action="review")
    except LocalCliIdentityUnavailableError:
        return None
    if match is None:
        return None
    identity, state = match
    if state == "blocked":
        return True, _custom_block_response(harness, native_result, identity.name, store_guard_home(store))
    if native_result.get("reason_code") != _GRANT_LIFTABLE_REASON or not _native_review_is_overridable(native_result):
        return None
    allowed = dict(native_result)
    allowed.update(decision="allow", minimum_action="allow", policy_action="allow")
    return False, render_accepted_allow(harness, allowed, guard_home=store_guard_home(store))


def _matching_grant(
    store: object,
    *,
    payload: Mapping[str, object],
    workspace: Path | None,
    home_dir: Path | None,
    current_action: GuardAction,
) -> tuple[UnlistedCliIdentity, str] | None:
    command = pre_tool_command(payload)
    cwd = _launch_cwd(payload, workspace)
    if command is None or cwd is None:
        return None
    from ..local_cli_trust import matching_local_cli_grant

    try:
        return matching_local_cli_grant(
            store=store,
            command=command,
            cwd=cwd,
            home_dir=home_dir,
            current_action=current_action,
        )
    except LocalCliIdentityUnavailableError:
        raise
    except Exception:
        _LOGGER.warning("custom extension grant lookup failed", exc_info=True)
        return None


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
