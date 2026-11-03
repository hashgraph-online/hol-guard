"""Bind live Codex completion to the exact action and current policy result."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import cast

from .native_hook_adapter import NativeHookAdapterError
from .native_hook_artifact_compose import NativeHookComposeError, native_hook_compose

FreshHookReviewer = Callable[
    [dict[str, object], Path | None, str | None, str | None],
    Mapping[str, object] | None,
]


def _text(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _mapping(value: object) -> dict[str, object] | None:
    return dict(cast(Mapping[str, object], value)) if isinstance(value, Mapping) else None


def _hook_payload(payload: Mapping[str, object]) -> dict[str, object] | None:
    raw_hook_input = payload.get("hook_input")
    if not isinstance(raw_hook_input, str):
        return None
    try:
        decoded = cast(object, json.loads(raw_hook_input))
    except json.JSONDecodeError:
        return None
    return cast(dict[str, object], decoded) if isinstance(decoded, dict) else None


def revalidate_codex_live_allow(
    request: object,
    payload: Mapping[str, object],
    *,
    home_dir: Path,
    guard_home: Path | None = None,
    reviewer: FreshHookReviewer,
    previous: object = None,
    request_id: str | None = None,
    authority_resolved: bool = False,
) -> bool:
    """Return true only when the exact original action is freshly allowed.

    Whether the payload still names the approved action, what saved allow the
    fresh review may claim, and whether that review authorizes the completion
    are all answered by the resident. This side decodes the payload, rebuilds
    the envelope and runs the review between the two answers, because the
    reviewer re-enters the hook pipeline the resident cannot call back into.
    """

    # Importing this CLI facade while daemon.server is still initializing
    # reaches back through _commands_shared to GuardDaemonServer. Defer the
    # dependency until request handling so daemon imports remain order-safe.
    from .cli.commands_support_hook_payload import _action_envelope_json, _hook_action_envelope

    request_mapping: Mapping[str, object] = cast(Mapping[str, object], request) if isinstance(request, Mapping) else {}
    previous_mapping: Mapping[str, object] = (
        cast(Mapping[str, object], previous) if isinstance(previous, Mapping) else {}
    )
    hook_payload = _hook_payload(payload)
    workspace_value = request_mapping.get("workspace")
    workspace = Path(workspace_value) if isinstance(workspace_value, str) and workspace_value else None

    fresh_envelope: dict[str, object] | None = None
    if hook_payload is not None:
        try:
            envelope = _hook_action_envelope(
                harness="codex",
                payload=hook_payload,
                home_dir=home_dir,
                workspace=workspace,
                guard_home=guard_home,
            )
        except (NativeHookAdapterError, ValueError):
            # Every live decision reaches here, a deny included, and the
            # envelope is only ever evidence for the resident's precheck. An
            # adapter that cannot build one must not escape into the daemon
            # handler, or the completion the harness is waiting on is never
            # written. An absent envelope is the fail-closed input: the
            # resident refuses the fresh allow on it, and Python makes no
            # judgement of its own.
            envelope = None
        if envelope is not None:
            fresh_envelope = _mapping(_action_envelope_json(envelope))

    try:
        precheck = native_hook_compose(
            "codex_live_allow_precheck",
            {
                "resolution_action": _text(request_mapping.get("resolution_action")),
                "artifact_hash": _text(request_mapping.get("artifact_hash")),
                "row_request_id": _text(request_mapping.get("request_id")),
                "stored_envelope": _mapping(request_mapping.get("action_envelope_json")),
                "previous_resolution_action": _text(previous_mapping.get("resolution_action")),
                "previous_status": _text(previous_mapping.get("status")),
                "request_id": request_id,
                "authority_resolved": authority_resolved,
                "hook_event_name": _text(hook_payload.get("hook_event_name")) if hook_payload else None,
                "fresh_envelope": fresh_envelope,
            },
            guard_home=guard_home,
        )
    except NativeHookComposeError:
        return False
    if precheck.get("review_required") is not True or hook_payload is None:
        return False

    claimed_saved_allow_hash = _text(precheck.get("claimed_saved_allow_hash"))
    claimed_approval_request_id = _text(precheck.get("claimed_approval_request_id"))
    try:
        fresh_review = reviewer(
            hook_payload,
            workspace,
            claimed_saved_allow_hash,
            claimed_approval_request_id,
        )
    except Exception:
        fresh_review = None

    try:
        settled = native_hook_compose(
            "codex_live_allow_settle",
            {"fresh_review": _mapping(fresh_review)},
            guard_home=guard_home,
        )
    except NativeHookComposeError:
        return False
    return settled.get("fresh_allow_authorized") is True


__all__ = ["FreshHookReviewer", "revalidate_codex_live_allow"]
