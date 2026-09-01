"""Typed request coercion shared by the isolated resident hook process."""

from __future__ import annotations

from argparse import Namespace
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from .hook_process_protocol import HOOK_ENV_ALLOWLIST, as_string_object_dict

if TYPE_CHECKING:
    from ..adapters.base import HarnessContext
    from ..store import GuardStore


def build_hook_process_review_request(
    *,
    payload: Mapping[str, object],
    harness: str,
    home_dir: Path,
    guard_home: Path,
    workspace: Path | None,
    hook_env: Mapping[str, str],
    claim_saved_approval: bool,
    claimed_saved_allow_hash: str | None,
    claimed_trusted_request_override: bool,
    claimed_approval_request_id: str | None,
    native_minimum_action: str | None = None,
) -> dict[str, object]:
    return {
        "payload": dict(payload),
        "harness": harness,
        "home_dir": str(home_dir),
        "guard_home": str(guard_home),
        "workspace": str(workspace) if workspace is not None else None,
        "hook_env": {key: value for key, value in hook_env.items() if key in HOOK_ENV_ALLOWLIST},
        "claim_saved_approval": claim_saved_approval,
        "claimed_saved_allow_hash": claimed_saved_allow_hash,
        "claimed_trusted_request_override": claimed_trusted_request_override,
        "claimed_approval_request_id": claimed_approval_request_id,
        "native_minimum_action": native_minimum_action,
    }


def runtime_hook_review_is_idempotent(payload: Mapping[str, object]) -> bool:
    event_name = payload.get("hook_event_name") or payload.get("hookEventName")
    if not isinstance(event_name, str):
        return False
    return any(
        isinstance(payload.get(identity_key), str) and bool(payload.get(identity_key))
        for identity_key in ("tool_call_id", "toolCallId", "action_id", "operation_id")
    )


@dataclass(frozen=True)
class ResidentHookRequest:
    payload: dict[str, object]
    harness: str
    home_dir: Path
    guard_home: Path
    workspace: Path | None
    claim_saved_approval: bool
    claimed_saved_allow_hash: str | None
    claimed_trusted_request_override: bool
    claimed_approval_request_id: str | None
    native_minimum_action: str | None


def coerce_resident_hook_request(request: dict[str, object]) -> ResidentHookRequest | None:
    payload = request.get("payload")
    harness = request.get("harness")
    home_value = request.get("home_dir")
    guard_home_value = request.get("guard_home")
    workspace_value = request.get("workspace")
    claim_saved_approval = request.get("claim_saved_approval", True)
    claimed_saved_allow_hash = request.get("claimed_saved_allow_hash")
    claimed_trusted_request_override = request.get("claimed_trusted_request_override", False)
    claimed_approval_request_id = request.get("claimed_approval_request_id")
    native_minimum_action = request.get("native_minimum_action")
    typed_payload = as_string_object_dict(payload)
    if typed_payload is None or not isinstance(harness, str):
        return None
    if not isinstance(home_value, str) or not isinstance(guard_home_value, str):
        return None
    if workspace_value is not None and not isinstance(workspace_value, str):
        return None
    if not isinstance(claim_saved_approval, bool) or not isinstance(claimed_trusted_request_override, bool):
        return None
    if claimed_saved_allow_hash is not None and not isinstance(claimed_saved_allow_hash, str):
        return None
    if claimed_approval_request_id is not None and not isinstance(claimed_approval_request_id, str):
        return None
    if native_minimum_action not in {None, "review"}:
        return None
    typed_native_minimum_action = native_minimum_action if isinstance(native_minimum_action, str) else None
    return ResidentHookRequest(
        payload=typed_payload,
        harness=harness,
        home_dir=Path(home_value),
        guard_home=Path(guard_home_value).resolve(strict=False),
        workspace=Path(workspace_value) if isinstance(workspace_value, str) else None,
        claim_saved_approval=claim_saved_approval,
        claimed_saved_allow_hash=claimed_saved_allow_hash,
        claimed_trusted_request_override=claimed_trusted_request_override,
        claimed_approval_request_id=claimed_approval_request_id,
        native_minimum_action=typed_native_minimum_action,
    )


def resident_hook_store_and_context(
    parsed: ResidentHookRequest,
    stores: dict[str, GuardStore],
) -> tuple[GuardStore, HarnessContext]:
    """Return the cached store and request context for one resident hook."""

    from ..adapters.base import HarnessContext
    from ..store import GuardStore

    store_key = str(parsed.guard_home)
    store = stores.get(store_key)
    if store is None:
        store = GuardStore(
            parsed.guard_home,
            prime_policy_integrity=False,
            daemon_managed_schema=True,
        )
        stores[store_key] = store
    context = HarnessContext(
        home_dir=parsed.home_dir,
        workspace_dir=parsed.workspace,
        guard_home=parsed.guard_home,
        home_override_explicit=True,
        workspace_override_explicit=parsed.workspace is not None,
    )
    return store, context


def compatibility_hook_args(parsed: ResidentHookRequest) -> Namespace:
    """Build the private CLI namespace used by the explicit compatibility path."""

    return Namespace(
        guard_command="hook",
        home=str(parsed.home_dir),
        guard_home=str(parsed.guard_home),
        workspace=str(parsed.workspace) if parsed.workspace is not None else None,
        runtime_harness=parsed.harness,
        harness=parsed.harness,
        artifact_id=None,
        artifact_name=None,
        policy_action=parsed.native_minimum_action,
        native_minimum_action=parsed.native_minimum_action,
        event_file=None,
        json=True,
    )


__all__ = [
    "ResidentHookRequest",
    "build_hook_process_review_request",
    "coerce_resident_hook_request",
    "compatibility_hook_args",
    "resident_hook_store_and_context",
    "runtime_hook_review_is_idempotent",
]
