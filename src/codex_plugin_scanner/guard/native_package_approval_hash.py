"""Resident bridge for the ``package_approval_hash`` op.

The resident owns the package approval identity, the composed current policy
action and the approval-context artifact hash. This module only hydrates facts
the resident cannot read itself (the bound ``GuardConfig`` view, the Python
execution context, the extension-control digest and the cached feed snapshot
hash), transports one request, and strictly validates the reply. A missing,
mismatched or malformed answer raises :class:`NativePackageApprovalHashError`;
there is no Python fallback, so an unavailable resident can never produce a
weaker action or a forgeable hash.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .action_lattice import GuardAction
from .config import GuardConfig, resolve_risk_action
from .native_context import _canonical_request_sha256, _resolve_digest_home, ensure_resident_prerequisite
from .native_package_authority import _REQUEST_SCHEMA, _RESULT_SCHEMA, _request_id, _resident_request

_APPROVAL_HASH_FEATURE = "package-approval-hash-v1"
_GUARD_ACTIONS = frozenset({"allow", "warn", "review", "require-reapproval", "sandbox-required", "block"})
_TOKEN_PREFIX = "guard-approval-context:v1:"
_EVALUATION_FIELDS = (
    "bundle_version",
    "decision",
    "enforcement",
    "entitlement_state",
    "exception_id",
    "matched_rule_id",
    "packages",
    "policy_action",
    "policy_version",
    "reasons",
)


class NativePackageApprovalHashError(RuntimeError):
    """No authoritative native approval-hash result was available."""


def package_config_policy_context(*, artifact: Any, config: GuardConfig | None) -> dict[str, object]:
    """Hydrate the bound ``GuardConfig`` view the resident folds into policy."""

    if config is None:
        return {"available": False}
    harness_package_script_action = (config.harness_risk_actions or {}).get(artifact.harness, {}).get("package_script")
    artifact_override = (config.artifact_actions or {}).get(artifact.artifact_id)
    publisher_override = (
        (config.publisher_actions or {}).get(artifact.publisher) if artifact.publisher is not None else None
    )
    harness_override = (config.harness_actions or {}).get(artifact.harness)
    return {
        "artifact_override": artifact_override,
        "available": True,
        "effective_package_script_action": resolve_risk_action(
            config,
            "package_script",
            harness=artifact.harness,
        ),
        "global_package_script_action": resolve_risk_action(config, "package_script", harness=None),
        "harness": artifact.harness,
        "harness_override": harness_override,
        "harness_package_script_action": harness_package_script_action,
        "managed_locked_settings": list(config.managed_locked_settings),
        "managed_policy_hash": config.managed_policy_hash,
        "managed_policy_status": config.managed_policy_status,
        "mode": config.mode,
        "publisher_override": publisher_override,
        "resolved_override": config.resolve_action_override(
            artifact.harness,
            artifact.artifact_id,
            artifact.publisher,
        ),
        "security_level": config.security_level,
    }


def _feed_snapshot_hash(store: Any) -> str | None:
    workspace_id = store.get_cloud_workspace_id()
    if workspace_id is None:
        return None
    cached_bundle = store.get_cached_supply_chain_bundle(workspace_id)
    bundle = cached_bundle.get("bundle") if isinstance(cached_bundle, dict) else None
    value = bundle.get("feedSnapshotHash") if isinstance(bundle, dict) else None
    return value if isinstance(value, str) and value else None


def _evaluation_view(evaluation: Any, fields: tuple[str, ...] = _EVALUATION_FIELDS) -> dict[str, object]:
    view: dict[str, object] = {}
    for field in fields:
        value = getattr(evaluation, field)
        view[field] = (
            [dict(item) if isinstance(item, Mapping) else item for item in value]
            if isinstance(value, (list, tuple))
            else value
        )
    return view


def _transport(
    request: dict[str, object],
    guard_home: Path,
    *,
    operation: str = "package_approval_hash",
    feature: str = _APPROVAL_HASH_FEATURE,
    error: type[RuntimeError] = NativePackageApprovalHashError,
) -> dict[str, Any]:
    """Send one package-authority request and return the strictly checked payload."""

    request["schema"] = _REQUEST_SCHEMA
    request["request_id"] = _request_id()
    request["guard_home"] = str(guard_home)
    try:
        request_sha256 = "sha256:" + _canonical_request_sha256(request)
    except (TypeError, ValueError) as cause:
        raise error(f"Native {operation} request invalid") from cause
    if not ensure_resident_prerequisite(guard_home):
        raise error(f"Native {operation} unavailable")
    response = _resident_request(
        operation=operation,
        request=request,
        guard_home=guard_home,
        timeout_seconds=2.0,
        required_features=(feature,),
    )
    if (
        not isinstance(response, dict)
        or response.get("schema") != _RESULT_SCHEMA
        or response.get("request_id") != request["request_id"]
        or response.get("request_sha256") != request_sha256
        or response.get("status") != "ok"
        or response.get("code") != "ok"
    ):
        raise error(f"Native {operation} unavailable or invalid")
    payload = response.get("payload")
    if not isinstance(payload, dict):
        raise error(f"Native {operation} payload invalid")
    return payload


def native_package_current_action(
    *,
    artifact: Any,
    evaluation: Any,
    config: GuardConfig | None,
    additional_current_action: object | None = None,
) -> GuardAction:
    """Return the resident-composed feed and configuration policy action."""

    request: dict[str, object] = {
        "kind": "current_action",
        "artifact": artifact.to_dict(),
        "evaluation": _evaluation_view(evaluation),
        "config_policy": package_config_policy_context(artifact=artifact, config=config),
    }
    if additional_current_action is not None:
        request["additional_current_action"] = additional_current_action
    payload = _transport(request, _resolve_digest_home(None))
    action = payload.get("current_action")
    if action not in _GUARD_ACTIONS:
        raise NativePackageApprovalHashError("Native package approval hash action invalid")
    return action  # type: ignore[return-value]


def native_package_approval_hash(
    *,
    artifact: Any,
    store: Any,
    workspace_dir: Path,
    evaluation: Any,
    execution_context: Any,
    launch_identity: Mapping[str, object] | None,
    config: GuardConfig | None,
    additional_current_action: object | None = None,
    additional_policy_context: dict[str, object] | None = None,
) -> tuple[GuardAction, str]:
    """Return the resident's composed action and approval-context token in one call."""

    from .native_policy_snapshot_publisher import provision_native_verifier_key_for_store
    from .runtime.extension_control_runtime import current_extension_control_binding_digest

    provision_native_verifier_key_for_store(store)
    request: dict[str, object] = {
        "kind": "artifact_hash",
        "artifact": artifact.to_dict(),
        "evaluation": _evaluation_view(evaluation),
        "config_policy": package_config_policy_context(artifact=artifact, config=config),
        "sandbox_analysis": config.sandbox_analysis if config is not None else "unknown",
        "store_path": str(store.path),
        "workspace_dir": str(workspace_dir),
        "execution_context": {
            "digest": execution_context.digest,
            "version": execution_context.version,
            "components": [
                {"name": component.name, "digest": component.digest} for component in execution_context.components
            ],
        },
        "extension_control_digest": current_extension_control_binding_digest(),
    }
    feed_snapshot_hash = _feed_snapshot_hash(store)
    for key, value in (
        ("additional_current_action", additional_current_action),
        ("additional_policy_context", additional_policy_context),
        ("launch_identity", dict(launch_identity) if launch_identity is not None else None),
        ("feed_snapshot_hash", feed_snapshot_hash),
    ):
        if value is not None:
            request[key] = value
    payload = _transport(request, Path(store.guard_home))
    action = payload.get("current_action")
    artifact_hash = payload.get("artifact_hash")
    token_valid = isinstance(artifact_hash, str) and artifact_hash.startswith(_TOKEN_PREFIX)
    if action not in _GUARD_ACTIONS or not token_valid:
        raise NativePackageApprovalHashError("Native package approval hash result invalid")
    return action, artifact_hash  # type: ignore[return-value]
