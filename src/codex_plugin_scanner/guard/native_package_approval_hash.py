"""Resident bridge for the ``package_approval_hash`` op.

The resident owns the package approval identity, the composed current policy
action and the approval-context artifact hash. This module only hydrates facts
the resident cannot read itself (the configuration fields the bound policy
view is built from, the Python execution context, the extension-control digest
and the cached feed snapshot hash), transports one request, and strictly
validates the reply. A missing,
mismatched or malformed answer raises :class:`NativePackageApprovalHashError`;
there is no Python fallback, so an unavailable resident can never produce a
weaker action or a forgeable hash.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

from .action_lattice import GuardAction
from .config import GuardConfig, risk_action_config_facts
from .native_context import _canonical_request_sha256, ensure_resident_prerequisite
from .native_package_authority import _REQUEST_SCHEMA, _RESULT_SCHEMA, _request_id, _resident_request

_APPROVAL_HASH_FEATURE = "package-approval-hash-v1"
_GUARD_ACTIONS = frozenset({"allow", "warn", "review", "require-reapproval", "sandbox-required", "block"})
_TOKEN_PREFIX = "guard-approval-context:v1:"
_MAX_REQUEST_BYTES = 4 * 1024 * 1024
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


def package_config_facts(config: GuardConfig | None) -> dict[str, object] | None:
    """The configuration fields the resident builds the bound policy view from.

    Sent instead of the finished view so the ``package_script`` action and the
    artifact/publisher/harness override folded into the composed action are
    resolved by the resident. The override maps and the managed-policy pair go
    over as they were loaded; ``None`` means no configuration is bound, and the
    caller sends ``{"available": False}`` as the view itself.
    """

    if config is None:
        return None
    return {
        **risk_action_config_facts(config),
        "artifact_actions": dict(config.artifact_actions) if config.artifact_actions is not None else None,
        "harness_actions": dict(config.harness_actions) if config.harness_actions is not None else None,
        "managed_policy_hash": config.managed_policy_hash,
        "managed_policy_status": config.managed_policy_status,
        "mode": config.mode,
        "publisher_actions": dict(config.publisher_actions) if config.publisher_actions is not None else None,
    }


def _feed_snapshot_hash(store: Any) -> str | None:
    workspace_id = store.get_cloud_workspace_id()
    if workspace_id is None:
        return None
    cached_bundle = store.get_cached_supply_chain_bundle(workspace_id)
    bundle = cached_bundle.get("bundle") if isinstance(cached_bundle, dict) else None
    value = bundle.get("feedSnapshotHash") if isinstance(bundle, dict) else None
    return value if isinstance(value, str) and value else None


def _view_item(item: object) -> object:
    if isinstance(item, Mapping):
        return dict(item)
    return item


def _view_value(value: object) -> object:
    if isinstance(value, (list, tuple)):
        return [_view_item(item) for item in value]
    return value


def _evaluation_view(evaluation: Any, fields: tuple[str, ...] = _EVALUATION_FIELDS) -> dict[str, object]:
    return {field: _view_value(getattr(evaluation, field)) for field in fields}


def _transport(
    request: dict[str, object],
    guard_home: Path,
    *,
    operation: str = "package_approval_hash",
    feature: str = _APPROVAL_HASH_FEATURE,
    error: type[RuntimeError] = NativePackageApprovalHashError,
    max_request_bytes: int = _MAX_REQUEST_BYTES,
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
        max_request_bytes=max_request_bytes,
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
    config_facts = package_config_facts(config)
    if config_facts is None:
        request["config_policy"] = {"available": False}
    else:
        request["config_facts"] = config_facts
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
    return cast(GuardAction, action), cast(str, artifact_hash)
