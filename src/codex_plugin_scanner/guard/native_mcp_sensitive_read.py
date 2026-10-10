"""Transport for the native sensitive-file-read decision owner.

The stdio proxy used to compose the sensitive-read verdict in Python. The
resident now owns every verdict, token and message: the current action, the
exact-context approval token, how a saved approval composes with the
recomputed action (including the claim and the rebuilt post-claim context) and
the response for a read that is not forwarded. This module only gathers the
facts the resident asks about and transports the answer; it never recomputes
or overrides a verdict. Anything but a bound, well-formed answer raises
``NativeMcpProxyDecisionError`` so callers fail closed.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .config import GuardConfig, resolve_risk_action
from .consumer import artifact_hash
from .harness_posture import config_for_harness, harness_posture_override
from .models import GuardArtifact
from .native_context import _resolve_digest_home
from .native_mcp_proxy_decision import NativeMcpProxyDecisionError, native_mcp_proxy_decide


def _config_facts(config: object, *, artifact: GuardArtifact, harness: str) -> dict[str, object] | None:
    if not isinstance(config, GuardConfig):
        return None
    view = config_for_harness(config, harness)
    return {
        "view_override": view.resolve_action_override(harness, artifact.artifact_id, artifact.publisher),
        "view_default_action": view.default_action,
        "risk_action": resolve_risk_action(view, "local_secret_read", harness=harness),
        "artifact_override": config.resolve_action_override(artifact.harness, artifact.artifact_id, artifact.publisher),
        "default_action": config.default_action,
        "managed_locked_settings": list(config.managed_locked_settings),
        "managed_policy_hash": config.managed_policy_hash,
        "managed_policy_status": config.managed_policy_status,
        "mode": config.mode,
        "protection_posture": config.protection_posture,
        "protection_posture_explicit": bool(config.protection_posture_explicit),
        "security_level": config.security_level,
        "harness_posture": harness_posture_override(config, artifact.harness),
        "sandbox_analysis": config.sandbox_analysis,
    }


def _workspace(cwd: Path | None) -> str:
    effective = cwd or Path.cwd()
    try:
        return str(effective.expanduser().resolve(strict=False))
    except (OSError, RuntimeError):
        return str(effective.expanduser().absolute())


def context_query(
    artifact: GuardArtifact,
    *,
    config: object,
    cwd: Path | None,
    harness: str,
    server_launch_identity: Mapping[str, object] | None,
    configured_env_values_hash: str | None,
) -> dict[str, object]:
    """The facts the resident needs to derive one read's action and approval token."""

    from .runtime.extension_control_runtime import current_extension_control_binding_digest

    return {
        "check": "sensitive_read_context",
        "config": _config_facts(config, artifact=artifact, harness=harness),
        "identity": {
            "artifact_id": artifact.artifact_id,
            "config_path": artifact.config_path,
            "harness": artifact.harness,
            "publisher": artifact.publisher,
            "source_scope": artifact.source_scope,
            "server_launch_identity": dict(server_launch_identity or {}),
            "configured_env_values_hash": configured_env_values_hash,
            "workspace": _workspace(cwd),
        },
        "content": artifact_hash(artifact),
        "capabilities": {
            "artifact_type": artifact.artifact_type,
            "path_class": artifact.metadata.get("path_class"),
            "tool_name": artifact.metadata.get("tool_name"),
        },
        "extension_control_digest": current_extension_control_binding_digest(),
    }


def _text(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise NativeMcpProxyDecisionError("native_mcp_proxy_decision_payload_invalid")
    return value


def sensitive_read_context(
    artifact: GuardArtifact,
    *,
    config: object,
    cwd: Path | None,
    harness: str,
    server_launch_identity: Mapping[str, object] | None = None,
    configured_env_values_hash: str | None = None,
    guard_home: Path | None = None,
) -> tuple[str, str]:
    """The resident's current action and exact-context approval token for one read."""

    query = context_query(
        artifact,
        config=config,
        cwd=cwd,
        harness=harness,
        server_launch_identity=server_launch_identity,
        configured_env_values_hash=configured_env_values_hash,
    )
    payload = native_mcp_proxy_decide(query, guard_home=_resolve_digest_home(guard_home))
    return _text(payload, "current_action"), _text(payload, "artifact_hash")


def lookup_facts(policy_lookup: Mapping[str, Any] | None, diagnosed_reason: str | None) -> dict[str, object] | None:
    """The policy-store lookup for one context hash; ``None`` without a store."""

    if policy_lookup is None:
        return None
    decision = policy_lookup["decision"]
    return {
        "decision_present": decision is not None,
        "decision_action": decision.get("action") if decision is not None else None,
        "decision_artifact_hash": decision.get("artifact_hash") if decision is not None else None,
        "ignored_integrity": policy_lookup["ignored_local_integrity"] is not None,
        "diagnosed_reason": diagnosed_reason,
    }


def sensitive_read_reuse(
    *,
    stage: str,
    current_action: str,
    artifact_hash_value: str,
    lookup: dict[str, object] | None,
    claimed_allow_hash: str | None,
    tool_name: str,
    path_class: str,
    asks_for_approval: bool,
    approval_center_present: bool,
    store_present: bool,
    guard_home: Path,
) -> dict[str, Any]:
    """The resident's composition of a saved approval with the recomputed action."""

    payload = native_mcp_proxy_decide(
        {
            "check": "sensitive_read_reuse",
            "stage": stage,
            "current_action": current_action,
            "artifact_hash": artifact_hash_value,
            "lookup": lookup,
            "claimed_allow_hash": claimed_allow_hash,
            "tool_name": tool_name,
            "path_class": path_class,
            "asks_for_approval": asks_for_approval,
            "approval_center_present": approval_center_present,
            "store_present": store_present,
        },
        guard_home=guard_home,
    )
    _text(payload, "policy_action")
    return payload


def sensitive_read_hint(
    *,
    policy_action: str,
    message: str,
    approval_summary: object,
    review_url: str,
    guard_home: Path,
) -> tuple[str, str]:
    """The review hint and the not-forwarded message that carries it."""

    payload = native_mcp_proxy_decide(
        {
            "check": "sensitive_read_hint",
            "policy_action": policy_action,
            "message": message,
            "approval_summary": str(approval_summary),
            "review_url": review_url,
        },
        guard_home=guard_home,
    )
    return _text(payload, "review_hint"), _text(payload, "message")
