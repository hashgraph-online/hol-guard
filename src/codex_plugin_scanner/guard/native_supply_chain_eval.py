"""Strict resident transport for package supply-chain evaluation.

The resident owns every package verdict: advisory, bundle, lockfile, Cloud and
heuristic decisions. Python sends the artifact, the workspace and the store
location, verifies that the reply is bound to the exact request it sent, and
hydrates the ``PackageRequestEvaluation`` DTO from it. There is no Python
evaluation fallback. A missing, mismatched or malformed native answer yields a
constant block evaluation, so an unavailable resident can only tighten a
package request and never allow one.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TypeGuard

from .models import GuardArtifact
from .native_context import _canonical_request_sha256, ensure_resident_prerequisite
from .native_package_authority import (
    _REQUEST_SCHEMA,
    _RESULT_SCHEMA,
    _request_id,
    _resident_request,
    evaluation_from_native_payload,
)

SUPPLY_CHAIN_EVAL_FEATURE = "supply-chain-eval-v1"
_EVAL_TIMEOUT_SECONDS = 25.0
_UNAVAILABLE_CODE = "native_supply_chain_eval_unavailable"
_UNAVAILABLE_MESSAGE = (
    "HOL Guard blocked this package request because its native package policy engine was unavailable."
)
_RESULT_KEYS = frozenset({"schema", "request_id", "request_sha256", "status", "code", "payload"})
_PAYLOAD_DECISIONS = frozenset({"allow", "monitor", "warn", "ask", "block"})
_PAYLOAD_TEXT_KEYS = (
    "policy_action",
    "enforcement",
    "entitlement_state",
    "cache_status",
    "package_intent_hash",
    "policy_version",
    "risk_summary",
)


class NativeSupplyChainEvalError(RuntimeError):
    """No authoritative native package evaluation was available."""


def _now_text(now: str | None) -> str:
    return now if isinstance(now, str) else datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _payload_is_complete(payload: object) -> TypeGuard[dict[str, Any]]:
    if not isinstance(payload, dict):
        return False
    if payload.get("decision") not in _PAYLOAD_DECISIONS:
        return False
    if not all(isinstance(payload.get(key), str) for key in _PAYLOAD_TEXT_KEYS):
        return False
    if not all(isinstance(payload.get(key), list) for key in ("reasons", "packages")):
        return False
    user_copy = payload.get("user_copy")
    return isinstance(user_copy, dict) and all(
        isinstance(user_copy.get(key), str) for key in ("title", "summary", "harness_message")
    )


def native_supply_chain_eval_payload(
    *,
    artifact: GuardArtifact,
    store_path: Path,
    guard_home: Path,
    workspace_dir: Path | None,
    now: str | None,
    external_archive_network_authorized: bool,
) -> dict[str, Any]:
    """Return the resident's bound evaluation payload or raise ``NativeSupplyChainEvalError``."""

    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": _request_id(),
        "store_path": str(store_path),
        "guard_home": str(guard_home),
        "artifact": artifact.to_dict(),
        "external_archive_network_authorized": bool(external_archive_network_authorized),
        "retain_external_archive_blob": False,
    }
    # The resident digests its typed request, which omits absent optional
    # fields, so an absent value must be omitted here rather than sent as null.
    if workspace_dir is not None:
        request["workspace_dir"] = str(workspace_dir)
    if now is not None:
        request["now"] = now
    private_metadata = getattr(artifact, "runtime_private_metadata", None)
    if private_metadata:
        request["runtime_private_metadata"] = dict(private_metadata)
    try:
        request_sha256 = "sha256:" + _canonical_request_sha256(request)
    except (TypeError, ValueError) as error:
        raise NativeSupplyChainEvalError("Native package evaluation request invalid") from error
    if not ensure_resident_prerequisite(guard_home):
        raise NativeSupplyChainEvalError("Native package evaluation unavailable")
    response = _resident_request(
        operation="supply_chain_eval",
        request=request,
        guard_home=guard_home,
        timeout_seconds=_EVAL_TIMEOUT_SECONDS,
        required_features=(SUPPLY_CHAIN_EVAL_FEATURE,),
    )
    if (
        not isinstance(response, dict)
        or not set(response) <= _RESULT_KEYS
        or response.get("schema") != _RESULT_SCHEMA
        or response.get("request_id") != request["request_id"]
        or response.get("request_sha256") != request_sha256
        or response.get("status") != "ok"
        or response.get("code") != "ok"
    ):
        raise NativeSupplyChainEvalError("Native package evaluation unavailable or invalid")
    payload = response.get("payload")
    if not _payload_is_complete(payload):
        raise NativeSupplyChainEvalError("Native package evaluation payload invalid")
    return payload


def unavailable_block_evaluation(artifact: GuardArtifact) -> Any:
    """Constant fail-closed block; it is not a verdict computation."""

    from .runtime.supply_chain_package_eval import PackageRequestEvaluation, SupplyChainUserCopy

    reason: dict[str, object] = {
        "code": _UNAVAILABLE_CODE,
        "message": _UNAVAILABLE_MESSAGE,
        "severity": "high",
        "source": "guard-local",
    }
    return PackageRequestEvaluation(
        decision="block",
        policy_action="block",
        enforcement="free_local",
        entitlement_state="free",
        cache_status="miss",
        package_intent_hash=str(artifact.artifact_id),
        policy_version="native-unavailable",
        bundle_version=None,
        workspace_fingerprint=None,
        reasons=(reason,),
        packages=(),
        risk_summary=_UNAVAILABLE_MESSAGE,
        user_copy=SupplyChainUserCopy(
            title="Package request blocked",
            summary=_UNAVAILABLE_MESSAGE,
            next_step="Restart HOL Guard or run `hol-guard doctor`, then retry.",
            dashboard_url=None,
            harness_message=_UNAVAILABLE_MESSAGE,
        ),
    )


def evaluate_package_request_native(
    *,
    artifact: GuardArtifact,
    store: Any,
    workspace_dir: Path | None,
    now: str | None = None,
    external_archive_network_authorized: bool = False,
) -> Any:
    """Evaluate one package request in the resident; fail closed when it cannot answer."""

    guard_home = getattr(store, "guard_home", None)
    store_path = getattr(store, "path", None)
    if not isinstance(guard_home, Path) or not isinstance(store_path, Path):
        return unavailable_block_evaluation(artifact)
    try:
        payload = native_supply_chain_eval_payload(
            artifact=artifact,
            store_path=store_path,
            guard_home=guard_home,
            workspace_dir=workspace_dir,
            now=now,
            external_archive_network_authorized=external_archive_network_authorized,
        )
        evaluation = evaluation_from_native_payload(payload)
    except (NativeSupplyChainEvalError, TypeError, ValueError, KeyError, AttributeError):
        return unavailable_block_evaluation(artifact)
    from .runtime.supply_chain_package_eval import _persist_evidence

    _persist_evidence(store=store, artifact=artifact, evaluation=evaluation, now=_now_text(now))
    return evaluation


__all__ = [
    "SUPPLY_CHAIN_EVAL_FEATURE",
    "NativeSupplyChainEvalError",
    "evaluate_package_request_native",
    "native_supply_chain_eval_payload",
    "unavailable_block_evaluation",
]
