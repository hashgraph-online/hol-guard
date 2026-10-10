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

import json
import os
from collections.abc import Callable
from contextlib import ExitStack
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
from .native_runtime import native_runtime_status
from .native_runtime_resilience import native_record_resident_failure
from .native_supply_chain_egress import EGRESS_REQUIRED_CODE, EgressExchanger, EgressProtocolError, private_spool_dir

SUPPLY_CHAIN_EVAL_FEATURE = "supply-chain-eval-v1"
# Replayed egress outcomes (up to EGRESS_MAX_SUPPLIED) ride in every round's request, so the
# generic 256 KiB package-authority cap is too small; stay under the native 6 MiB frame cap.
_EVAL_MAX_REQUEST_BYTES = 4 * 1024 * 1024
_EVAL_TIMEOUT_SECONDS = 25.0
_PROBE_REQUIRED_CODE = "saved_policy_probe_required"
# Each round either performs the exchanges the resident asked for or answers its
# saved-policy question. The resident collects every registry lookup of a round
# at once, so a normal evaluation settles in a handful of rounds.
_MAX_ROUNDS = 24
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


_TEST_SEAM_MAX_BYTES = 8192
_TEST_AUTH_KEYS = frozenset({"sync_url", "access_token", "issuer", "dpop_key_material", "error"})


# Tests assign ``{metadata_url: registry_json_object | None}`` (monkeypatched) to
# resolve package ranges without network. Only forwarded under pytest.
_test_registry_metadata_override: dict[str, object] | None = None


def _test_seam_overrides() -> dict[str, object]:
    """Return pytest-only Cloud seam overrides for the resident request.

    Production never forwards anything: the gate is ``PYTEST_CURRENT_TEST``, and
    the resident independently ignores the fields unless it was started with
    the dedicated ``HOL_GUARD_RESIDENT_TEST_SEAMS`` opt-in (diagnostics alone
    never enable them). The values are the same hermetic Cloud auth and
    entitlement fixtures the Python resolver honored, plus public-registry
    metadata fixtures keyed by metadata URL, restricted to a small known-key,
    bounded JSON shape.
    """

    if not os.environ.get("PYTEST_CURRENT_TEST"):
        return {}
    overrides: dict[str, object] = {}
    auth: object | None = None
    from .runtime import runner

    module_override = getattr(runner, "_test_sync_auth_context_override", None)
    if isinstance(module_override, dict):
        auth = dict(module_override)
    else:
        raw_auth = os.environ.get("HOL_GUARD_TEST_SYNC_AUTH_CONTEXT_JSON")
        if raw_auth is not None and len(raw_auth) <= _TEST_SEAM_MAX_BYTES:
            try:
                auth = json.loads(raw_auth)
            except json.JSONDecodeError:
                auth = None
    if isinstance(auth, dict) and set(auth) <= _TEST_AUTH_KEYS:
        unreachable = os.environ.get("HOL_GUARD_TEST_CLOUD_UNREACHABLE_URL")
        if unreachable is not None and len(unreachable) <= _TEST_SEAM_MAX_BYTES:
            auth["sync_url"] = unreachable
        overrides["sync_auth_context_override"] = auth
    raw_entitlement = os.environ.get("HOL_GUARD_TEST_PACKAGE_ENTITLEMENT_JSON")
    if raw_entitlement is not None and len(raw_entitlement) <= _TEST_SEAM_MAX_BYTES:
        try:
            entitlement = json.loads(raw_entitlement)
        except json.JSONDecodeError:
            entitlement = None
        if isinstance(entitlement, dict):
            overrides["package_entitlement_override"] = entitlement
    registry = _test_registry_metadata_override
    if isinstance(registry, dict) and len(json.dumps(registry)) <= _TEST_SEAM_MAX_BYTES:
        overrides["registry_metadata_override"] = dict(registry)
    return overrides


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


def _bound_response(response: object, request: dict[str, object], request_sha256: str) -> dict[str, Any]:
    if (
        not isinstance(response, dict)
        or not set(response) <= _RESULT_KEYS
        or response.get("schema") != _RESULT_SCHEMA
        or response.get("request_id") != request["request_id"]
        or response.get("request_sha256") != request_sha256
    ):
        raise NativeSupplyChainEvalError("Native package evaluation unavailable or invalid")
    return response


def _record_unbound_answer(guard_home: Path) -> None:
    """An answer not bound to this request is a resident failure, not a success."""
    identity = native_runtime_status().identity
    if identity is not None:
        native_record_resident_failure(identity.sha256, guard_home, reason="native_supply_chain_eval_unbound")


def _send_eval_request(request: dict[str, object], guard_home: Path) -> dict[str, Any]:
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
        max_request_bytes=_EVAL_MAX_REQUEST_BYTES,
    )
    if response is None:
        # `_resident_request` already recorded why (transport, schema) or that the
        # resident refused; recording again would double-count one failure.
        raise NativeSupplyChainEvalError("Native package evaluation unavailable or invalid")
    try:
        return _bound_response(response, request, request_sha256)
    except NativeSupplyChainEvalError:
        _record_unbound_answer(guard_home)
        raise


def native_supply_chain_eval_payload(
    *,
    artifact: GuardArtifact,
    store_path: Path,
    guard_home: Path,
    workspace_dir: Path | None,
    now: str | None,
    external_archive_network_authorized: bool,
    saved_policy_lookup: Callable[[dict[str, Any]], dict[str, Any] | None] | None = None,
) -> dict[str, Any]:
    """Return the resident's bound evaluation payload or raise ``NativeSupplyChainEvalError``.

    When the resident holds a cached Cloud validation error it asks for the
    saved-policy lookup it cannot hydrate itself (``saved_policy_probe_required``).
    ``saved_policy_lookup`` reads that row; the resident decides what it means.
    """

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
    request.update(_test_seam_overrides())
    fixed_now = _now_text(now)
    exchanger: EgressExchanger | None = None
    probed = False
    with ExitStack() as stack:
        response = _send_eval_request(request, guard_home)
        # The initial request plus at most _MAX_ROUNDS follow-ups; the response to the last
        # follow-up is inspected as well, so a verdict reached on it is not discarded.
        for round_index in range(_MAX_ROUNDS + 1):
            answered_ok = response.get("status") == "ok"
            needs_egress = answered_ok and response.get("code") == EGRESS_REQUIRED_CODE
            needs_probe = (
                answered_ok
                and response.get("code") == _PROBE_REQUIRED_CODE
                and saved_policy_lookup is not None
                and isinstance(response.get("payload"), dict)
                and not probed
            )
            if not (needs_egress or needs_probe):
                break
            if round_index == _MAX_ROUNDS:
                _record_unbound_answer(guard_home)
                raise NativeSupplyChainEvalError("Native package evaluation did not settle")
            if needs_egress:
                # The resident cannot reach the network itself: perform what it asked
                # for under the managed network policy and replay with the outcomes.
                if exchanger is None:
                    exchanger = EgressExchanger(stack.enter_context(private_spool_dir()))
                try:
                    exchanger.fulfil(response.get("payload"))
                except EgressProtocolError as error:
                    _record_unbound_answer(guard_home)
                    raise NativeSupplyChainEvalError("Native package evaluation egress request invalid") from error
                request = {
                    **request,
                    "request_id": _request_id(),
                    "now": fixed_now,
                    "egress_supplied": list(exchanger.supplied),
                    "egress_spool_dir": str(exchanger.spool_dir),
                }
            else:
                probed = True
                decision = saved_policy_lookup(response["payload"])
                probe: dict[str, object] = {} if decision is None else {"decision": decision}
                request = {**request, "request_id": _request_id(), "now": fixed_now, "saved_policy_probe": probe}
            response = _send_eval_request(request, guard_home)
    if response.get("status") != "ok" or response.get("code") != "ok":
        raise NativeSupplyChainEvalError("Native package evaluation unavailable or invalid")
    payload = response.get("payload")
    if not _payload_is_complete(payload):
        _record_unbound_answer(guard_home)
        raise NativeSupplyChainEvalError("Native package evaluation payload invalid")
    return payload


def _saved_policy_decision(
    *,
    store: Any,
    artifact: GuardArtifact,
    workspace_dir: Path | None,
    cached_payload: dict[str, Any],
    now: str,
) -> dict[str, Any] | None:
    """Read the saved policy row that covers a cached Cloud validation error.

    Hydration only: the approval-identity hash and the signed approval store
    live here. The resident decides whether the row keeps the cached block.
    """

    if workspace_dir is None:
        return None
    try:
        from .local_supply_chain import package_request_policy_hash

        artifact_hash = package_request_policy_hash(
            artifact=artifact,
            store=store,
            workspace_dir=workspace_dir,
            evaluation=evaluation_from_native_payload(cached_payload),
        )
    except (ImportError, TypeError, ValueError, KeyError, AttributeError, OSError):
        return None
    lookup = store.resolve_policy_decision_lookup(
        artifact.harness,
        artifact.artifact_id,
        artifact_hash,
        str(workspace_dir),
        artifact.publisher,
        now,
        consume_one_shot=False,
    )
    decision = lookup["decision"]
    return decision if isinstance(decision, dict) else None


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
            saved_policy_lookup=lambda cached: _saved_policy_decision(
                store=store,
                artifact=artifact,
                workspace_dir=workspace_dir,
                cached_payload=cached,
                now=_now_text(now),
            ),
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
