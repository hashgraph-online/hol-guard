"""Resident bridge for the ``package_policy_resolve`` op.

The resident owns the stored package policy override: whether a saved approval
is reused, a saved block is kept or the saved state is rejected, and the
resulting verdict rewrite. This module only hydrates the facts the resident
cannot read (the store lookup, the daemon fallback, the approval request row
and the synced-bundle rules), runs the single claim the resident asks for, and
strictly validates the reply. A missing, mismatched or malformed answer raises
:class:`NativePackagePolicyResolveError`; there is no Python fallback, so an
unavailable resident can never leave a saved approval applied.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .native_context import _resolve_digest_home
from .native_package_approval_hash import _evaluation_view, _transport
from .native_package_evaluation_compose import NativePackageEvaluationComposeError, apply_package_evaluation_patch

_RESOLVE_FEATURE = "package-policy-resolve-v1"
_CLAIM_KINDS = frozenset({"daemon", "legacy_local", "store"})
_DISPOSITIONS = frozenset({"consumed", "retained"})


class NativePackagePolicyResolveError(NativePackageEvaluationComposeError):
    """No authoritative native stored-policy resolution was available."""


def _text(value: object) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _approval_request(store: Any, decision: Mapping[str, object]) -> dict[str, object] | None:
    request_id = decision.get("request_id")
    getter = getattr(store, "get_approval_request", None)
    if not isinstance(request_id, str) or not request_id or not callable(getter):
        return None
    try:
        row = getter(request_id)
    except Exception:
        return None
    return dict(row) if isinstance(row, dict) else None


def _bundle_rules(store: Any, decision: Mapping[str, object]) -> list[dict[str, object]] | None:
    """Synced-bundle rules owned by a package-family row, when a bundle validates."""

    owner = _text(decision.get("owner"))
    if (
        _text(decision.get("source")) != "policy-bundle"
        or _text(decision.get("artifact_id")) != "family:package-request"
        or owner is None
        or not callable(getattr(store, "get_sync_payload", None))
    ):
        return None
    from .synced_policy import validated_synced_policy_bundle

    bundle = validated_synced_policy_bundle(store)
    rules = bundle.get("rules") if isinstance(bundle, dict) else None
    if not isinstance(rules, list):
        return None
    return [dict(rule) for rule in rules if isinstance(rule, dict) and _text(rule.get("ruleId")) == owner]


def _hydrate(
    store: Any,
    *,
    artifact: Any,
    artifact_hash: str,
    policy_workspaces: tuple[str, ...],
    now: str,
) -> dict[str, object]:
    decision: dict[str, object] | None = None
    ignored_integrity: object = None
    for workspace in policy_workspaces:
        lookup = store.resolve_policy_decision_lookup(
            artifact.harness,
            artifact.artifact_id,
            artifact_hash,
            workspace,
            artifact.publisher,
            now,
            consume_one_shot=False,
        )
        found = lookup["decision"]
        ignored_integrity = lookup["ignored_local_integrity"]
        if isinstance(found, dict):
            decision = found
            break
        if ignored_integrity is not None:
            break
    authority = None
    if decision is None and ignored_integrity is not None:
        from .daemon.policy_authority_client import resolve_package_policy

        resolution = resolve_package_policy(
            guard_home=store.guard_home,
            harness=artifact.harness,
            artifact_id=artifact.artifact_id,
            artifact_hash=artifact_hash,
            workspaces=policy_workspaces,
            publisher=artifact.publisher,
        )
        authority = resolution.authority
        if resolution.decision is not None:
            decision = resolution.decision
            ignored_integrity = None
    facts: dict[str, object] = {
        "ignored_integrity": ignored_integrity is not None,
        "daemon_authority": authority is not None,
        "authority": authority,
    }
    if decision is not None:
        facts["decision"] = decision
        request = _approval_request(store, decision)
        if request is not None:
            facts["approval_request"] = request
        rules = _bundle_rules(store, decision)
        if rules is not None:
            facts["bundle_rules"] = rules
    elif ignored_integrity is None:
        for workspace in policy_workspaces:
            reason, stored_hash = store.approval_reuse_diagnostic(
                artifact.harness, artifact.artifact_id, artifact_hash, workspace, artifact.publisher, now
            )
            if reason is not None:
                facts["diagnosed_reason"] = reason
                if stored_hash is not None:
                    facts["diagnosed_stored_hash"] = stored_hash
                break
    return facts


def _run_claim(kind: str, store: Any, decision: dict[str, object], authority: Any, now: str) -> bool:
    if kind == "daemon" and authority is not None:
        from .daemon.policy_authority_client import claim_package_policy

        return claim_package_policy(authority, decision)
    if kind == "legacy_local":
        approval_id = decision.get("approval_id")
        if not isinstance(approval_id, str):
            raise NativePackagePolicyResolveError("Native package policy claim invalid")
        return store.claim_local_once_approval(approval_id, claimed_at=now, expected_decision=decision)
    if kind == "store":
        return store.claim_approval_reuse_decision(decision, now=now)
    raise NativePackagePolicyResolveError("Native package policy claim invalid")


def _call(request: dict[str, object], guard_home: Path) -> dict[str, Any]:
    payload = _transport(
        dict(request),
        guard_home,
        operation="package_policy_resolve",
        feature=_RESOLVE_FEATURE,
        error=NativePackagePolicyResolveError,
    )
    patch = payload.get("patch")
    claim = payload.get("claim")
    disposition = payload.get("claim_disposition")
    if (
        set(payload) != {"patch", "claim", "claim_disposition", "reused"}
        or not isinstance(payload["reused"], bool)
        or not isinstance(patch, dict)
        or (claim is not None and claim not in _CLAIM_KINDS)
        or (disposition is not None and disposition not in _DISPOSITIONS)
    ):
        raise NativePackagePolicyResolveError("Native package policy resolution invalid")
    return payload


def native_resolve_stored_package_policy(
    evaluation: Any,
    *,
    store: Any,
    artifact: Any,
    artifact_hash: str,
    workspace_dir: Path,
    now: str,
    policy_workspaces: tuple[str, ...],
    current_action: object | None,
    claim_saved_approval: bool,
) -> tuple[Any, str | None, dict[str, object] | None]:
    """Return the resolved evaluation, claim disposition and the reused saved decision."""

    facts = _hydrate(
        store,
        artifact=artifact,
        artifact_hash=artifact_hash,
        policy_workspaces=policy_workspaces,
        now=now,
    )
    authority = facts.pop("authority")
    decision = facts.get("decision")
    nothing_saved = decision is None and not facts["ignored_integrity"] and "diagnosed_reason" not in facts
    if nothing_saved and current_action is None:
        return evaluation, None, None
    request: dict[str, object] = {
        "evaluation": _evaluation_view(evaluation, fields=("policy_action", "reasons", "packages")),
        "harness": artifact.harness,
        "artifact_id": artifact.artifact_id,
        "artifact_hash": artifact_hash,
        "workspace_dir": str(workspace_dir),
        "claim_saved_approval": claim_saved_approval,
        **facts,
    }
    if current_action is not None:
        request["current_action"] = current_action
    guard_home = _resolve_digest_home(Path(store.guard_home) if getattr(store, "guard_home", None) else None)
    payload = _call(request, guard_home)
    claim = payload["claim"]
    if claim is not None:
        if not isinstance(decision, dict):
            raise NativePackagePolicyResolveError("Native package policy claim invalid")
        if not _run_claim(claim, store, decision, authority, now):
            request["claim_succeeded"] = False
            payload = _call(request, guard_home)
    resolved = apply_package_evaluation_patch(evaluation, payload["patch"])
    if payload["reused"] and not isinstance(decision, dict):
        raise NativePackagePolicyResolveError("Native package policy resolution invalid")
    return resolved, payload["claim_disposition"], decision if payload["reused"] else None
