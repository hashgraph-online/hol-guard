"""Resident bridge for the ``package_protect_finalize`` op.

The resident owns the decision tail of the pre-spawn package authority check:
whether a claimed saved approval still holds for the rebuilt authority, whether
an unclaimed one must be rejected, and which verdict rewrite results. The
caller keeps the callbacks, the initial claim and the rebuild, hydrates the
read-only stored-policy facts the resident cannot read, and applies the
returned patch mechanically.

A malformed or mismatched answer raises :class:`NativePackageProtectFinalizeError`;
an unreachable resident (down, older than the op, timed out) fails closed with
a terminal block.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .native_context import _canonical_request_sha256, _resolve_digest_home, ensure_resident_prerequisite
from .native_package_approval_hash import _evaluation_view
from .native_package_authority import _REQUEST_SCHEMA, _RESULT_SCHEMA, _request_id, _resident_request
from .native_package_evaluation_compose import (
    _VERDICT_KEYS,
    NativePackageEvaluationComposeError,
    apply_package_evaluation_patch,
    native_unavailable_block_evaluation,
)
from .native_package_policy_resolve import _hydrate
from .runtime.package_execution_policy import is_execution_permitted

_FINALIZE_FEATURE = "package-protect-finalize-v1"
_EVALUATION_FIELDS = ("policy_action", "reasons", "packages")


class NativePackageProtectFinalizeError(NativePackageEvaluationComposeError):
    """No authoritative native package-protect finalize result was available."""


def package_protect_stored_policy(
    store: Any,
    *,
    artifact: Any,
    artifact_hash: str,
    workspace_dir: Path,
    now: str,
    policy_workspaces: tuple[str, ...],
) -> dict[str, object]:
    """Read-only stored-policy facts for the rebuilt artifact; nothing is claimed."""

    facts = _hydrate(
        store,
        artifact=artifact,
        artifact_hash=artifact_hash,
        policy_workspaces=policy_workspaces,
        now=now,
    )
    facts.pop("authority")
    return {
        "harness": artifact.harness,
        "artifact_id": artifact.artifact_id,
        "artifact_hash": artifact_hash,
        "workspace_dir": str(workspace_dir),
        **facts,
    }


def _call(request: dict[str, object], guard_home: Path) -> dict[str, Any] | None:
    """The reply patch, or ``None`` when the resident cannot service the op."""

    request["schema"] = _REQUEST_SCHEMA
    request["request_id"] = _request_id()
    request["guard_home"] = str(guard_home)
    try:
        request_sha256 = "sha256:" + _canonical_request_sha256(request)
    except (TypeError, ValueError) as error:
        raise NativePackageProtectFinalizeError("Native package protect finalize request invalid") from error
    if not ensure_resident_prerequisite(guard_home):
        return None
    response = _resident_request(
        operation="package_protect_finalize",
        request=request,
        guard_home=guard_home,
        timeout_seconds=2.0,
        required_features=(_FINALIZE_FEATURE,),
    )
    if response is None:
        return None
    payload = response.get("payload")
    patch = payload.get("patch") if isinstance(payload, dict) else None
    if (
        response.get("schema") != _RESULT_SCHEMA
        or response.get("request_id") != request["request_id"]
        or response.get("request_sha256") != request_sha256
        or response.get("status") != "ok"
        or response.get("code") != "ok"
        or not isinstance(payload, dict)
        or set(payload) != {"patch"}
        or not isinstance(patch, dict)
    ):
        raise NativePackageProtectFinalizeError("Native package protect finalize result invalid")
    return patch


def native_finalize_package_protect(
    *,
    initial: Any,
    current: Any | None,
    claim_failure: Any | None,
    saved_approval_claimed: bool,
    claim_disposition: str | None,
    stored_policy: Mapping[str, object] | None,
    store: Any,
) -> Any:
    """Return the final evaluation for the rebuilt (or initial) authority."""

    rebuilt = current.evaluation if current is not None and claim_failure is None else claim_failure
    base = initial.evaluation if current is None else rebuilt
    request: dict[str, object] = {
        "evaluation": _evaluation_view(base, fields=_EVALUATION_FIELDS),
        "initial_artifact_id": initial.artifact.artifact_id,
        "initial_artifact_hash": initial.artifact_hash,
        "observe_mode": bool(current is not None and current.observe_mode),
        "claim_failed": claim_failure is not None,
        "saved_approval_claimed": saved_approval_claimed,
    }
    if current is not None:
        request["current_action"] = current.current_action
        request["current_artifact_id"] = current.artifact.artifact_id
        request["current_artifact_hash"] = current.artifact_hash
    if claim_disposition is not None:
        request["claim_disposition"] = claim_disposition
    if stored_policy is not None:
        request["stored_policy"] = dict(stored_policy)
    guard_home = _resolve_digest_home(Path(store.guard_home) if getattr(store, "guard_home", None) else None)
    patch = _call(request, guard_home)
    if patch is None:
        return native_unavailable_block_evaluation(base)
    _check_reply(
        base,
        patch,
        current=current,
        claim_failure=claim_failure,
        saved_approval_claimed=saved_approval_claimed,
    )
    return apply_package_evaluation_patch(base, patch)


def _check_reply(
    base: Any,
    patch: Mapping[str, Any],
    *,
    current: Any | None,
    claim_failure: Any | None,
    saved_approval_claimed: bool,
) -> None:
    """Reject replies that break the request's invariants; never recomputes the verdict."""

    effective = patch.get("policy_action", base.policy_action)
    if effective != base.policy_action and not set(patch) >= _VERDICT_KEYS:
        raise NativePackageProtectFinalizeError("Native package protect finalize changed the action without a verdict")
    if current is None:
        # Nothing rebuilt to run: the reply can only reject the reuse.
        if is_execution_permitted(effective):
            raise NativePackageProtectFinalizeError("Native package protect finalize allowed an unbound launch")
        return
    if (claim_failure is not None or current.observe_mode) and effective != current.current_action:
        raise NativePackageProtectFinalizeError("Native package protect finalize changed a fixed current action")
    reasons = patch.get("reasons", base.reasons)
    reuses_saved = isinstance(reasons, (list, tuple)) and any(
        isinstance(reason, Mapping) and reason.get("code") == "saved_package_approval" for reason in reasons
    )
    # A failed claim keeps the saved-approval reason it was refused for, but
    # the check above pins its action to the current one.
    if claim_failure is None and not saved_approval_claimed and reuses_saved:
        raise NativePackageProtectFinalizeError("Native package protect finalize reused an unclaimed approval")
