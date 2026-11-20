#!/usr/bin/env python3
"""Record artifact-hook approval-reuse step vectors from the Python ladder.

``evaluate_native_artifact_hook`` walked the saved-approval reuse ladder in
Python: read the saved decision, claim it when the reuse said so, revalidate
after the claim, apply a trusted-request override (a second claim), then settle
the claimed pass. The resident decides all of that now
(``artifact_reuse_step`` in ``hook_decision_artifact_reuse_step.rs``) and
answers with a plan the transport only executes.

The ladder below (``_recorded_ladder``) is that Python code as it stood at
3b8ac2e848, kept here so the oracle never calls the code it checks. Its store
claim is a stub that takes the next outcome of the run, so each fact set is
walked once per claim outcome (depth first) and the paths fold into the plan
tree the resident must answer. The resident answers the ladder asked of the
composition queries (``saved_reuse``, ``package_reuse_settle``,
``trusted_override`` and ``claimed_reuse``) come from a runtime binary built at
that commit, so the oracle keeps the compose logic it always ran:

    HOL_GUARD_NATIVE_BINARY=<runtime at 3b8ac2e848> PYTHONPATH=src \
        .venv/bin/python scripts/ci/record_artifact_reuse_step_vectors.py

Each vector holds the resident's inputs (``facts``) and the ``plan`` the
oracle exhibits: ``claim`` (the store claim, with the plan to follow when it
succeeds and when it fails), ``revalidate`` (the post-claim pass) or ``settled``
(the settlement of the ladder). The Rust ``hook_decision_artifact_reuse_step``
tests replay the plan.

Deliberate differences from the old ladder, all of them in the failure paths
the vectors do not cover: a resident that cannot answer no longer recomputes
the action locally for a tool request (the hook answers with the host outage),
and the compose answer the store pre-seeded for ``saved_reuse`` is ignored (the
resident recomputes it from the same query).
"""

from __future__ import annotations

import gzip
import json
import os
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from artifact_reuse_step_cases import RUNTIME_HASH, cases

OUTPUT = Path("rust/crates/guard-runtime/tests/fixtures/artifact_reuse_step_vectors.json.gz")

Compose = Callable[[str, dict[str, Any]], dict[str, Any]]


# --- The retired ladder -------------------------------------------------------


class NeedClaimError(Exception):
    """The ladder reached a store claim whose outcome this run has not chosen."""


def _optional_string(value: object | None) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _stored_decision(stored: dict[str, Any] | None) -> dict[str, Any] | None:
    """The saved decision row the facts describe."""

    if stored is None:
        return None
    row: dict[str, Any] = {"action": stored["action"], "artifact_hash": stored["artifact_hash"]}
    row["source"] = stored["source"]
    if stored["request_id"] is not None:
        row.update(approval_id="approval-1", request_id=stored["request_id"], _approval_authority_revision=1)
    return row


def claimed_approval_request_id(decision: dict[str, Any]) -> str | None:
    """Frozen copy of the workflow helper; the oracle never imports what it checks."""

    approval_id = decision.get("approval_id")
    request_id = decision.get("request_id")
    revision = decision.get("_approval_authority_revision")
    if (
        isinstance(approval_id, str)
        and approval_id
        and isinstance(request_id, str)
        and request_id
        and isinstance(revision, int)
        and not isinstance(revision, bool)
        and revision >= 0
    ):
        return request_id
    return None


def _recorded_ladder(facts: dict[str, Any], outcomes: tuple[bool, ...], compose: Compose) -> dict[str, Any]:
    """``evaluate_native_artifact_hook``'s reuse ladder; every effect is a stub.

    Returns the ``revalidate`` the ladder ended in, or the settlement the rest
    of the hook went on to read. A claim takes the next of ``outcomes``.
    """

    from codex_plugin_scanner.guard.runtime.approval_reuse import _decision_from_native_payload

    pending = iter(outcomes)

    def claim() -> bool:
        try:
            return next(pending)
        except StopIteration:
            raise NeedClaimError from None

    def revalidate_claimed_allow(
        claimed_hash: str,
        *,
        trusted_request_override: bool,
        package_approval_consumed: bool = False,
        approval_request_id: str | None = None,
    ) -> dict[str, Any]:
        return {
            "effect": "revalidate",
            "trusted_request_override": trusted_request_override,
            "package_approval_consumed": package_approval_consumed,
            "request_id": approval_request_id,
        }

    current_policy_action = facts["current_action"]
    _claim_saved_approval = facts["claim_saved_approval"]
    stored_policy_decision = _stored_decision(facts["stored"])
    stored_policy_action = (
        _optional_string(stored_policy_decision.get("action")) if stored_policy_decision is not None else None
    )
    remembered_rule_rejection = {"reason": "recorded"} if facts["remembered_rule_rejected"] else None
    runtime_artifact_hash = RUNTIME_HASH
    trusted_request_override_hash = RUNTIME_HASH if facts["trusted_override"] is not None else None
    claimed = facts["claimed"]
    _claimed_saved_allow_hash = claimed["claimed_hash"] if claimed is not None else None
    lookup = facts["lookup"]
    scanner_evidence_payload: list[dict[str, Any]] = []
    approval_reuse = None
    package_approval_reuse_evidence = None
    approval_reuse_source: str | None = None
    package_risk_refresh = False
    if lookup["mode"] == "package":
        settle = compose(
            "package_reuse_settle",
            {
                "reasons": list(lookup["reasons"]),
                "claim_saved_approval": bool(_claim_saved_approval),
                "current_action": current_policy_action,
                "evaluation_policy_action": lookup["evaluation_policy_action"],
                "stored_policy_action": stored_policy_action,
                "stored_artifact_hash": (
                    stored_policy_decision.get("artifact_hash") if stored_policy_decision is not None else None
                ),
                "approval_reuse_source": approval_reuse_source,
            },
        )
        reuse = settle["approval_reuse"]
        approval_reuse = _decision_from_native_payload(reuse) if isinstance(reuse, dict) else None
        scanner_evidence_payload.extend(settle["evidence_appends"])
        if settle["revalidate_required"]:
            return revalidate_claimed_allow(
                runtime_artifact_hash,
                trusted_request_override=False,
                package_approval_consumed=settle["claim_disposition"] == "consumed",
            )
        policy_action = settle["policy_action"]
        approval_reuse_source = settle["approval_reuse_source"]
        reuse_evidence = settle["reuse_evidence"]
        if isinstance(reuse_evidence, dict):
            package_approval_reuse_evidence = reuse_evidence
        scanner_evidence_payload.extend(settle["settled_evidence_appends"])
        if policy_action != current_policy_action:
            package_risk_refresh = True
    else:
        saved_fields = dict(lookup["saved"], current_action=current_policy_action)
        saved_answer = compose("saved_reuse", saved_fields)
        approval_reuse = _decision_from_native_payload(saved_answer["approval_reuse"])
        approval_reuse_source = saved_answer["approval_reuse_source"]
        workflow_request_id = (
            claimed_approval_request_id(stored_policy_decision) if stored_policy_decision is not None else None
        )
        workflow_reapproval_pending = (
            approval_reuse.reason_code == "approval_reuse_reapproval_required"
            and workflow_request_id is not None
            and lookup["workflow_preflight"]
        )
        if (
            (approval_reuse.should_claim or workflow_reapproval_pending)
            and stored_policy_decision is not None
            and _claim_saved_approval
        ):
            if not claim():
                failed = compose(
                    "saved_reuse",
                    {
                        **saved_fields,
                        "stored_present": True,
                        "integrity_failure": False,
                        "stored_validation_reason": "approval_reuse_claim_failed",
                    },
                )
                approval_reuse = _decision_from_native_payload(failed["approval_reuse"])
            else:
                return revalidate_claimed_allow(
                    runtime_artifact_hash,
                    trusted_request_override=False,
                    approval_request_id=workflow_request_id,
                )
        policy_action = approval_reuse.action
        if approval_reuse_source is not None:
            scanner_evidence_payload.append(
                {
                    "source": "approval_reuse",
                    "input_source": approval_reuse_source,
                    **approval_reuse.to_evidence(),
                }
            )
    trusted_request_override_applied = False
    trusted_request_override_reason: str | None = None
    if trusted_request_override_hash is not None:
        override = facts["trusted_override"]
        override_fields: dict[str, Any] = {
            "token_validation_reason": override["token_validation_reason"],
            "policy_action": policy_action,
            "remembered_rule_rejected": remembered_rule_rejection is not None,
            "prior_reuse_reason_code": approval_reuse.reason_code if approval_reuse is not None else None,
            "stored_present": stored_policy_decision is not None,
            "stored_action": stored_policy_decision.get("action") if stored_policy_decision is not None else None,
            "stored_source": stored_policy_decision.get("source") if stored_policy_decision is not None else None,
            "stored_validation_reason": (
                override["stored_validation_reason"] if stored_policy_decision is not None else None
            ),
            "claim_succeeded": None,
        }
        override_answer = compose("trusted_override", override_fields)
        if override_answer["claim_required"] and stored_policy_decision is not None:
            if claim():
                return revalidate_claimed_allow(
                    runtime_artifact_hash,
                    trusted_request_override=True,
                    approval_request_id=claimed_approval_request_id(stored_policy_decision),
                )
            override_answer = compose("trusted_override", {**override_fields, "claim_succeeded": False})
        trusted_request_override_reason = override_answer["reason_code"]
        scanner_evidence_payload.append(override_answer["evidence"])
    if _claimed_saved_allow_hash is not None:
        claim_answer = compose(
            "claimed_reuse",
            {
                "claimed_hash": _claimed_saved_allow_hash,
                "token_validation_reason": claimed["token_validation_reason"],
                "post_claim_refresh_failed": claimed["post_claim_refresh_failed"],
                "remembered_rule_rejected": remembered_rule_rejection is not None,
                "prior_reuse": (
                    {
                        "action": approval_reuse.action,
                        "saved_action": approval_reuse.saved_action,
                        "reason_code": approval_reuse.reason_code,
                    }
                    if approval_reuse is not None
                    else None
                ),
                "package_reuse_saved_action": (
                    package_approval_reuse_evidence.get("saved_action")
                    if package_approval_reuse_evidence is not None
                    else None
                ),
                "workflow_capability_required": claimed["workflow_capability_required"],
                "workflow_authorization_claimed": claimed["workflow_authorization_claimed"],
                "policy_action": policy_action,
                "current_policy_action": current_policy_action,
                "claimed_trusted_request_override": claimed["claimed_trusted_request_override"],
                "claimed_package_approval_consumed": claimed["claimed_package_approval_consumed"],
            },
        )
        approval_reuse = _decision_from_native_payload(claim_answer["approval_reuse"])
        policy_action = claim_answer["policy_action"]
        approval_reuse_source = claim_answer["approval_reuse_source"]
        trusted_request_override_applied = bool(claim_answer["trusted_request_override_applied"])
        trusted_request_override_reason = claim_answer["trusted_request_override_reason"]
        scanner_evidence_payload.append(claim_answer["evidence"])
    return {
        "effect": "settled",
        "policy_action": policy_action,
        "approval_reuse_source": approval_reuse_source,
        "trusted_request_override_applied": trusted_request_override_applied,
        "trusted_request_override_reason": trusted_request_override_reason,
        "evidence": scanner_evidence_payload,
        "approval_reuse": (
            approval_reuse.to_evidence() if approval_reuse is not None else package_approval_reuse_evidence
        ),
        "package_risk_refresh": package_risk_refresh,
    }


def plan_of(facts: dict[str, Any], compose: Compose, outcomes: tuple[bool, ...] = ()) -> dict[str, Any]:
    """Fold every claim outcome of the ladder into the plan tree it exhibits."""

    try:
        return _recorded_ladder(facts, outcomes, compose)
    except NeedClaimError:
        return {
            "effect": "claim",
            "on_claimed": plan_of(facts, compose, (*outcomes, True)),
            "on_failed": plan_of(facts, compose, (*outcomes, False)),
        }


# --- The resident the oracle composes with ------------------------------------


def bind_resident(binary: str) -> Path:
    """Point the native bridge at ``binary`` with a throwaway guard home."""

    os.environ.update(
        {
            "HOL_GUARD_NATIVE": "force",
            "HOL_GUARD_NATIVE_BINARY": binary,
            "HOL_GUARD_TEST_MODE": "1",
            "HOL_GUARD_RESIDENT_TEST_SEAMS": "1",
        }
    )
    from codex_plugin_scanner.guard import config
    from codex_plugin_scanner.guard.native_context import bind_context_digest_home
    from codex_plugin_scanner.guard.native_policy_snapshot import provision_native_policy_verifier_key

    home = Path(tempfile.mkdtemp(prefix="reuse-step-"))
    (home / "native-runtime").mkdir(mode=0o700, parents=True)
    provision_native_policy_verifier_key(home, b"\x07" * 32)
    config.resolve_guard_home = lambda override=None: Path(override) if override else home
    bind_context_digest_home(home)
    return home


def memoized_compose(home: Path) -> Compose:
    from codex_plugin_scanner.guard.native_hook_artifact_compose import native_hook_compose

    answers: dict[str, dict[str, Any]] = {}

    def compose(kind: str, fields: dict[str, Any]) -> dict[str, Any]:
        key = kind + json.dumps(fields, sort_keys=True)
        if key not in answers:
            answers[key] = native_hook_compose(kind, fields, guard_home=home)
        return answers[key]

    return compose


def main() -> int:
    binary = os.environ.get("HOL_GUARD_NATIVE_BINARY")
    if not binary:
        raise SystemExit("set HOL_GUARD_NATIVE_BINARY to a runtime built at the oracle commit")
    compose = memoized_compose(bind_resident(binary))
    seen: set[str] = set()
    vectors: list[dict[str, Any]] = []
    for facts in cases():
        key = json.dumps(facts, sort_keys=True)
        if key in seen:
            continue
        seen.add(key)
        vectors.append({"facts": facts, "plan": plan_of(facts, compose)})
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    body = json.dumps(vectors, sort_keys=True, separators=(",", ":")).encode()
    OUTPUT.write_bytes(gzip.compress(body, compresslevel=9, mtime=0))
    print(f"wrote {len(vectors)} vectors to {OUTPUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
