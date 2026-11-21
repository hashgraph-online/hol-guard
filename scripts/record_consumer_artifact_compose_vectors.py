#!/usr/bin/env python3
"""Record consumer artifact compose vectors from the retired Python composition.

The expected answers come only from the consumer evaluation helpers that
existed before the resident owned this composition (a scratch checkout of the
base commit, passed as ``--base-src``): ``score_verdict``, the current-action
lattice, saved/claimed approval reuse, the trusted-request override and
runtime-detector authority. They are never produced by the new Rust op, so the
vectors stay an independent oracle for it. The retired helpers already asked
the resident for approval reuse and context-token validation, so both runs use
``--native-binary`` for those pre-existing operations.

Usage:
    record_consumer_artifact_compose_vectors.py --base-src <base-checkout>/src \
        --native-binary <hol-guard-runtime> --output <file>

The script runs twice: the parent builds inputs and captures the native query
the working tree sends, and a child (``--oracle``) whose ``PYTHONPATH`` is the
base checkout recomposes the same inputs with the retired helpers.
"""

from __future__ import annotations

import argparse
import importlib
import itertools
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

ARTIFACT_ID = "artifact-1"
NOW = "2026-01-01T00:00:00Z"
RUNTIME_SIGNAL = {
    "signal_id": "runtime-1",
    "category": "network",
    "severity": "high",
    "confidence": "strong",
    "detector": "runtime.test",
    "title": "Runtime signal",
    "plain_reason": "runtime detector reason",
    "technical_detail": None,
    "evidence_ref": None,
    "redaction_level": "none",
    "false_positive_hint": None,
    "advisory_id": None,
}


def _bind_resident(binary: str) -> None:
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

    home = Path(tempfile.mkdtemp(prefix="consumer-compose-vectors-"))
    (home / "native-runtime").mkdir(mode=0o700, parents=True)
    provision_native_policy_verifier_key(home, b"\x07" * 32)
    config.resolve_guard_home = lambda override=None: Path(override) if override else home
    bind_context_digest_home(home)


def _scoring_objects(scoring: dict) -> tuple:
    # Resolved at run time from the base checkout (``PYTHONPATH=--base-src``): the
    # delta/provenance/history dataclasses no longer exist in the working tree.
    types = importlib.import_module("codex_plugin_scanner.guard.types")
    capability_delta, guard_signal = types.CapabilityDelta, types.GuardSignal
    history_context, provenance_bundle = types.HistoryContext, types.ProvenanceBundle

    signals = tuple(
        guard_signal(
            signal_id=f"signal-{index}",
            family=family,
            severity=severity,
            confidence=confidence,
            evidence_source=source,
            matched_text=None,
            explanation=explanation,
            remediation=None,
            rule_version="test",
        )
        for index, (family, severity, confidence, source, explanation) in enumerate(scoring["signals"])
    )
    deltas = tuple(
        capability_delta(delta_type=kind, before=None, after=None, severity=severity, explanation=explanation)
        for kind, severity, explanation in scoring["deltas"]
    )
    source_kind, trust = scoring["provenance"]
    approvals, incidents = scoring["history"]
    return (
        signals,
        deltas,
        provenance_bundle(source_kind=source_kind, publisher_trust=trust),
        history_context(prior_approvals=approvals, prior_incidents=incidents),
    )


def _scoring_evidence(objects: tuple) -> tuple:
    """The signals and the evidence-op scoring dict of the working tree."""

    signals, deltas, provenance, history = objects
    return signals, {
        "deltas": [
            {"delta_type": delta.delta_type, "severity": int(delta.severity), "explanation": delta.explanation}
            for delta in deltas
        ],
        "provenance_source_kind": provenance.source_kind,
        "publisher_trust": provenance.publisher_trust,
        "prior_approvals": int(history.prior_approvals),
        "prior_incidents": int(history.prior_incidents),
    }


class _Store:
    guard_home = None

    def __init__(self, saved: dict) -> None:
        self.saved = saved

    def resolve_policy_decision_lookup_with_memory_pattern(self, *_args: object, **_kwargs: object) -> dict:
        ignored = {"reason": "local_integrity_failed"} if self.saved.get("ignored") else None
        return {"decision": self.saved.get("decision"), "ignored_local_integrity": ignored}

    def approval_reuse_validation_reason(self, *_args: object) -> str | None:
        return self.saved.get("diagnosed")


def _by_artifact(value: object) -> dict | None:
    return None if value is None else {ARTIFACT_ID: value}


def _oracle_current(case: dict) -> dict:
    from codex_plugin_scanner.guard.action_lattice import most_restrictive_guard_action
    from codex_plugin_scanner.guard.consumer import service as svc
    from codex_plugin_scanner.guard.policy import decide_action

    config = SimpleNamespace(
        changed_hash_action=case["config_changed_hash_action"],
        default_action=case["config_default_action"],
    )
    configured_action = case["configured_action"]
    effective_default_action = case["effective_default_action"]
    reusable = case["skill_directory_identity_reusable"]
    if case["removed"]:
        current = decide_action(
            configured_action=configured_action,
            default_action=effective_default_action,
            config=config,
            changed=True,
        )
        if reusable is False:
            current = most_restrictive_guard_action(current, "require-reapproval")
        return {"current_action": current, "scanner_action": None, "verdict": None}
    verdict = svc.score_verdict(*_scoring_objects(case["scoring"]))
    metadata = {} if case["guard_default_action"] is None else {"guard_default_action": case["guard_default_action"]}
    artifact = SimpleNamespace(metadata=metadata)
    if configured_action is None and case["artifact_type"] in {
        "prompt_request",
        "file_read_request",
        "tool_action_request",
    }:
        current = svc._guard_default_action(artifact) or "require-reapproval"
    elif case["first_seen"] and configured_action is None and effective_default_action is not None:
        current = effective_default_action
    else:
        current = decide_action(
            configured_action=configured_action,
            default_action=effective_default_action,
            config=config,
            changed=case["changed"],
        )
    scanner = svc._default_action_from_verdict(verdict)
    current = most_restrictive_guard_action(current, scanner)
    if reusable is False:
        current = most_restrictive_guard_action(current, "require-reapproval")
    return {
        "current_action": current,
        "scanner_action": scanner,
        "verdict": {
            "action": verdict.action,
            "severity": verdict.severity,
            "confidence": verdict.confidence,
            "reasons": list(verdict.reasons),
            "recommended_next_actions": list(verdict.recommended_next_actions),
            "suppressible": verdict.suppressible,
            "review_priority": verdict.review_priority,
            "evidence_sources": list(verdict.evidence_sources),
            "provenance_state": verdict.provenance_state,
        },
    }


def _oracle_runtime(case: dict) -> dict:
    from codex_plugin_scanner.guard.consumer import service as svc
    from codex_plugin_scanner.guard.runtime.approval_reuse import (
        approval_reuse_authority_unavailable,
        evaluate_approval_reuse,
    )

    current = case["current_action"]
    ctx = case["approval_context_hash"]
    reusable = case["skill_directory_identity_reusable"]
    claimed_overrides = _by_artifact(case["claimed"])
    retained_overrides = _by_artifact(case["retained"])
    qualification_overrides = _by_artifact(case["qualification"])
    runtime_context = case["runtime_detector_context"]
    block_reason = case["runtime_detector_block_reason"]
    runtime_signals = svc._runtime_detector_risk_signals(runtime_context)
    runtime_action, runtime_reason = svc._runtime_detector_context_authority(runtime_context)
    pending: list = []
    approval_reuse, has_saved_state = svc._compose_consumer_saved_policy(
        store=_Store(case["saved"]),
        harness="codex",
        artifact_id=ARTIFACT_ID,
        artifact_hash=ctx,
        workspace="workspace",
        publisher=None,
        current_action=current,
        identity_reusable=reusable is not False,
        now=NOW,
        pending_approval_claims=pending,
    )
    claimed = reusable is not False and svc._claimed_saved_approval_applies(
        claimed_overrides,
        retained_overrides,
        artifact_id=ARTIFACT_ID,
        approval_context_hash=ctx,
        current_action=current,
        has_saved_state=has_saved_state,
        approval_reuse=approval_reuse,
        qualification=(qualification_overrides or {}).get(ARTIFACT_ID),
    )
    approval_claim = svc._saved_approval_claim_evidence(
        claimed_overrides,
        retained_overrides,
        artifact_id=ARTIFACT_ID,
        approval_context_hash=ctx,
        claimed=claimed,
    )
    if claimed:
        qualification = (qualification_overrides or {}).get(ARTIFACT_ID, {})
        claimed_reuse = evaluate_approval_reuse(
            current,
            "allow",
            saved_decision_present=True,
            fresh_local_approval=qualification.get("fresh_local_approval") is True,
            durable_exact_approval=qualification.get("durable_exact_approval") is True,
        )
        approval_reuse = claimed_reuse if claimed_reuse is not None else approval_reuse_authority_unavailable(current)
        has_saved_state = True
    trusted = svc._trusted_request_override_applies(
        _by_artifact(case["trusted"]),
        artifact_id=ARTIFACT_ID,
        approval_context_hash=ctx,
        approval_reuse=approval_reuse,
    )
    policy_action, finalized, scanner_evidence, decision_reason = svc._compose_runtime_policy_decision(
        approval_reuse=approval_reuse,
        has_saved_state=has_saved_state,
        trusted_request_override=trusted,
        claimed_saved_approval=claimed,
        skill_directory_identity_reusable=reusable,
        runtime_risk_signals_v2=runtime_signals,
        runtime_context_action=runtime_action,
        runtime_detector_block_reason=block_reason,
        approval_context_hash=ctx,
    )
    composition = {
        "configured_action": case["configured_action"],
        "current_action": current,
        "saved_action": approval_reuse.saved_action,
        "saved_state_present": has_saved_state,
        "scanner_action": case["scanner_action"],
        "raw_scoring_recommendation": case["raw_scoring_recommendation"],
        "scoring_recommendation_non_authoritative": True,
        "trusted_request_override": trusted,
        **(
            {"skill_directory_identity_reusable": reusable, "skill_directory_identity_floor": "require-reapproval"}
            if reusable is False
            else {}
        ),
        **({"saved_approval_claim": approval_claim} if approval_claim is not None else {}),
        **(
            {
                "runtime_detector_action": "block" if block_reason else runtime_action,
                "runtime_detector_reason": block_reason or runtime_reason,
            }
            if block_reason or runtime_action is not None
            else {}
        ),
        "final_action": policy_action,
    }
    approval_source = (
        "runtime-detector"
        if block_reason
        else "fresh-approval"
        if trusted
        else "saved-approval"
        if approval_reuse.accepted and approval_reuse.saved_action == "allow"
        else "saved-policy"
        if approval_reuse.saved_action == "block"
        else "policy"
    )
    return {
        "approval_claim": approval_claim,
        "approval_reuse": approval_reuse.to_evidence(),
        "approval_source": approval_source,
        "append_pending_claim": bool(pending),
        "authority_finalized": finalized,
        "decision_reason": decision_reason,
        "policy_action": policy_action,
        "policy_composition": composition,
        "saved_state_present": has_saved_state,
        "scanner_evidence": list(scanner_evidence),
        "trusted_request_override": trusted,
    }


def _oracle(cases: list[dict], binary: str) -> list[dict]:
    _bind_resident(binary)
    return [_oracle_current(case) if case["kind"] == "current_action" else _oracle_runtime(case) for case in cases]


class _CapturedError(Exception):
    pass


def _capture(kind: str, fields: dict, *, guard_home: object) -> dict:
    del guard_home
    raise _CapturedError({"kind": kind, **fields})


def _capture_query(case: dict) -> dict:
    from codex_plugin_scanner.guard.consumer import service as svc

    original = svc.native_consumer_compose
    svc.native_consumer_compose = _capture
    try:
        if case["kind"] == "current_action":
            scoring = svc._scoring_inputs(
                *(
                    ((), svc._REMOVED_SCORING)
                    if case["removed"]
                    else _scoring_evidence(_scoring_objects(case["scoring"]))
                )
            )
            guard_default_action = case["guard_default_action"]
            svc._native_current_action(
                _Store({}),
                SimpleNamespace(
                    changed_hash_action=case["config_changed_hash_action"],
                    default_action=case["config_default_action"],
                ),
                removed=case["removed"],
                artifact_type=None if case["removed"] else case["artifact_type"],
                configured_action=case["configured_action"],
                guard_default_action=guard_default_action if isinstance(guard_default_action, str) else None,
                first_seen=case["first_seen"],
                changed=case["changed"],
                effective_default_action=case["effective_default_action"],
                skill_directory_identity_reusable=case["skill_directory_identity_reusable"],
                scoring=scoring,
            )
        else:
            runtime_context = case["runtime_detector_context"]
            inputs = svc._ConsumerAuthorityInputs(
                store=_Store(case["saved"]),
                harness="codex",
                workspace="workspace",
                now=NOW,
                trusted_request_overrides=_by_artifact(case["trusted"]) or {},
                claimed_saved_approval_overrides=_by_artifact(case["claimed"]) or {},
                retained_saved_approval_overrides=_by_artifact(case["retained"]) or {},
                saved_approval_qualification_overrides=_by_artifact(case["qualification"]) or {},
                runtime_detector_composition=svc._runtime_detector_composition(runtime_context),
                runtime_detector_block_reason=case["runtime_detector_block_reason"],
                runtime_signals=[signal.to_dict() for signal in svc._runtime_detector_risk_signals(runtime_context)],
                pending_approval_claims=[],
            )
            svc._native_runtime_decision(
                inputs,
                artifact_id=ARTIFACT_ID,
                approval_context_hash=case["approval_context_hash"],
                publisher=None,
                memory_command=None,
                memory_artifact_type=None,
                memory_artifact_name=None,
                current_action=case["current_action"],
                configured_action=case["configured_action"],
                scanner_action=case["scanner_action"],
                raw_scoring_recommendation=case["raw_scoring_recommendation"],
                skill_directory_identity_reusable=case["skill_directory_identity_reusable"],
            )
    except _CapturedError as captured:
        return captured.args[0]
    finally:
        svc.native_consumer_compose = original
    raise SystemExit("query was not captured")


_SCORING = {
    "empty": {"signals": [], "deltas": [], "provenance": ["none", "unknown"], "history": [0, 0]},
    "one_signal": {
        "signals": [["network", 5, 0.6, "artifact", "Reaches a new host."]],
        "deltas": [],
        "provenance": ["none", "unknown"],
        "history": [0, 0],
    },
    "ranked_signals": {
        "signals": [
            ["policy", 7, 0.8, "prompt", "Policy rule matched."],
            ["secret", 9, 0.7, "artifact", "Reads a secret."],
            ["network", 3, 0.9, "history", "Low network signal."],
            ["filesystem", 9, 0.76, "cloud", "Writes outside the workspace."],
        ],
        "deltas": [],
        "provenance": ["none", "unknown"],
        "history": [0, 0],
    },
    "reapproval_deltas": {
        "signals": [],
        "deltas": [
            ["subprocess_added", 6, "Spawns a subprocess."],
            ["new_network_host", 4, "Adds a host."],
            ["secret_scope_expanded", 5, "Reads more secrets."],
        ],
        "provenance": ["none", "unknown"],
        "history": [0, 0],
    },
    "flagged_curated": {"signals": [], "deltas": [], "provenance": ["curated", "flagged"], "history": [0, 0]},
    "revoked_unprovenanced": {"signals": [], "deltas": [], "provenance": ["none", "revoked"], "history": [0, 0]},
    "prior_approvals": {
        "signals": [["network", 4, 0.74, "artifact", "Known host."]],
        "deltas": [],
        "provenance": ["none", "unknown"],
        "history": [2, 0],
    },
    "prior_incident": {
        "signals": [["network", 4, 0.6, "artifact", "Known host."]],
        "deltas": [],
        "provenance": ["none", "unknown"],
        "history": [1, 1],
    },
    "sandbox_unprovenanced": {
        "signals": [["filesystem", 8, 0.7, "artifact", "Writes system files."]],
        "deltas": [],
        "provenance": ["none", "unknown"],
        "history": [0, 0],
    },
    "severe_signed": {
        "signals": [["filesystem", 8, 0.7, "artifact", "Writes system files."]],
        "deltas": [],
        "provenance": ["signed", "known-good"],
        "history": [3, 0],
    },
    "round_tie": {
        "signals": [["network", 2, 0.5625, "artifact", "Tie confidence."]],
        "deltas": [],
        "provenance": ["none", "unknown"],
        "history": [0, 0],
    },
    "unknown_source": {
        "signals": [["network", 6, 0.6875, "bogus", "Unknown evidence source."]],
        "deltas": [],
        "provenance": ["attested", "known-good"],
        "history": [0, 0],
    },
    "approval_surface": {
        "signals": [],
        "deltas": [["approval_surface_changed", 3, "Approval surface changed."]],
        "provenance": ["self-declared", "unknown"],
        "history": [0, 0],
    },
    "many_reasons": {
        "signals": [
            ["network", 2, 0.6, "artifact", "Reason one."],
            ["secret", 6, 0.6, "prompt", "Reason two."],
            ["policy", 6, 0.6, "artifact", "Reason three."],
            ["filesystem", 1, 0.6, "artifact", "Reason four."],
        ],
        "deltas": [["new_network_host", 4, "Delta one."], ["transport_changed", 2, "Delta two."]],
        "provenance": ["none", "unknown"],
        "history": [1, 0],
    },
    "prior_approvals_severe": {
        "signals": [["secret", 8, 0.9, "artifact", "Reads a secret."]],
        "deltas": [],
        "provenance": ["curated", "known-good"],
        "history": [1, 0],
    },
    "flagged_self_declared": {
        "signals": [["network", 9, 0.8, "artifact", "Exfiltration pattern."]],
        "deltas": [],
        "provenance": ["self-declared", "flagged"],
        "history": [0, 0],
    },
}


def _current_cases() -> list[dict]:
    base = {
        "kind": "current_action",
        "removed": False,
        "artifact_type": "mcp_server",
        "configured_action": None,
        "guard_default_action": None,
        "first_seen": False,
        "changed": False,
        "effective_default_action": None,
        "config_changed_hash_action": "require-reapproval",
        "config_default_action": "warn",
        "skill_directory_identity_reusable": None,
        "scoring": _SCORING["empty"],
    }
    cases: list[dict] = []
    for artifact_type, configured, first_seen, changed, effective, reusable in itertools.product(
        ["mcp_server", "skill"],
        [None, "allow", "bogus", "ask"],
        [False, True],
        [False, True],
        [None, "allow", "review"],
        [None, False],
    ):
        cases.append(
            {
                **base,
                "artifact_type": artifact_type,
                "configured_action": configured,
                "first_seen": first_seen,
                "changed": changed,
                "effective_default_action": effective,
                "skill_directory_identity_reusable": reusable,
            }
        )
    for artifact_type, guard_default, configured, (first_seen, effective) in itertools.product(
        ["prompt_request", "tool_action_request"],
        [None, "warn", "allow", "bogus", 5],
        [None, "block"],
        [(False, None), (True, "allow")],
    ):
        cases.append(
            {
                **base,
                "artifact_type": artifact_type,
                "guard_default_action": guard_default,
                "configured_action": configured,
                "first_seen": first_seen,
                "effective_default_action": effective,
            }
        )
    for changed_hash, default, changed in itertools.product(
        ["allow", "bogus", "sandbox-required"], ["allow", "bogus", "block"], [False, True]
    ):
        cases.append(
            {**base, "config_changed_hash_action": changed_hash, "config_default_action": default, "changed": changed}
        )
    for scoring, configured in itertools.product(_SCORING, [None, "allow"]):
        cases.append({**base, "scoring": _SCORING[scoring], "configured_action": configured, "artifact_type": "skill"})
    for configured, effective, changed_hash, reusable in itertools.product(
        [None, "warn", "bogus"], [None, "allow"], ["require-reapproval", "allow"], [None, True, False]
    ):
        cases.append(
            {
                **base,
                "removed": True,
                "configured_action": configured,
                "effective_default_action": effective,
                "config_changed_hash_action": changed_hash,
                "skill_directory_identity_reusable": reusable,
            }
        )
    return cases


def _tokens() -> dict[str, str]:
    from codex_plugin_scanner.guard.runtime.approval_context import build_approval_context_token

    def token(**overrides: object) -> str:
        components = {"identity": "codex", "content": "hash-1", "capabilities": {}, "policy": "warn", "sandbox": "none"}
        return build_approval_context_token(**{**components, **overrides})

    return {
        "ctx": token(),
        "content": token(content="hash-2"),
        "policy": token(policy="block"),
        "identity": token(identity="claude-code"),
    }


def _runtime_cases(tokens: dict[str, str]) -> list[dict]:
    ctx = tokens["ctx"]

    def saved(action: object = "allow", artifact_hash: object = ctx, **extra: object) -> dict:
        decision = {
            "action": action,
            "artifact_hash": artifact_hash,
            "scope": "artifact",
            "fresh_local_approval": False,
            "durable_exact_approval": False,
            "harness": "codex",
            "artifact_id": ARTIFACT_ID,
        }
        decision.update(extra)
        return {"decision": decision}

    saved_states = {
        "none": {},
        "allow_exact": saved(),
        "allow_exact_fresh": saved(fresh_local_approval=True),
        "allow_exact_durable": saved(durable_exact_approval=True),
        "allow_content": saved(artifact_hash=tokens["content"]),
        "allow_policy": saved(artifact_hash=tokens["policy"]),
        "allow_identity": saved(artifact_hash=tokens["identity"]),
        "allow_legacy": saved(artifact_hash="sha256:legacy"),
        "allow_broad_harness": saved(artifact_hash=None, scope="harness"),
        "allow_unhashed_artifact": saved(artifact_hash=None),
        "block_saved": saved(action="block"),
        "review_saved": saved(action="review"),
        "bogus_saved": saved(action="bogus"),
        "integrity_with_row": {**saved(fresh_local_approval=True), "ignored": True},
        "integrity_only": {"ignored": True},
        "diagnosed": {"diagnosed": "approval_reuse_expired"},
    }
    base = {
        "kind": "runtime_decision",
        "current_action": "review",
        "configured_action": None,
        "scanner_action": "allow",
        "raw_scoring_recommendation": "allow",
        "skill_directory_identity_reusable": None,
        "approval_context_hash": ctx,
        "saved": {},
        "claimed": None,
        "retained": None,
        "qualification": None,
        "trusted": None,
        "runtime_detector_context": None,
        "runtime_detector_block_reason": None,
    }
    actions = ["allow", "warn", "review", "require-reapproval", "block", "sandbox-required"]
    cases: list[dict] = []
    for current, state, reusable in itertools.product(actions, saved_states, [None, False]):
        cases.append(
            {
                **base,
                "current_action": current,
                "saved": saved_states[state],
                "skill_directory_identity_reusable": reusable,
            }
        )
    qualifications = [None, {"fresh_local_approval": True}, {"durable_exact_approval": True, "fresh_local_approval": 1}]
    for current, state, claimed, retained, qualification in itertools.product(
        ["review", "require-reapproval", "block"],
        ["none", "allow_exact_fresh", "allow_exact", "allow_content"],
        [None, ctx],
        [None, ctx],
        qualifications,
    ):
        cases.append(
            {
                **base,
                "current_action": current,
                "saved": saved_states[state],
                "claimed": claimed,
                "retained": retained,
                "qualification": qualification,
            }
        )
    for claimed, retained in [(tokens["content"], None), (None, tokens["content"]), (ctx, ctx)]:
        for reusable in [None, False]:
            cases.append(
                {
                    **base,
                    "saved": saved_states["allow_exact_fresh"],
                    "claimed": claimed,
                    "retained": retained,
                    "qualification": qualifications[1],
                    "skill_directory_identity_reusable": reusable,
                }
            )
    for current, state, trusted in itertools.product(
        ["warn", "review", "require-reapproval", "block"],
        ["none", "integrity_only", "allow_content", "allow_exact"],
        [None, ctx, tokens["content"]],
    ):
        cases.append({**base, "current_action": current, "saved": saved_states[state], "trusted": trusted})
    compositions = [
        None,
        {"composition": {"action": "warn", "reason": "warn reason"}},
        {"composition": {"action": "review", "reason": "review reason"}},
        {"composition": {"action": "review", "reason": "  \t"}},
        {"composition": {"action": "block", "reason": "block reason"}},
        {"composition": {"action": "allow", "reason": "allow reason"}},
        {"composition": {"action": "sandbox-required", "reason": "sandbox"}},
        {"composition": {"action": "ask", "reason": "legacy alias"}},
        {"composition": {"action": "warn", "reason": 5}},
        {"composition": {"action": "warn"}},
        {"composition": {"action": "review", "reason": "\x1c"}},
        {"composition": "warn"},
        {
            "composition": {"action": "review", "reason": "with signals"},
            "signals_v2": [RUNTIME_SIGNAL, RUNTIME_SIGNAL, {"signal_id": "broken"}, "junk"],
        },
        {"signals_v2": [RUNTIME_SIGNAL]},
    ]
    for runtime_context, current, state, trusted in itertools.product(
        compositions, ["allow", "review"], ["none", "allow_exact_fresh"], [None, ctx]
    ):
        cases.append(
            {
                **base,
                "current_action": current,
                "saved": saved_states[state],
                "trusted": trusted,
                "runtime_detector_context": runtime_context,
            }
        )
    for block_reason, runtime_context, current in itertools.product(
        [None, "", "detector says no"], compositions[:2], ["allow", "review"]
    ):
        cases.append(
            {
                **base,
                "current_action": current,
                "trusted": ctx,
                "runtime_detector_context": runtime_context,
                "runtime_detector_block_reason": block_reason,
            }
        )
    for configured, scanner, raw in [("block", None, "warn"), ("allow", "require-reapproval", "require_reapproval")]:
        cases.append(
            {**base, "configured_action": configured, "scanner_action": scanner, "raw_scoring_recommendation": raw}
        )
    return cases


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--oracle", action="store_true")
    parser.add_argument("--base-src", type=Path)
    parser.add_argument("--native-binary", required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.oracle:
        print(json.dumps(_oracle(json.loads(sys.stdin.read()), args.native_binary), sort_keys=True))
        return
    _bind_resident(args.native_binary)
    cases = _current_cases() + _runtime_cases(_tokens())
    env = {**os.environ, "PYTHONPATH": str(args.base_src)}
    done = subprocess.run(
        [sys.executable, str(Path(__file__).resolve()), "--oracle", "--native-binary", args.native_binary],
        input=json.dumps(cases),
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    if done.returncode != 0:
        raise SystemExit(done.stderr)
    expected = json.loads(done.stdout)
    lines = [
        json.dumps(
            {"expected": answer, "name": f"{case['kind']}.{index}", "query": _capture_query(case)},
            sort_keys=True,
            separators=(",", ":"),
        )
        for index, (case, answer) in enumerate(zip(cases, expected, strict=True))
    ]
    args.output.write_text("[\n" + ",\n".join(lines) + "\n]\n", encoding="utf-8")


if __name__ == "__main__":
    main()
