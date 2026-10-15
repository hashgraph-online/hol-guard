#!/usr/bin/env python3
"""Record consumer artifact projection vectors from the retired Python logic.

The expected answers come only from the consumer helpers that existed before
the resident owned this projection (a scratch checkout of the base commit,
passed as ``--base-src``): ``normalize_artifact_capabilities``,
``compute_capability_delta``, ``diff_artifact``, ``build_history_context``,
``build_provenance_bundle``, ``build_incident_context`` and the result-row
assembly that was inline in ``evaluate_detection``. They are never produced
by the new Rust op, so the vectors stay an independent oracle for it.

Usage:
    record_consumer_artifact_project_vectors.py --base-src <base-checkout>/src \
        --output <file>
"""

from __future__ import annotations

import argparse
import gzip
import importlib
import itertools
import json
import random
import sys
from pathlib import Path
from typing import Any

from record_consumer_artifact_project_data import (
    ACTIONS,
    ARTIFACTS,
    BEFORES,
    CONFIGS,
    FIELD_SETS,
    HARNESSES,
    HISTORIES,
    ID,
    LAUNCHES,
    PATH,
    RISKS,
    SCOPES,
    SNAPSHOT_EDITS,
    STRUCTURED_BASES,
    STRUCTURED_SUMMARIES,
    TYPES,
)
from record_consumer_artifact_project_wire import Store, make, snapshot, wire_artifact, wire_history


def _evidence_case(name: str, current: Any, before: Any, edit: str, history_name: str) -> dict[str, Any]:
    # The module only exists in the base checkout this recorder runs against.
    capabilities = importlib.import_module("codex_plugin_scanner.guard.capabilities")
    compute_capability_delta = capabilities.compute_capability_delta
    normalize_artifact_capabilities = capabilities.normalize_artifact_capabilities
    from codex_plugin_scanner.guard.consumer import service

    history = HISTORIES[history_name]
    store = Store(history)
    previous = snapshot(service, before, edit) if before is not None else None
    previous_caps = normalize_artifact_capabilities(before) if before is not None else None
    diff = service.diff_artifact(previous, current)
    capabilities = normalize_artifact_capabilities(current)
    deltas = compute_capability_delta(previous_caps, capabilities)
    context = service.build_history_context(store, current.harness, current.artifact_id, current.publisher)
    provenance = service.build_provenance_bundle(store, current.publisher)
    scoring = service._scoring_inputs((), deltas, provenance, context)
    scoring.pop("signals")
    payload = service._serialize_artifact(current)
    expected = {
        "changed": diff["changed"],
        "first_seen": diff["changed_fields"] == ["first_seen"],
        "diff_summary": service._build_diff_summary(diff),
        "changed_fields": diff["changed_fields"],
        "previous_hash": diff["previous_hash"],
        "current_hash": diff["current_hash"],
        "capabilities_summary": service._capabilities_summary(current),
        "changed_capabilities": [delta.delta_type for delta in deltas] or list(diff["changed_fields"]),
        "provenance_summary": (
            f"{current.source_scope} artifact defined at {current.config_path} (provenance: {provenance.source_kind})"
        ),
        "scoring": scoring,
        "capability_snapshot": capabilities.to_dict(),
        "capability_delta": [delta.to_dict() for delta in deltas],
        "history_context": context.to_dict(),
        "provenance": provenance.to_dict(),
    }
    query = {
        "kind": "artifact_evidence",
        "artifact": wire_artifact(current),
        "current_payload": payload,
        "payload_keys": list(payload),
        "current_hash": diff["current_hash"],
        "previous_snapshot": previous,
        "previous_capabilities": previous_caps.to_dict() if previous_caps is not None else None,
        "history": wire_history(history, current.publisher),
    }
    return {"name": name, "query": query, "expected": expected}


def _evidence_cases() -> list[dict[str, Any]]:
    cases = []
    for (artifact_name, base), (before_name, change) in itertools.product(ARTIFACTS.items(), BEFORES.items()):
        current = make(base)
        before = None if change is None else make(base, change)
        history_name = ("none", "item", "known-good", "flagged")[len(cases) % 4]
        cases.append(
            _evidence_case(f"{artifact_name}/{before_name}/{history_name}", current, before, "keep", history_name)
        )
    rng = random.Random(4217)
    for artifact_name, base in ARTIFACTS.items():
        for edit in SNAPSHOT_EDITS[1:]:
            for history_name in HISTORIES:
                before = make(base, {"args": ("prev",)} if rng.random() < 0.5 else {})
                name = f"{artifact_name}/{edit}/{history_name}"
                cases.append(_evidence_case(name, make(base, {"publisher": "acme"}), before, edit, history_name))
    return cases


def _incident_cases() -> list[dict[str, Any]]:
    from codex_plugin_scanner.guard.incident import build_incident_context

    rng = random.Random(881)
    cases = []
    artifact_names = list(ARTIFACTS)
    for index in range(900):
        kind = rng.choice(TYPES)
        artifact_name = rng.choice([*artifact_names, None, None])
        artifact = None if artifact_name is None else make(ARTIFACTS[artifact_name])
        fields: dict[str, Any] = {
            "harness": rng.choice(HARNESSES),
            "artifact": artifact,
            "artifact_id": rng.choice((ID, "id with space", "x")),
            "artifact_name": rng.choice(("", "tool", "naïve", "a`b")),
            "artifact_type": kind,
            "source_scope": rng.choice(SCOPES),
            "config_path": rng.choice(CONFIGS),
            "changed_fields": list(rng.choice(FIELD_SETS)),
            "policy_action": rng.choice(ACTIONS),
            "launch_target": rng.choice(LAUNCHES),
            "risk_summary": rng.choice(RISKS),
        }
        expected = build_incident_context(**fields)
        query = {
            "kind": "incident_context",
            **{key: value for key, value in fields.items() if key != "artifact"},
            "artifact": wire_artifact(artifact) if artifact is not None else None,
        }
        cases.append({"name": f"incident-{index}", "query": query, "expected": dict(expected)})
    return cases


def _runtime(rng: random.Random) -> dict[str, Any]:
    status = rng.choice(("none", "reused", "claimed"))
    return {
        "approval_reuse": {"status": status, "reason_code": rng.choice((None, "exact_context", "stale"))},
        "approval_claim": rng.choice((None, {"claim": "x", "n": 1})),
        "scanner_evidence": rng.choice(([], [{"detector": "d", "score": 0.5}])),
        "trusted_request_override": rng.choice((True, False, None)),
    }


def _verdict(rng: random.Random) -> dict[str, Any]:
    return {
        "action": rng.choice(("allow", "warn", "block")),
        "reasons": ["a", "b"][: rng.randint(0, 2)],
        "confidence": rng.choice((0.25, 0.7, 1.0)),
        "severity": rng.randint(0, 9),
        "evidence_sources": rng.choice(([], ["history"], ["scoring", "capability"])),
        "provenance_state": rng.choice(("none", "curated")),
        "recommended_next_actions": rng.choice(([], ["review_artifact"])),
        "suppressible": rng.choice((True, False)),
        "review_priority": rng.choice(("low", "high")),
    }


def _decision(rng: random.Random, action: str) -> Any:
    from codex_plugin_scanner.guard.runtime.decisions import build_authoritative_decision

    return build_authoritative_decision(
        action,
        reason=rng.choice(("because", "exact_approval")),
        composition_trace={"base": "x", "n": rng.randint(0, 3)},
        authority_finalized=rng.choice((True, False)),
    )


def _result_case(rng: random.Random, index: int, artifact: Any) -> dict[str, Any]:
    from codex_plugin_scanner.guard.incident import build_incident_context

    action = rng.choice(ACTIONS)
    decision = _decision(rng, action)
    evidence = _evidence_case("e", artifact, None, "keep", rng.choice(list(HISTORIES)))["expected"]
    verdict, runtime = _verdict(rng), _runtime(rng)
    risk_summary = rng.choice(RISKS[1:])
    scanner_action = rng.choice((None, "warn", "allow"))
    signals = rng.choice(([], [{"signal_id": "s1", "severity": 5}]))
    risk_signals = rng.choice(([], ["plain reason"]))
    workspace = rng.choice((None, "/work/space"))
    from codex_plugin_scanner.guard.consumer import service

    launch = service._launch_target_from_artifact(artifact)
    incident = build_incident_context(
        harness="codex",
        artifact=artifact,
        artifact_id=artifact.artifact_id,
        artifact_name=artifact.name,
        artifact_type=artifact.artifact_type,
        source_scope=artifact.source_scope,
        config_path=artifact.config_path,
        changed_fields=list(evidence["changed_fields"]),
        policy_action=decision.action,
        launch_target=launch,
        risk_summary=risk_summary,
    )
    override = runtime["trusted_request_override"] is True
    row = {
        "artifact_id": artifact.artifact_id,
        "artifact_name": artifact.name,
        "changed": evidence["changed"],
        "changed_fields": evidence["changed_fields"],
        **decision.to_artifact_projection(),
        "artifact_hash": evidence["current_hash"],
        "approval_context_hash": f"ctx-{index}",
        "effective_workspace": workspace,
        "approval_reuse_status": runtime["approval_reuse"]["status"],
        "approval_reuse_reason_code": runtime["approval_reuse"]["reason_code"],
        "approval_reuse": dict(runtime["approval_reuse"]),
        "scanner_evidence": list(runtime["scanner_evidence"]),
        "trusted_request_override": {
            "applied": override,
            "reason_code": "trusted_request_override_exact_context" if override else None,
        },
        **({"approval_claim": runtime["approval_claim"]} if runtime["approval_claim"] is not None else {}),
        "scoring_recommendation": {
            "non_authoritative": True,
            "action": verdict["action"],
            "mapped_guard_action": scanner_action,
            "reasons": list(verdict["reasons"]),
            "confidence": verdict["confidence"],
            "severity": verdict["severity"],
            "evidence_sources": list(verdict["evidence_sources"]),
        },
        "risk_signals": list(risk_signals),
        "risk_summary": risk_summary,
        "signals": signals,
        "confidence": verdict["confidence"],
        "severity": verdict["severity"],
        "evidence_sources": list(verdict["evidence_sources"]),
        "provenance_state": verdict["provenance_state"],
        "provenance": evidence["provenance"],
        "history_context": evidence["history_context"],
        "capability_snapshot": evidence["capability_snapshot"],
        "capability_delta": evidence["capability_delta"],
        "remediation": list(verdict["recommended_next_actions"]),
        "suppressibility": verdict["suppressible"],
        "review_priority": verdict["review_priority"],
        "artifact_type": artifact.artifact_type,
        "config_path": artifact.config_path,
        "source_scope": artifact.source_scope,
        **{key: incident[key] for key in _INCIDENT_KEYS},
    }
    query = {
        "kind": "artifact_result",
        "harness": "codex",
        "artifact": wire_artifact(artifact),
        "evidence": evidence,
        "projection": decision.to_artifact_projection(),
        "verdict": verdict,
        "scanner_action": scanner_action,
        "runtime": runtime,
        "signals": signals,
        "risk_signals": risk_signals,
        "risk_summary": risk_summary,
        "approval_context_hash": f"ctx-{index}",
        "effective_workspace": workspace,
        "policy_action": decision.action,
    }
    return {"name": f"result-{index}", "query": query, "expected": row}


def _result_cases() -> list[dict[str, Any]]:
    rng = random.Random(2209)
    cases = []
    for index in range(120):
        artifact = make(ARTIFACTS[rng.choice(list(ARTIFACTS))])
        cases.append(_result_case(rng, index, artifact))
    return cases


_INCIDENT_KEYS = ("artifact_label", "source_label", "trigger_summary", "why_now", "launch_summary", "risk_headline")


def _removed_cases() -> list[dict[str, Any]]:
    from codex_plugin_scanner.guard.consumer import service
    from codex_plugin_scanner.guard.incident import build_incident_context
    from codex_plugin_scanner.guard.types import HistoryContext, ProvenanceBundle

    rng = random.Random(7741)
    previous_options = (
        {"name": "gone", "artifact_type": "mcp_server", "source_scope": "project", "config_path": PATH},
        {"artifact_type": "hook_group"},
        {"source_scope": "global", "name": "n", "config_path": "C:\\x\\y.toml"},
        {},
        {"name": 5, "artifact_type": 7, "source_scope": None, "config_path": None},
    )
    cases = []
    for index in range(60):
        previous = dict(rng.choice(previous_options))
        action = rng.choice(ACTIONS)
        decision = _decision(rng, action)
        runtime = _runtime(rng)
        authority = rng.choice((True, False))
        detail = rng.choice(("runtime detail", "other"))
        signals = rng.choice(([], [{"signal_id": "s2"}]))
        risk_signals = rng.choice(([], ["runtime reason"]))
        artifact_id = rng.choice((ID, "removed-id"))
        name = previous.get("name")
        scope, path = previous.get("source_scope"), previous.get("config_path")
        kind_value = previous.get("artifact_type")
        kind = str(kind_value) if isinstance(kind_value, str) else "artifact"
        summary = detail if authority else "Artifact was removed from the harness configuration."
        incident = build_incident_context(
            harness="codex",
            artifact=None,
            artifact_id=artifact_id,
            artifact_name=str(name) if isinstance(name, str) else artifact_id,
            artifact_type=kind,
            source_scope=str(scope) if isinstance(scope, str) else None,
            config_path=str(path) if isinstance(path, str) else None,
            changed_fields=["removed"],
            policy_action=decision.action,
            launch_target=None,
            risk_summary=summary,
        )
        override = runtime["trusted_request_override"] is True
        row = {
            "artifact_id": artifact_id,
            "artifact_name": str(name) if isinstance(name, str) else artifact_id,
            "changed": True,
            "changed_fields": ["removed"],
            **decision.to_artifact_projection(),
            "artifact_hash": f"prev-{index}",
            "approval_context_hash": f"ctx-{index}",
            "effective_workspace": "/work/space",
            "approval_reuse_status": runtime["approval_reuse"]["status"],
            "approval_reuse_reason_code": runtime["approval_reuse"]["reason_code"],
            "approval_reuse": dict(runtime["approval_reuse"]),
            "scanner_evidence": list(runtime["scanner_evidence"]),
            "trusted_request_override": {
                "applied": override,
                "reason_code": "trusted_request_override_exact_context" if override else None,
            },
            **({"approval_claim": runtime["approval_claim"]} if runtime["approval_claim"] is not None else {}),
            "scoring_recommendation": {
                "non_authoritative": True,
                "action": "warn",
                "mapped_guard_action": "warn",
                "reasons": ["Artifact removal should be reviewed for intentionality."],
                "confidence": 0.7,
                "severity": 3,
                "evidence_sources": ["history"],
            },
            "removed": True,
            "risk_signals": list(risk_signals) or ["artifact removed from local harness configuration"],
            "risk_summary": summary,
            "signals": signals,
            "confidence": 0.7,
            "severity": 3,
            "evidence_sources": ["history"],
            "provenance_state": "none",
            "provenance": ProvenanceBundle().to_dict(),
            "history_context": HistoryContext().to_dict(),
            "capability_snapshot": {},
            "capability_delta": [],
            "remediation": ["defer_and_notify_team"],
            "suppressibility": True,
            "review_priority": "low",
            "artifact_type": kind,
            "config_path": str(path) if isinstance(path, str) else None,
            "source_scope": str(scope) if isinstance(scope, str) else None,
            **{key: incident[key] for key in _INCIDENT_KEYS},
        }
        expected = {
            "receipt": {
                "capabilities_summary": service._removed_capabilities_summary(previous),
                "provenance_summary": service._build_removed_provenance(previous),
                "artifact_name": str(name) if isinstance(name, str) else artifact_id,
                "source_scope": str(scope) if isinstance(scope, str) else None,
            },
            "result": row,
        }
        query = {
            "kind": "removed_result",
            "harness": "codex",
            "artifact_id": artifact_id,
            "previous": previous,
            "previous_hash": f"prev-{index}",
            "projection": decision.to_artifact_projection(),
            "runtime": runtime,
            "signals": signals,
            "risk_signals": risk_signals,
            "has_runtime_authority": authority,
            "dashboard_detail": detail,
            "approval_context_hash": f"ctx-{index}",
            "effective_workspace": "/work/space",
            "policy_action": decision.action,
        }
        cases.append({"name": f"removed-{index}", "query": query, "expected": expected})
    return cases


def _structured_cases() -> list[dict[str, Any]]:
    """Non-string summaries: capability text sees them, launch and incident copy do not."""

    from codex_plugin_scanner.guard.consumer import service
    from codex_plugin_scanner.guard.incident import build_incident_context

    rng = random.Random(5150)
    cases = []
    index = 1000
    for (label, summaries), (base_name, base) in itertools.product(
        STRUCTURED_SUMMARIES.items(), STRUCTURED_BASES.items()
    ):
        artifact = make(base, {"metadata": dict(summaries)})
        stem = f"{label}-{base_name}"
        evidence = _evidence_case(f"structured-evidence-{stem}", artifact, None, "keep", "none")
        launch = service._launch_target_from_artifact(artifact)
        incidents = []
        for launch_target in (None, launch):
            fields: dict[str, Any] = {
                "harness": "codex",
                "artifact": artifact,
                "artifact_id": artifact.artifact_id,
                "artifact_name": artifact.name,
                "artifact_type": artifact.artifact_type,
                "source_scope": artifact.source_scope,
                "config_path": artifact.config_path,
                "changed_fields": ["args"],
                "policy_action": rng.choice(ACTIONS),
                "launch_target": launch_target,
                "risk_summary": None,
            }
            expected = build_incident_context(**fields)
            query = {
                "kind": "incident_context",
                **{key: value for key, value in fields.items() if key != "artifact"},
                "artifact": wire_artifact(artifact),
            }
            name = f"structured-incident-{stem}-{launch_target is None}"
            incidents.append({"name": name, "query": query, "expected": dict(expected)})
        result = _result_case(rng, index, artifact)
        result["name"] = f"structured-result-{stem}"
        index += 1
        for case in (evidence, *incidents, result):
            case["source_metadata"] = dict(summaries)
            cases.append(case)
    return cases


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-src", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.base_src))
    cases = [*_evidence_cases(), *_incident_cases(), *_result_cases(), *_removed_cases(), *_structured_cases()]
    document = json.dumps(cases, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")
    # mtime=0 keeps the archive byte-identical across recordings.
    args.output.write_bytes(gzip.compress(document, mtime=0))
    print(f"recorded {len(cases)} vectors")


if __name__ == "__main__":
    main()
