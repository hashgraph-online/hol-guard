"""Record public decision behavior before retiring the Python implementation."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATH = "src/codex_plugin_scanner/guard/runtime/decisions.py"
SIGNAL_PATH = "src/codex_plugin_scanner/guard/runtime/signals.py"
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--reference", default="55e051a711550e55d0dad5991c5bc63918946bfa")
options = parser.parse_args()
reference = subprocess.run(
    ["git", "show", f"{options.reference}:{SOURCE_PATH}"], cwd=ROOT, capture_output=True, check=True
).stdout
if hashlib.sha256(reference).hexdigest() != "deff9f12e7d0be568f1e0531627d3b41479fdce4690f118d7293053bbb53bded":
    raise SystemExit("reference implementation digest mismatch")
signal_reference = subprocess.run(
    ["git", "show", f"{options.reference}:{SIGNAL_PATH}"], cwd=ROOT, capture_output=True, check=True
).stdout
if hashlib.sha256(signal_reference).hexdigest() != "1d200371b9898ec1bb2205e5146eb18c70445417cf245024d7c4342c0bffe85c":
    raise SystemExit("reference signal implementation digest mismatch")
old_signals = ModuleType("codex_plugin_scanner.guard.runtime._signal_reference")
old_signals.__package__ = "codex_plugin_scanner.guard.runtime"
sys.modules[old_signals.__name__] = old_signals
exec(compile(signal_reference, SIGNAL_PATH, "exec"), old_signals.__dict__)
RiskSignalV2 = old_signals.RiskSignalV2
old = ModuleType("codex_plugin_scanner.guard.runtime._decision_reference")
old.__package__ = "codex_plugin_scanner.guard.runtime"
sys.modules[old.__name__] = old
exec(compile(reference, SOURCE_PATH, "exec"), old.__dict__)
old.RiskSignalV2 = RiskSignalV2


def evaluate(kind: str, args: dict[str, object]) -> dict[str, object]:
    try:
        payload = args.get("payload", {})
        if kind == "decision_v2_decode":
            value = old.GuardDecisionV2.from_dict(payload).to_dict()
        elif kind == "decision_enforcement_decode":
            value = old.GuardDecisionEnforcementState.from_dict(payload).to_dict()
        elif kind == "decision_authoritative_decode":
            value = old.AuthoritativeGuardDecision.from_dict(payload).to_dict()
        elif kind == "decision_artifact_decode":
            value = old.authoritative_decision_from_artifact(
                payload, require_authoritative=args.get("require_authoritative", False)
            ).to_dict()
        else:
            signals = tuple(RiskSignalV2.from_dict(item) for item in args.get("signals", []))
            if kind == "decision_legacy":
                value = old.decision_from_legacy_policy_action(
                    args["action"], reason=args["reason"], signals=signals
                ).to_dict()
            elif kind == "decision_build":
                value = old.build_authoritative_decision(
                    args["action"],
                    reason=args["reason"],
                    signals=signals,
                    composition_trace=args["composition_trace"],
                    authority_finalized=args["authority_finalized"],
                    source=args.get("source", "composed-consumer-policy"),
                ).to_dict()
            else:
                raise AssertionError(kind)
        return {"status": "ok", "value": value}
    except (ValueError, TypeError, KeyError) as error:
        return {"status": "error", "error_type": type(error).__name__, "message": str(error)}


def main() -> None:
    vectors: list[dict[str, object]] = []

    def record(kind: str, args: dict[str, object]) -> dict[str, object]:
        expected = evaluate(kind, args)
        vectors.append({"kind": kind, "args": deepcopy(args), "expected": expected})
        return expected

    signal = {
        "signal_id": "fixture:signal",
        "category": "secret",
        "severity": "high",
        "confidence": "likely",
        "detector": "fixture.detector",
        "title": "Fixture signal",
        "plain_reason": "Synthetic evidence",
        "technical_detail": None,
        "evidence_ref": None,
        "redaction_level": "summary",
        "false_positive_hint": None,
        "advisory_id": None,
    }
    signal_sets = [[], [signal]]
    for confidence in ("weak", "possible", "likely", "strong"):
        variant = {**signal, "confidence": confidence}
        signal_sets.append([variant, {**signal, "confidence": "strong", "plain_reason": "Stronger evidence"}])
    for detail in (None, "Source-to-sink route: local secret -> HTTP endpoint."):
        signal_sets.append(
            [
                {
                    **signal,
                    "signal_id": "data-flow:fixture",
                    "detector": "data_flow.exfiltration",
                    "technical_detail": detail,
                }
            ]
        )

    for action in ("allow", "warn", "review", "require-reapproval", "sandbox-required", "block"):
        for signals in signal_sets:
            base = {"action": action, "reason": "fixture reason", "signals": signals}
            legacy = record("decision_legacy", base)
            if legacy["status"] == "ok":
                payload = legacy["value"]
                record("decision_v2_decode", {"payload": payload})
                for field in payload:
                    for replacement in (None, False, [], ""):
                        record("decision_v2_decode", {"payload": {**payload, field: replacement}})
            for finalized in (False, True):
                for trace in (
                    {},
                    {"configured_action": action, "current_action": action},
                    {"runtime_detector_action": "block"},
                ):
                    built = record(
                        "decision_build", {**base, "composition_trace": trace, "authority_finalized": finalized}
                    )
                    if built["status"] != "ok":
                        continue
                    payload = built["value"]
                    record("decision_authoritative_decode", {"payload": payload})
                    record("decision_enforcement_decode", {"payload": payload["enforcement"]})
                    artifact = {
                        "authoritative_decision": payload,
                        "policy_action": action,
                        "verdict_action": action,
                        "decision_v2_json": payload["decision_v2"],
                        "policy_composition": payload["composition_trace"],
                    }
                    record("decision_artifact_decode", {"payload": artifact})
        for key in ("policy_action", "verdict_action"):
            record("decision_artifact_decode", {"payload": {"policy_action": action, key: "block"}})
        for raw in (None, {}, [], "invalid"):
            record("decision_artifact_decode", {"payload": {"policy_action": action, "authoritative_decision": raw}})
        for field in ("policy_composition", "decision_v2_json", "action_envelope_json"):
            record("decision_artifact_decode", {"payload": {"policy_action": action, field: None}})
        record("decision_artifact_decode", {"payload": {"policy_action": action}, "require_authoritative": True})

    sample = old.build_authoritative_decision(
        "allow", reason="fixture reason", composition_trace={}, authority_finalized=True
    ).to_dict()
    for field in sample:
        missing = {key: value for key, value in sample.items() if key != field}
        record("decision_authoritative_decode", {"payload": missing})
        for replacement in (None, False, [], "", 2):
            record("decision_authoritative_decode", {"payload": {**sample, field: replacement}})
    for field in sample["enforcement"]:
        for replacement in (None, 0, 1, "false"):
            record("decision_enforcement_decode", {"payload": {**sample["enforcement"], field: replacement}})
        altered = deepcopy(sample)
        altered["enforcement"][field] = not altered["enforcement"][field]
        record("decision_authoritative_decode", {"payload": altered})
    for key in ("future_action", "launch_permitted", "policyAction", "other"):
        record("decision_v2_decode", {"payload": {**sample["decision_v2"], key: "allow"}})
        record("decision_authoritative_decode", {"payload": {**sample, key: "allow"}})
    for schema in (1.0, True, 0, "1"):
        record("decision_authoritative_decode", {"payload": {**sample, "schema_version": schema}})
    for reason in ("\u001c", "\u001d", "\u001e", "\u001f", "\u00a0", "\u2003", "\u200b", "reason \U0001f512"):
        record(
            "decision_build",
            {
                "action": "allow",
                "reason": reason,
                "signals": [],
                "composition_trace": {},
                "authority_finalized": True,
            },
        )
    consumer_path = "rust/crates/guard-runtime/tests/fixtures/consumer_artifact_compose_vectors.json"
    consumer_reference = subprocess.check_output(["git", "show", f"{options.reference}:{consumer_path}"], cwd=ROOT)
    if (
        hashlib.sha256(consumer_reference).hexdigest()
        != "dc1b734f34297eaa047ddd5f657ca9fbf3646b06ec6adcd8679336d913c035da"
    ):
        raise SystemExit("original consumer composition corpus digest mismatch")
    for vector in json.loads(consumer_reference):
        if vector["query"]["kind"] != "runtime_decision":
            continue
        composed = vector["expected"]
        args = {
            "action": composed["policy_action"],
            "reason": composed["decision_reason"],
            "composition_trace": composed["policy_composition"],
            "authority_finalized": composed["authority_finalized"],
            "signals": [],
        }
        vectors.append(
            {
                "kind": "decision_build",
                "args": args,
                "expected": evaluate("decision_build", args),
                "consumer_runtime_query": vector["query"],
                "consumer_runtime_expected": composed,
            }
        )
    result = {
        "schema": "decision-authority-reference.v1",
        "source": SOURCE_PATH,
        "reference_commit": options.reference,
        "source_sha256": hashlib.sha256(reference).hexdigest(),
        "signal_source_sha256": hashlib.sha256(signal_reference).hexdigest(),
        "consumer_corpus_sha256": hashlib.sha256(consumer_reference).hexdigest(),
        "vectors": vectors,
    }
    destination = ROOT / "tests/fixtures/decision_authority_vectors.json"
    destination.write_text(json.dumps(result, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    print(f"Recorded {len(vectors)} original-Python outcomes")


if __name__ == "__main__":
    main()
