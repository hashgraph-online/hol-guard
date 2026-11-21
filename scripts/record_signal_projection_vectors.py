"""Record signal and persistence projection outcomes from pinned Python source."""

from __future__ import annotations

import hashlib
import itertools
import json
import subprocess
import sys
from copy import deepcopy
from dataclasses import asdict
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]
BASE = "55e051a711550e55d0dad5991c5bc63918946bfa"
SOURCES = {
    "runtime/signals.py": "1d200371b9898ec1bb2205e5146eb18c70445417cf245024d7c4342c0bffe85c",
    "runtime/decisions.py": "deff9f12e7d0be568f1e0531627d3b41479fdce4690f118d7293053bbb53bded",
    "decision_projection_boundaries.py": "7882c11404caa5388afbf8f2262b6fa1804b76ad824a59f8f823387f80cad8cd",
    "decision_boundaries.py": "411d6e1e3a400955c466de1338c3725c60fb8458d321342c7f448cd3c64eca2f",
}
modules = {}
for source, digest in SOURCES.items():
    path = "src/codex_plugin_scanner/guard/" + source
    raw = subprocess.run(["git", "show", f"{BASE}:{path}"], cwd=ROOT, capture_output=True, check=True).stdout
    if hashlib.sha256(raw).hexdigest() != digest:
        raise SystemExit("reference source digest mismatch: " + source)
    name = "codex_plugin_scanner.guard." + source.removesuffix(".py").replace("/", ".")
    module = ModuleType(name)
    module.__package__ = name.rsplit(".", 1)[0]
    sys.modules[name] = module
    exec(compile(raw, path, "exec"), module.__dict__)
    modules[source] = module
decisions = modules["runtime/decisions.py"]
approval = modules["decision_projection_boundaries.py"]
boundaries = modules["decision_boundaries.py"]


def evaluate(kind, args):
    try:
        if kind == "projection_artifact_surfaces":
            artifact = args["artifact"]
            decisions.authoritative_decision_from_artifact(artifact)
            return {
                "status": "ok",
                "value": asdict(
                    boundaries.canonical_approval_surfaces(
                        artifact.get("policy_action"),
                        artifact.get("decision_v2_json"),
                        artifact.get("action_envelope_json"),
                        reject_contradiction=True,
                    )
                ),
            }
        function = {
            "projection_approval": approval.canonical_approval_decision,
            "projection_receipt": boundaries.canonical_receipt_decision,
            "projection_surfaces": boundaries.canonical_approval_surfaces,
        }[kind]
        values = [args["action"]]
        if kind != "projection_receipt":
            values.append(args["decision"])
        if kind != "projection_approval":
            values.append(args["envelope"])
        value = asdict(function(*values, reject_contradiction=args["reject"]))
        return {"status": "ok", "value": value}
    except (ValueError, TypeError, KeyError) as error:
        return {"status": "error", "error_type": type(error).__name__, "message": str(error)}


def main():
    vectors = []

    def record(kind, args):
        vectors.append({"kind": kind, "args": deepcopy(args), "expected": evaluate(kind, args)})

    v2 = dict(
        signal_id="fixture:signal",
        category="policy",
        severity="info",
        confidence="likely",
        detector="fixture",
        title="Guard risk signal",
        plain_reason="fixture reason",
        technical_detail=None,
        evidence_ref=None,
        redaction_level="summary",
        false_positive_hint=None,
        advisory_id=None,
    )
    for action, reject in itertools.product(
        ("allow", "warn", "review", "require-reapproval", "sandbox-required", "block", "ask", "unknown", None, 0),
        (False, True),
    ):
        sample = decisions.decision_from_legacy_policy_action("review", reason="fixture reason").to_dict()
        degraded = {**sample, "detail_reason_code": "remembered_rule_ignored_degraded_trust"}
        message = "The remembered local rule was ignored. One-time approvals still work."
        degraded.update(harness_message=message, dashboard_primary_detail=message)
        raw_decisions = [None, {}, [], "invalid", sample, degraded]
        for field in ("guard_action", "action", "futureAction", "preExecutionResult"):
            raw_decisions.extend({field: value} for value in ("allow", "ask", "block", "unknown", None))
        raw_decisions.extend(
            [
                {"signals": [{}, v2, {**v2, "category": "bad"}, [], {**v2, "signal_id": "\u001c"}]},
                {"policyVersion": "v1", "package_review_cloud_reason_code": "cloud_timeout"},
                {"policyVersion": " ", "package_review_cloud_reason_code": "unknown"},
                {"reason": "\u001c"},
                {"reason": "\u200b"},
            ]
        )
        envelopes = [None, {}, [], "invalid", {"observed_policy_action": "block"}, {"policy_action": None}]
        for field in (
            "policy_action",
            "pre_execution_result",
            "observed_policy_action",
            "futureAction",
            "policyAction",
        ):
            envelopes.extend({field: value} for value in ("allow", "ask", "block", "unknown", None))
        envelopes.extend(
            [
                {snake: "allow", camel: "block"}
                for snake, camel in (
                    ("policy_action", "policyAction"),
                    ("action_id", "actionId"),
                    ("action_type", "actionType"),
                    ("pre_execution_result", "preExecutionResult"),
                    ("observed_policy_action", "observedPolicyAction"),
                )
            ]
        )
        for decision in raw_decisions:
            record("projection_approval", {"action": action, "decision": decision, "reject": reject})
        for envelope in envelopes:
            record("projection_receipt", {"action": action, "envelope": envelope, "reject": reject})
        for decision, envelope in itertools.product(raw_decisions[:8], envelopes[:8]):
            record(
                "projection_surfaces", {"action": action, "decision": decision, "envelope": envelope, "reject": reject}
            )
    artifact_reference = json.loads((ROOT / "tests/fixtures/decision_authority_vectors.json").read_text())
    for vector in artifact_reference["vectors"]:
        if vector["kind"] == "decision_artifact_decode" and isinstance(vector["args"].get("payload"), dict):
            record("projection_artifact_surfaces", {"artifact": vector["args"]["payload"]})
    result = {
        "schema": "signal-projection-reference.v1",
        "reference_commit": BASE,
        "source_sha256": SOURCES,
        "vectors": vectors,
    }
    (ROOT / "tests/fixtures/signal_projection_vectors.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=True) + "\n"
    )
    print(f"Recorded {len(vectors)} old Python signal/projection outcomes")


if __name__ == "__main__":
    main()
