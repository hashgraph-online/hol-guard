"""Compile published generic rules after exact installation targeting."""

from __future__ import annotations

import json

from ..models import PolicyDecision
from ..policy_document import GuardPolicyDocument
from ..policy_document_compile import compile_policy_document
from ..policy_document_types import PolicyCompilationError


def build_canonical_policy_bundle_decisions(
    policy_bundle: dict[str, object],
    *,
    device_id: str,
    device_name: str,
) -> list[PolicyDecision]:
    payload = policy_bundle.get("payload")
    if not isinstance(payload, dict):
        raise PolicyCompilationError("missing_policy_bundle_payload", "policy-bundle")
    local_document = json.loads(json.dumps(payload))
    spec = local_document.get("spec")
    if not isinstance(spec, dict):
        raise PolicyCompilationError("invalid_policy_spec", "policy-bundle")
    rules = spec.get("rules")
    if not isinstance(rules, list):
        raise PolicyCompilationError("invalid_policy_rules", "policy-bundle")
    local_rules: list[object] = []
    for raw_rule in rules:
        if not isinstance(raw_rule, dict):
            continue
        # Extension-targeted rules are compiled by the Managed Controls
        # authority path. Materializing them again as generic policy rows can
        # reject valid Extension outcomes (for example ``review``) or apply a
        # second, semantically different enforcement decision.
        if "x-hol-extension-targets" in raw_rule:
            continue
        match = raw_rule.get("match")
        if not isinstance(match, dict):
            local_rules.append(raw_rule)
            continue
        devices = match.get("devices")
        if isinstance(devices, list) and devices:
            device_selectors = {str(value) for value in devices}
            if device_id not in device_selectors:
                continue
            match.pop("devices", None)
        local_rules.append(raw_rule)
    spec["rules"] = local_rules
    document = GuardPolicyDocument.from_mapping(local_document)
    decisions: list[PolicyDecision] = []
    for row in compile_policy_document(document):
        decision = row.decision
        decisions.append(
            PolicyDecision(
                harness=decision.harness,
                scope=decision.scope,
                action=decision.action,
                artifact_id=decision.artifact_id,
                artifact_hash=decision.artifact_hash,
                exact_command_sha256=decision.exact_command_sha256,
                workspace=decision.workspace,
                publisher=decision.publisher,
                reason=decision.reason,
                owner=row.rule_id,
                source="policy-bundle-canonical",
                expires_at=decision.expires_at,
            )
        )
    return decisions
