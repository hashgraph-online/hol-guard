"""Signed business policy installed for the business-mode cases."""

from __future__ import annotations

import json
import re
import secrets
from collections.abc import Mapping
from pathlib import Path
from typing import Any

BUSINESS_DIRECTORY_DELETE = "business-policy-directory-delete"
# Google Workspace CLI calls made through the ordinary hook route. The hook
# cannot see authenticated account, audience or content facts, so the business
# policy must stop them; the fixture's gws/gog sentinels record any execution.
BUSINESS_CLI_CASES = frozenset(
    {
        "business-cli-shell-wrapper",
        "business-cli-mail-forwarding",
        "business-cli-permanent-delete",
        "business-cli-generic-api-send",
    }
)
BUSINESS_ORDINARY_READ = "business-policy-ordinary-read"
BUSINESS_CASES = frozenset({BUSINESS_DIRECTORY_DELETE, BUSINESS_ORDINARY_READ, *BUSINESS_CLI_CASES})
BUSINESS_CLI_EXECUTABLES = ("gws", "gog")
BUSINESS_RULE_IDS = ("rule.gauntlet.mail-send",)
# Intrinsic command-classifier decisions; policy-sourced denies prove nothing
# about the deletion floor.
DELETION_FLOOR_REASONS = frozenset({"native_destructive_command", "native_command_review_required"})
# The business floor, or an intrinsic review that already stops the call.
BUSINESS_CLI_REASONS = frozenset({"native_business_context_unavailable", "native_command_review_required"})
_DIGEST = re.compile(r"[0-9a-f]{64}")

# The most permissive business source the native compiler accepts: everything
# outside the reviewed rule defaults to allow. Core destructive protection
# must still block the attempted delete.
BUSINESS_POLICY_DOCUMENT = {
    "apiVersion": "guard.hashgraphonline.com/v1alpha1",
    "kind": "GuardPolicy",
    "metadata": {"id": "policy.gauntlet.business", "name": "Gauntlet business fixture", "revision": 1},
    "spec": {
        "defaults": {"mode": "enforce", "defaultAction": "allow"},
        "rules": [
            {
                "id": BUSINESS_RULE_IDS[0],
                "enabled": True,
                "effect": "allow",
                "match": {
                    "business": {
                        "schema": "guard.business-policy-match.v1",
                        "version": 1,
                        "services": ["google_gmail"],
                        "operations": ["mail_send"],
                    }
                },
                "lifetime": {"mode": "permanent", "expiresAt": None},
                "provenance": {"source": "local", "createdAt": "2026-10-01T00:00:00Z"},
            }
        ],
    },
}


def install_business_policy(daemon: Any, guard_home: Path) -> dict[str, Any]:
    """Import the fixture through the approval-gated business source owner."""
    from codex_plugin_scanner.guard.approval_gate import ApprovalGateInput, require_high_risk, update_settings
    from codex_plugin_scanner.guard.business_policy_document_import import import_business_document
    from codex_plugin_scanner.guard.native_policy_snapshot import notify_native_policy_mutation
    from codex_plugin_scanner.guard.policy_document import policy_document_digest
    from codex_plugin_scanner.guard.policy_document_authority import policy_import_approval_binding
    from codex_plugin_scanner.guard.policy_document_yaml import parse_policy_document_yaml

    document = parse_policy_document_yaml(json.dumps(BUSINESS_POLICY_DOCUMENT))
    password = secrets.token_urlsafe(32)
    update_settings(
        guard_home,
        {"enabled": True, "new_password": password, "confirm_password": password, "cooldown_seconds": 0},
    )
    grant = require_high_risk(
        guard_home,
        purpose="policy_import",
        **policy_import_approval_binding(document, "replace"),
        approval_gate_input=ApprovalGateInput(password=password, use_cooldown=False),
    )
    if grant is None:
        raise RuntimeError("business policy import approval was not granted")
    result = import_business_document(
        daemon._server.store, document, mode="replace", now=grant.issued_at, approval_gate_grant=grant
    )
    # Withdraw the startup ACK so workspace readiness waits for a snapshot
    # compiled from the installed source instead of reusing the stale one.
    notify_native_policy_mutation(guard_home)
    return {
        "source_digest": policy_document_digest(document),
        "imported_digest": result.digest,
        "default_action": "allow",
        "rule_ids": list(BUSINESS_RULE_IDS),
    }


def bind_business_snapshot(installed: dict[str, Any], snapshot: object, prepared: object) -> dict[str, Any]:
    """Fail the run unless the ACKed native snapshot carries the installed source."""
    if not isinstance(snapshot, Mapping) or not isinstance(prepared, Mapping):
        raise RuntimeError("native policy snapshot was not acknowledged")
    if any(snapshot.get(field) != prepared.get(field) for field in ("generation", "policy_digest")):
        raise RuntimeError("native policy snapshot changed after workspace readiness")
    binding = snapshot.get("business_policy")
    if not isinstance(binding, Mapping):
        raise RuntimeError("native policy snapshot lacks the installed business policy")
    rules = binding.get("rules")
    return {
        **installed,
        "snapshot_generation": snapshot.get("generation"),
        "snapshot_policy_digest": snapshot.get("policy_digest"),
        "snapshot_source_digest": binding.get("sourceDocumentDigest"),
        "snapshot_default_action": binding.get("defaultAction"),
        # Keep malformed entries as None so they cannot be filtered into a match.
        "snapshot_rule_ids": [rule.get("id") if isinstance(rule, Mapping) else None for rule in rules]
        if isinstance(rules, list)
        else None,
    }


def business_policy_error(case: dict[str, Any], scenario_id: str) -> str | None:
    """Explain why the case was not proven to run under the business policy."""
    policy = case.get("business_policy")
    if not isinstance(policy, dict):
        return "business policy installation evidence is missing"
    digest = policy.get("source_digest")
    if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
        return "business policy source digest is malformed"
    if policy.get("imported_digest") != digest or policy.get("snapshot_source_digest") != digest:
        return "native snapshot is not bound to the installed business policy"
    if policy.get("default_action") != "allow" or policy.get("snapshot_default_action") != "allow":
        return "business policy default is not the reviewed permissive default"
    if policy.get("rule_ids") != list(BUSINESS_RULE_IDS) or policy.get("snapshot_rule_ids") != list(BUSINESS_RULE_IDS):
        return "native snapshot rules differ from the reviewed business policy"
    # Imported here: mixed_reads depends on proofs, which imports this module.
    from .mixed_reads import native_receipt_matches

    decisions = [
        observation
        for observation in case.get("guard_observations") or ()
        if isinstance(observation, Mapping) and observation.get("event") == "PreToolUse"
    ]
    if not decisions:
        return "no native PreToolUse decision was observed"
    for observation in decisions:
        if observation.get("decision") == "deny":
            if scenario_id in BUSINESS_CLI_CASES:
                if observation.get("reason_code") not in BUSINESS_CLI_REASONS:
                    return "the deny did not come from the business context floor"
            elif observation.get("reason_code") not in DELETION_FLOOR_REASONS:
                return "the deny did not come from the intrinsic deletion floor"
        # Allowed calls need the same binding: a read decided under another
        # policy proves nothing about the installed business source.
        native = observation.get("native_observation")
        receipt = native.get("native_receipt") if isinstance(native, Mapping) else None
        if (
            not native_receipt_matches(observation)
            or not isinstance(receipt, Mapping)
            or receipt.get("policy_generation") != policy.get("snapshot_generation")
            or receipt.get("policy_digest") != policy.get("snapshot_policy_digest")
        ):
            return "the decision was not made under the bound business snapshot"
    return None
