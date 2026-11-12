"""Factories shared by the workflow-capability vector scenarios (recorder only)."""

from __future__ import annotations

import hashlib
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from codex_plugin_scanner.guard.workflow_capabilities import (
    WORKFLOW_CAPABILITY_ALGORITHM,
    WORKFLOW_CAPABILITY_SCHEMA,
    SignedWorkflowCapability,
    WorkflowCapabilityBinding,
    WorkflowCapabilityClaim,
    WorkflowCapabilityError,
    WorkflowCapabilityRuleBinding,
    format_utc_timestamp,
)

# The resident signs capabilities in production; these vectors need a local
# signer to build the envelopes the resident must accept or reject.
sys.path.insert(0, str(Path(__file__).resolve().parents[5] / "tests"))

from workflow_capability_frame_support import sign_workflow_capability

KEY = b"k" * 32
KEY_ID = "guard-policy-integrity-key:test"
OTHER_KEY = b"o" * 32
OTHER_KEY_ID = "guard-policy-integrity-key:other"
ISSUED = datetime(2026, 7, 19, 12, tzinfo=timezone.utc)


def at(minutes: int) -> str:
    return format_utc_timestamp(ISSUED + timedelta(minutes=minutes))


def binding(**changes: object) -> WorkflowCapabilityBinding:
    values: dict[str, object] = {
        "operation_id": "test.run",
        "resource_type": "test-file-set",
        "resource_sha256": "1" * 64,
        "repository_sha256": "2" * 64,
        "workspace_sha256": "3" * 64,
        "executable_sha256": "4" * 64,
        "launch_sha256": "5" * 64,
        "policy_id": "local.command-policy",
        "policy_version": "policy.v7",
        "effect_id": "command.effect",
        "effect_version": "effect.v2",
        "decision_id": "decision.exact-local",
        "decision_version": "decision.v3",
    }
    values.update(changes)
    return WorkflowCapabilityBinding(
        rules=(
            WorkflowCapabilityRuleBinding("command.exact", "v2"),
            WorkflowCapabilityRuleBinding("workspace.bound", "v1"),
        ),
        **values,  # type: ignore[arg-type]
    )


def claim(capability_id: str = "wc-test-1", max_uses: int = 1, **changes: object) -> WorkflowCapabilityClaim:
    values: dict[str, object] = {
        "schema_version": WORKFLOW_CAPABILITY_SCHEMA,
        "algorithm": WORKFLOW_CAPABILITY_ALGORITHM,
        "capability_id": capability_id,
        "approval_provenance_id": f"provenance-{capability_id}",
        "task_id": "task-local-check",
        "nonce": hashlib.sha256(capability_id.encode("ascii")).hexdigest(),
        "issuer_id": "guard.local",
        "subject_id": "codex.local",
        "binding": binding(),
        "issued_at": at(0),
        "not_before": at(0),
        "expires_at": at(60),
        "max_uses": max_uses,
    }
    values.update(changes)
    return WorkflowCapabilityClaim(**values)  # type: ignore[arg-type]


def signed(capability_id: str = "wc-test-1", max_uses: int = 1, **changes: object) -> SignedWorkflowCapability:
    return sign_workflow_capability(claim(capability_id, max_uses, **changes), key=KEY, key_id=KEY_ID)


def issue(capability_id: str = "wc-test-1", *, now: int = 1, max_uses: int = 1, **changes: object) -> dict[str, object]:
    capability = signed(capability_id, max_uses, **changes)
    return {
        "op": "issue",
        "label": f"issue {capability_id}",
        "signed": capability,
        "approval_provenance_id": capability.claim.approval_provenance_id,
        "now": at(now),
    }


def claim_step(
    capability_id: str = "wc-test-1",
    *,
    invocation_id: str,
    now: int = 2,
    expected_binding: WorkflowCapabilityBinding | None = None,
    max_uses: int = 1,
    **expected: str,
) -> dict[str, object]:
    try:
        base = claim(capability_id, max_uses)
    except WorkflowCapabilityError:
        base = claim("wc-invalid-id-base", max_uses)
    step: dict[str, object] = {
        "op": "claim",
        "label": f"claim {capability_id} {invocation_id}",
        "capability_id": capability_id,
        "invocation_id": invocation_id,
        "expected_binding": base.binding if expected_binding is None else expected_binding,
        "expected_subject_id": base.subject_id,
        "expected_task_id": base.task_id,
        "expected_issuer_id": base.issuer_id,
        "expected_approval_provenance_id": base.approval_provenance_id,
        "now": at(now),
    }
    step.update(expected)
    return step


def revoke(
    capability_id: str = "wc-test-1", *, now: int = 3, reason_code: str = "operator.revoked"
) -> dict[str, object]:
    return {
        "op": "revoke",
        "label": f"revoke {capability_id}",
        "capability_id": capability_id,
        "reason_code": reason_code,
        "now": at(now),
    }


def lookup(capability_id: str = "wc-test-1", *, now: int = 4) -> dict[str, object]:
    return {"op": "lookup", "label": f"lookup {capability_id}", "capability_id": capability_id, "now": at(now)}


def receipt_lookup(
    *, receipt_id: str | None = None, invocation_id: str | None = None, now: int = 4
) -> dict[str, object]:
    return {
        "op": "receipt_lookup",
        "label": "receipt lookup",
        "receipt_id": receipt_id,
        "invocation_id": invocation_id,
        "now": at(now),
    }


def sql(label: str, *statements: tuple[str, tuple[object, ...]]) -> dict[str, object]:
    return {"op": "sql", "label": label, "statements": list(statements)}


def autotime(scenario: dict[str, object]) -> dict[str, object]:
    """Give every store call a strictly later clock than the one before it."""

    steps: list[dict[str, object]] = []
    minute = 5
    for step in scenario["steps"]:  # type: ignore[attr-defined]
        if "now" in step:
            step = {**step, "now": at(minute)}
            minute += 1
        steps.append(step)
    return {**scenario, "steps": steps}
