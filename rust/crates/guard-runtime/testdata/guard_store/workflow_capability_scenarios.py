"""Behavioural scenarios for the workflow-capability store vectors (recorder only).

Each scenario runs through the ORIGINAL Python store. Receipt lookups use the
token `@last_receipt` for the receipt id returned by the latest claim.
"""

from __future__ import annotations

from dataclasses import replace

from workflow_capability_factories import (
    autotime,
    OTHER_KEY,
    OTHER_KEY_ID,
    at,
    binding,
    claim,
    claim_step,
    issue,
    lookup,
    receipt_lookup,
    revoke,
    signed,
    sign_workflow_capability,
)

LAST = "@last_receipt"


def _issue_bad_signature() -> dict[str, object]:
    step = issue("wc-bad-sig")
    step["signed"] = sign_workflow_capability(claim("wc-bad-sig"), key=OTHER_KEY, key_id=OTHER_KEY_ID)
    step["label"] = "issue signed with another key"
    return step


def _issue_tampered_claim() -> dict[str, object]:
    step = issue("wc-tamper")
    capability = signed("wc-tamper")
    object.__setattr__(capability.claim, "task_id", "task-forged")
    step["signed"] = capability
    step["label"] = "issue with forged claim body"
    return step


def _issue_key_id_mismatch() -> dict[str, object]:
    step = issue("wc-keyid")
    step["signed"] = replace(signed("wc-keyid"), key_id="guard-policy-integrity-key:unknown")
    step["label"] = "issue with unknown key id"
    return step


CONTEXT_DRIFT = (
    ("policy_version", "policy.v8"),
    ("policy_id", "local.other-policy"),
    ("effect_version", "effect.v3"),
    ("effect_id", "command.other-effect"),
    ("decision_version", "decision.v4"),
    ("decision_id", "decision.other"),
    ("operation_id", "test.lint"),
    ("resource_type", "source-file-set"),
    ("resource_sha256", "6" * 64),
    ("repository_sha256", "0" * 64),
    ("workspace_sha256", "9" * 64),
    ("executable_sha256", "8" * 64),
    ("launch_sha256", "7" * 64),
)

IDENTITY_DRIFT = (
    ("expected_subject_id", "subject.other"),
    ("expected_task_id", "task.other"),
    ("expected_issuer_id", "issuer.other"),
    ("expected_approval_provenance_id", "provenance-other"),
)

SCENARIOS: list[dict[str, object]] = [
    {
        "name": "issue_lookup_claim_exhaust",
        "steps": [
            lookup("wc-test-1", now=1),
            issue("wc-test-1"),
            lookup("wc-test-1", now=2),
            claim_step("wc-test-1", invocation_id="invocation-1", now=3),
            receipt_lookup(receipt_id=LAST, now=4),
            receipt_lookup(invocation_id="invocation-1", now=4),
            receipt_lookup(invocation_id="invocation-unknown", now=4),
            claim_step("wc-test-1", invocation_id="invocation-2", now=5),
            lookup("wc-test-1", now=6),
            lookup("wc-unknown", now=6),
        ],
    },
    {
        "name": "multi_use_and_replay",
        "steps": [
            issue("wc-first", max_uses=2),
            issue("wc-second", max_uses=1),
            claim_step("wc-first", invocation_id="invocation-shared", max_uses=2),
            claim_step("wc-second", invocation_id="invocation-shared"),
            claim_step("wc-first", invocation_id="invocation-2", max_uses=2),
            receipt_lookup(receipt_id=LAST),
            claim_step("wc-first", invocation_id="invocation-3", max_uses=2),
            claim_step("wc-absent", invocation_id="invocation-4"),
        ],
    },
    {
        "name": "issue_rejections",
        "steps": [
            {**issue("wc-drift"), "approval_provenance_id": "provenance-other"},
            _issue_bad_signature(),
            _issue_tampered_claim(),
            _issue_key_id_mismatch(),
            issue("wc-early", now=-5),
            issue("wc-late", now=61),
            issue("wc-nonce-first"),
            issue("wc-nonce-replay", nonce=claim("wc-nonce-first").nonce),
            issue("wc-nonce-first", now=2),
            lookup("wc-nonce-first"),
            lookup("wc-drift"),
        ],
    },
    {
        "name": "claim_context_drift",
        "steps": [
            issue("wc-drift", max_uses=3),
            *[
                claim_step(
                    "wc-drift",
                    invocation_id=f"invocation-{field}",
                    expected_binding=binding(**{field: value}),
                    max_uses=3,
                )
                for field, value in CONTEXT_DRIFT
            ],
            *[
                claim_step("wc-drift", invocation_id=f"invocation-{field}", max_uses=3, **{field: value})
                for field, value in IDENTITY_DRIFT
            ],
            claim_step("wc-drift", invocation_id="invocation-good", max_uses=3),
        ],
    },
    {
        "name": "claim_time_window",
        "steps": [
            issue("wc-window"),
            claim_step("wc-window", invocation_id="invocation-expired", now=61),
            claim_step("wc-window", invocation_id="invocation-backdated", now=1),
            lookup("wc-window", now=2),
            lookup("wc-window", now=62),
            claim_step("wc-window", invocation_id="invocation-expired-again", now=70),
        ],
    },
    {
        "name": "revoke_flow",
        "steps": [
            revoke("wc-unissued", now=1),
            issue("wc-revoke", max_uses=2),
            revoke("wc-revoke", now=3, reason_code="BAD CODE"),
            revoke("wc-revoke", now=3),
            revoke("wc-revoke", now=4),
            claim_step("wc-revoke", invocation_id="invocation-revoked", now=5, max_uses=2),
            lookup("wc-revoke", now=6),
            revoke("wc-absent", now=7),
            issue("wc-after", now=8),
            claim_step("wc-after", invocation_id="invocation-after", now=9),
            receipt_lookup(receipt_id=LAST, now=10),
        ],
    },
    {
        "name": "key_rotation",
        "steps": [
            issue("wc-rotate", max_uses=2),
            {**claim_step("wc-rotate", invocation_id="invocation-rotated", max_uses=2), "key": "other"},
            {**lookup("wc-rotate"), "key": "other"},
            claim_step("wc-rotate", invocation_id="invocation-original", max_uses=2),
            {**receipt_lookup(receipt_id=LAST), "key": "other"},
            {**revoke("wc-rotate", now=5), "key": "other"},
            {**issue("wc-rotate-new", now=6), "key": "other"},
        ],
    },
]

_AUTO_TIME = {"multi_use_and_replay"}
SCENARIOS = [autotime(scenario) if scenario["name"] in _AUTO_TIME else scenario for scenario in SCENARIOS]
