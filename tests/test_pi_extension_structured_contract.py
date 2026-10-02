from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.pi_extension_source import managed_extension_source
from tests.pi_extension_response_callback_support import _run_generated_callback_payload
from tests.pi_extension_response_source_support import _generated_source


@pytest.mark.parametrize("harness", ["pi", "omp"])
@pytest.mark.parametrize(
    ("reason_code", "message"),
    [
        ("structured_review_deadline_exceeded", "review deadline expired"),
        ("structured_review_cancelled", "review was cancelled"),
        ("structured_content_unproved", "could not be validated for this destination"),
    ],
)
def test_structured_withholding_does_not_claim_pending_approval(
    tmp_path: Path, harness: str, reason_code: str, message: str
) -> None:
    source = _generated_source(tmp_path, harness=harness)
    candidate = '{"note":"fixture"}'
    response = {
        "decision": "allow",
        "reason": "private fixture https://example.test/review",
        "model_output_action": "allow_original",
        "reviewed_output_sha256": hashlib.sha256(candidate.encode("utf-8")).hexdigest(),
        "structured_content_mediation": {
            "schema": "guard-structured-content-mediation.v1",
            "action": "withhold",
            "reason_code": reason_code,
        },
    }
    result = _run_generated_callback_payload(
        source, [{"type": "text", "text": candidate}], response, use_generated_blocked_reason=True
    )
    text = result["result"]["content"][0]["text"]
    assert result["result"]["isError"] is True
    assert message in text
    assert "approval is pending" not in text
    assert "wait for the user to approve" not in text
    assert "private fixture" not in text
    assert "example.test" not in text


@pytest.mark.parametrize("harness", ["pi", "omp"])
def test_generated_structured_receiver_requires_exact_clean_forward_bytes(
    tmp_path: Path,
    harness: str,
) -> None:
    source = managed_extension_source(
        guard_home=tmp_path / harness / "guard-home",
        home_dir=tmp_path / harness / "home",
        settings_path=tmp_path / harness / "settings.json",
        harness=harness,
        display_name=harness,
    )
    content = [{"type": "text", "text": '{"employee":{"email":"","id":7},"note":"π"}'}]
    candidate = '{"employee":{"email":"","id":7},"note":"π"}'
    text_digest = hashlib.sha256(candidate.encode("utf-8")).hexdigest()
    structured_digest = hashlib.sha256(candidate.encode("utf-8")).hexdigest()
    forward = _run_generated_callback_payload(
        source,
        content,
        {
            "decision": "allow",
            "model_output_action": "allow_original",
            "reviewed_output_sha256": text_digest,
            "structured_content_mediation": {
                "schema": "guard-structured-content-mediation.v1",
                "action": "forward",
                "reason_code": "structured_clean_forward",
                "native_decision_id": "a" * 64,
                "content_sha256": structured_digest,
            },
        },
    )
    assert forward["payload"]["structured_output_json"] == candidate
    assert forward["preserved"] is True

    withhold = _run_generated_callback_payload(
        source,
        content,
        {
            "decision": "allow",
            "model_output_action": "allow_original",
            "reviewed_output_sha256": text_digest,
            "structured_content_mediation": {
                "schema": "guard-structured-content-mediation.v1",
                "action": "withhold",
                "reason_code": "structured_declared_schema_scan",
                "native_decision_id": "a" * 64,
            },
        },
    )
    assert withhold["result"]["isError"] is True
    assert "π" not in withhold["result"]["content"][0]["text"]

    changed = _run_generated_callback_payload(
        source,
        [{"type": "text", "text": '{"employee":{"email":"","id":7},"note":"changed"}'}],
        {
            "decision": "allow",
            "model_output_action": "allow_original",
            "reviewed_output_sha256": text_digest,
            "structured_content_mediation": {
                "schema": "guard-structured-content-mediation.v1",
                "action": "forward",
                "reason_code": "structured_clean_forward",
                "native_decision_id": "a" * 64,
                "content_sha256": structured_digest,
            },
        },
    )
    assert changed["result"]["isError"] is True

    protected_content = [
        {"type": "text", "text": '{"employee":{"email":"person@example.test","id":7},"note":"π"}'},
    ]
    protected_candidate = '{"employee":{"email":"person@example.test","id":7},"note":"π"}'
    protected = _run_generated_callback_payload(
        source,
        protected_content,
        {
            "decision": "allow",
            "model_output_action": "allow_original",
            "reviewed_output_sha256": hashlib.sha256(protected_candidate.encode("utf-8")).hexdigest(),
            "structured_content_mediation": {
                "schema": "guard-structured-content-mediation.v1",
                "action": "withhold",
                "reason_code": "structured_declared_schema_scan",
                "native_decision_id": "a" * 64,
            },
        },
    )
    assert protected["result"]["isError"] is True
    assert "person@example.test" not in protected["result"]["content"][0]["text"]

    unknown_metadata = _run_generated_callback_payload(
        source,
        [{"type": "text", "text": candidate, "metadata": {"fixture": "unknown"}}],
        {
            "decision": "allow",
            "model_output_action": "allow_original",
            "reviewed_output_sha256": text_digest,
            "structured_content_mediation": {
                "schema": "guard-structured-content-mediation.v1",
                "action": "forward",
                "reason_code": "structured_clean_forward",
                "native_decision_id": "a" * 64,
                "content_sha256": structured_digest,
            },
        },
    )
    assert unknown_metadata["result"]["isError"] is True


def test_generated_structured_receiver_fails_closed_without_host_cancellation_signal(tmp_path: Path) -> None:
    source = _generated_source(tmp_path)
    candidate = '{"employee":{"email":"","id":7},"note":"x"}'
    response = {
        "decision": "allow",
        "model_output_action": "allow_original",
        "reviewed_output_sha256": hashlib.sha256(candidate.encode("utf-8")).hexdigest(),
        "structured_content_mediation": {
            "schema": "guard-structured-content-mediation.v1",
            "action": "forward",
            "reason_code": "structured_clean_forward",
            "native_decision_id": "a" * 64,
            "content_sha256": hashlib.sha256(candidate.encode("utf-8")).hexdigest(),
        },
    }
    result = _run_generated_callback_payload(
        source,
        [{"type": "text", "text": candidate}],
        response,
        include_signal=False,
    )
    assert "structured_output_json" not in result["payload"]
    assert result["preserved"] is False
    assert result["result"]["isError"] is True


def test_generated_managed_structured_mediation_precedes_watch_shortcut(tmp_path: Path) -> None:
    source = _generated_source(tmp_path, harness="pi")
    benign = '{"employee":{"email":"","id":7},"note":"watch"}'
    benign_response = {
        "decision": "allow",
        "model_output_action": "allow_original",
        "observe_mode": True,
        "reviewed_output_sha256": hashlib.sha256(benign.encode("utf-8")).hexdigest(),
        "structured_content_mediation": {
            "schema": "guard-structured-content-mediation.v1",
            "action": "forward",
            "reason_code": "structured_clean_forward",
            "native_decision_id": "a" * 64,
            "content_sha256": hashlib.sha256(benign.encode("utf-8")).hexdigest(),
        },
    }
    allowed = _run_generated_callback_payload(
        source,
        [{"type": "text", "text": benign}],
        benign_response,
    )
    assert allowed["preserved"] is True
    assert allowed["payload"]["structured_output_json"] == benign

    protected = '{"employee":{"email":"person@example.test","id":7},"note":"watch"}'
    protected_response = {
        **benign_response,
        "reviewed_output_sha256": hashlib.sha256(protected.encode("utf-8")).hexdigest(),
        "structured_content_mediation": {
            **benign_response["structured_content_mediation"],
            "action": "withhold",
            "reason_code": "structured_declared_schema_scan",
        },
    }
    blocked = _run_generated_callback_payload(
        source,
        [{"type": "text", "text": protected}],
        protected_response,
    )
    assert blocked["preserved"] is False
    assert blocked["result"]["isError"] is True
    assert "person@example.test" not in blocked["result"]["content"][0]["text"]


def test_generated_structured_receiver_rejects_late_cancellation_and_expired_deadline(tmp_path: Path) -> None:
    source = _generated_source(tmp_path)
    candidate = '{"employee":{"email":"","id":7},"note":"x"}'
    response = {
        "decision": "allow",
        "model_output_action": "allow_original",
        "reviewed_output_sha256": hashlib.sha256(candidate.encode("utf-8")).hexdigest(),
        "structured_content_mediation": {
            "schema": "guard-structured-content-mediation.v1",
            "action": "forward",
            "reason_code": "structured_clean_forward",
            "native_decision_id": "a" * 64,
            "content_sha256": hashlib.sha256(candidate.encode("utf-8")).hexdigest(),
        },
    }
    cancelled = _run_generated_callback_payload(
        source,
        [{"type": "text", "text": candidate}],
        response,
        abort_during_guard=True,
    )
    assert cancelled["preserved"] is False
    assert cancelled["result"]["isError"] is True
    assert "Resume the task to review the output again." in cancelled["result"]["content"][0]["text"]
    assert "approve" not in cancelled["result"]["content"][0]["text"]

    expired = _run_generated_callback_payload(
        source,
        [{"type": "text", "text": candidate}],
        response,
        guard_timeout_ms=0,
    )
    assert expired["payload"] is None
    assert expired["preserved"] is False
    assert expired["result"]["isError"] is True


@pytest.mark.parametrize("trigger", ["abort", "deadline"])
def test_generated_structured_receiver_rechecks_lifecycle_at_final_original_proof(
    tmp_path: Path,
    trigger: str,
) -> None:
    source = _generated_source(tmp_path, harness="pi")
    candidate = '{"employee":{"email":"","id":7},"note":"final"}'
    digest = hashlib.sha256(candidate.encode("utf-8")).hexdigest()
    response = {
        "decision": "allow",
        "model_output_action": "allow_original",
        "reviewed_output_sha256": digest,
        "structured_content_mediation": {
            "schema": "guard-structured-content-mediation.v1",
            "action": "forward",
            "reason_code": "structured_clean_forward",
            "native_decision_id": "a" * 64,
            "content_sha256": digest,
        },
    }
    result = _run_generated_callback_payload(
        source,
        [{"type": "text", "text": candidate}],
        response,
        abort_during_structured_proof=trigger == "abort",
        expire_during_structured_proof=trigger == "deadline",
    )
    assert result["preserved"] is False
    assert result["result"]["isError"] is True
