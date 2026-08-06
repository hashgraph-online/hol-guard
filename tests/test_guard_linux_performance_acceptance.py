from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from codex_plugin_scanner.guard.runtime.linux_performance_acceptance import (
    MAX_LATENCY_NS,
    MAX_PERFORMANCE_PAYLOAD_BYTES,
    MAX_PERFORMANCE_SAMPLES,
    LinuxPerformanceAcceptanceError,
    LinuxPerformanceBudgets,
    LinuxPerformanceEvidence,
    assess_linux_network_performance,
    capture_linux_network_performance,
)

PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
PUBLIC_KEY = PRIVATE_KEY.public_key()
SUBJECT_DIGEST = "a" * 64
CHALLENGE = "challenge-2026-08-05"
EXPIRES_AT = 2_000_000_000
NOW = 1_900_000_000


def _capture(*, samples: int = 100, payload: bytes = b"evidence", dropped: int = 0) -> LinuxPerformanceEvidence:
    return capture_linux_network_performance(
        lambda: None,
        lambda: None,
        lambda: None,
        sample_count=samples,
        payload=payload,
        dropped_events=dropped,
        collector_private_key=PRIVATE_KEY,
        subject_digest=SUBJECT_DIGEST,
        challenge=CHALLENGE,
        expires_at_epoch_seconds=EXPIRES_AT,
    )


def _assess(
    evidence: LinuxPerformanceEvidence,
    *,
    budgets: LinuxPerformanceBudgets | None = None,
):
    kwargs = {} if budgets is None else {"budgets": budgets}
    return assess_linux_network_performance(
        evidence,
        PUBLIC_KEY,
        expected_subject_digest=SUBJECT_DIGEST,
        expected_challenge=CHALLENGE,
        now_epoch_seconds=NOW,
        **kwargs,
    )


def _boundary_budgets(evidence: LinuxPerformanceEvidence) -> LinuxPerformanceBudgets:
    report = _assess(
        evidence,
        budgets=LinuxPerformanceBudgets(
            minimum_samples=1,
            compile_p95_ns=10**12,
            decision_p95_ns=10**12,
            observation_p95_ns=10**12,
            operation_max_ns=10**12,
            evidence_max_bytes=10**6,
        ),
    )
    return LinuxPerformanceBudgets(
        minimum_samples=report.sample_count,
        compile_p95_ns=report.compile_p95_ns,
        decision_p95_ns=report.decision_p95_ns,
        observation_p95_ns=report.observation_p95_ns,
        operation_max_ns=report.operation_max_ns,
        evidence_max_bytes=report.evidence_bytes,
    )


def test_accepts_measured_exact_boundaries_with_deterministic_digest() -> None:
    evidence = _capture()
    budgets = _boundary_budgets(evidence)
    first = _assess(evidence, budgets=budgets)
    second = _assess(evidence, budgets=budgets)

    assert first.accepted
    assert first.reasons == ()
    assert first.sample_count == 100
    assert first.evidence_digest == second.evidence_digest


def test_rejects_latency_size_and_dropped_event_breaches() -> None:
    evidence = _capture(payload=b"oversized", dropped=1)
    boundary = _boundary_budgets(evidence)
    budgets = LinuxPerformanceBudgets(
        minimum_samples=100,
        compile_p95_ns=max(1, boundary.compile_p95_ns - 1),
        decision_p95_ns=max(1, boundary.decision_p95_ns - 1),
        observation_p95_ns=max(1, boundary.observation_p95_ns - 1),
        operation_max_ns=max(1, boundary.operation_max_ns - 1),
        evidence_max_bytes=len(evidence.payload) - 1,
    )
    report = _assess(evidence, budgets=budgets)

    assert not report.accepted
    assert "compile-p95-exceeded" in report.reasons
    assert "decision-p95-exceeded" in report.reasons
    assert "observation-p95-exceeded" in report.reasons
    assert "dropped-events" in report.reasons
    assert "operation-max-exceeded" in report.reasons
    assert "evidence-size-exceeded" in report.reasons


def test_rejects_insufficient_samples() -> None:
    evidence = _capture(samples=1)
    report = _assess(
        evidence,
        budgets=LinuxPerformanceBudgets(minimum_samples=2),
    )
    assert report.reasons == ("insufficient-samples",)


def test_rejects_malformed_or_unattested_evidence() -> None:
    with pytest.raises(LinuxPerformanceAcceptanceError, match="invalid-compile-ns"):
        _ = LinuxPerformanceEvidence((True,), (1,), (1,), b"x", 0, "0" * 64, b"", SUBJECT_DIGEST, CHALLENGE, EXPIRES_AT)
    with pytest.raises(LinuxPerformanceAcceptanceError, match="mismatched-sample-counts"):
        _ = LinuxPerformanceEvidence((1,), (1, 2), (1,), b"x", 0, "0" * 64, b"", SUBJECT_DIGEST, CHALLENGE, EXPIRES_AT)
    with pytest.raises(LinuxPerformanceAcceptanceError, match="collector-attestation-invalid"):
        measured = _capture(samples=1)
        tampered = LinuxPerformanceEvidence(
            measured.compile_ns,
            measured.decision_ns,
            measured.observation_ns,
            measured.payload,
            measured.dropped_events,
            measured.manifest_digest,
            measured.collector_signature[:-1] + b"0",
            subject_digest=measured.subject_digest,
            challenge=measured.challenge,
            expires_at_epoch_seconds=measured.expires_at_epoch_seconds,
        )
        _ = _assess(tampered)


def test_revalidates_snapshot_after_frozen_evidence_is_mutated() -> None:
    evidence = _capture(samples=1)
    object.__setattr__(evidence, "payload", b"mutated")

    with pytest.raises(LinuxPerformanceAcceptanceError, match="manifest-digest-mismatch"):
        _ = _assess(evidence)


def test_rejects_resource_inputs_above_hard_limits() -> None:
    with pytest.raises(LinuxPerformanceAcceptanceError, match="invalid-sample-count"):
        _ = capture_linux_network_performance(
            lambda: None,
            lambda: None,
            lambda: None,
            sample_count=MAX_PERFORMANCE_SAMPLES + 1,
            payload=b"",
            dropped_events=0,
            collector_private_key=PRIVATE_KEY,
            subject_digest=SUBJECT_DIGEST,
            challenge=CHALLENGE,
            expires_at_epoch_seconds=EXPIRES_AT,
        )
    with pytest.raises(LinuxPerformanceAcceptanceError, match="invalid-compile-ns"):
        _ = LinuxPerformanceEvidence(
            (MAX_LATENCY_NS + 1,),
            (1,),
            (1,),
            b"",
            0,
            "0" * 64,
            b"",
            SUBJECT_DIGEST,
            CHALLENGE,
            EXPIRES_AT,
        )
    with pytest.raises(LinuxPerformanceAcceptanceError, match="invalid-evidence-payload"):
        _ = LinuxPerformanceEvidence(
            (1,),
            (1,),
            (1,),
            bytes(MAX_PERFORMANCE_PAYLOAD_BYTES + 1),
            0,
            "0" * 64,
            b"",
            SUBJECT_DIGEST,
            CHALLENGE,
            EXPIRES_AT,
        )


def test_rejects_invalid_collector_and_budget_values() -> None:
    with pytest.raises(LinuxPerformanceAcceptanceError, match="invalid-sample-count"):
        _ = capture_linux_network_performance(
            lambda: None,
            lambda: None,
            lambda: None,
            sample_count=0,
            payload=b"",
            dropped_events=0,
            collector_private_key=PRIVATE_KEY,
            subject_digest=SUBJECT_DIGEST,
            challenge=CHALLENGE,
            expires_at_epoch_seconds=EXPIRES_AT,
        )
    with pytest.raises(LinuxPerformanceAcceptanceError, match="invalid-minimum-samples"):
        _ = LinuxPerformanceBudgets(minimum_samples=0)


def test_rejects_replayed_stale_and_wrong_key_evidence() -> None:
    evidence = _capture(samples=1)
    with pytest.raises(LinuxPerformanceAcceptanceError, match="performance-evidence-binding-invalid"):
        _ = assess_linux_network_performance(
            evidence,
            PUBLIC_KEY,
            expected_subject_digest="b" * 64,
            expected_challenge=CHALLENGE,
            now_epoch_seconds=NOW,
        )
    with pytest.raises(LinuxPerformanceAcceptanceError, match="performance-evidence-binding-invalid"):
        _ = assess_linux_network_performance(
            evidence,
            PUBLIC_KEY,
            expected_subject_digest=SUBJECT_DIGEST,
            expected_challenge="different-challenge",
            now_epoch_seconds=NOW,
        )
    with pytest.raises(LinuxPerformanceAcceptanceError, match="performance-evidence-binding-invalid"):
        _ = assess_linux_network_performance(
            evidence,
            PUBLIC_KEY,
            expected_subject_digest=SUBJECT_DIGEST,
            expected_challenge=CHALLENGE,
            now_epoch_seconds=EXPIRES_AT,
        )
    with pytest.raises(LinuxPerformanceAcceptanceError, match="invalid-performance-input"):
        _ = assess_linux_network_performance(
            evidence,
            object(),  # type: ignore[arg-type]
            expected_subject_digest=SUBJECT_DIGEST,
            expected_challenge=CHALLENGE,
            now_epoch_seconds=NOW,
        )


def test_rejects_tampered_signed_binding() -> None:
    evidence = _capture(samples=1)
    object.__setattr__(evidence, "challenge", "tampered-challenge")
    with pytest.raises(LinuxPerformanceAcceptanceError, match="manifest-digest-mismatch"):
        _ = assess_linux_network_performance(
            evidence,
            PUBLIC_KEY,
            expected_subject_digest=SUBJECT_DIGEST,
            expected_challenge="tampered-challenge",
            now_epoch_seconds=NOW,
        )
