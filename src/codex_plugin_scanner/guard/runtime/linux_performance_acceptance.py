"""Measured, provenance-bound acceptance contract for Linux network performance."""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from codex_plugin_scanner.guard.runtime.network_policy_contract import canonical_digest, canonical_json


class LinuxPerformanceAcceptanceError(ValueError):
    """Raised when performance evidence is malformed or untrusted."""


@dataclass(frozen=True, slots=True)
class LinuxPerformanceBudgets:
    minimum_samples: int = 100
    compile_p95_ns: int = 50_000_000
    decision_p95_ns: int = 1_000_000
    observation_p95_ns: int = 10_000_000
    operation_max_ns: int = 250_000_000
    evidence_max_bytes: int = 1_048_576

    def __post_init__(self) -> None:
        for name, value in (
            ("minimum-samples", self.minimum_samples),
            ("compile-p95-ns", self.compile_p95_ns),
            ("decision-p95-ns", self.decision_p95_ns),
            ("observation-p95-ns", self.observation_p95_ns),
            ("operation-max-ns", self.operation_max_ns),
            ("evidence-max-bytes", self.evidence_max_bytes),
        ):
            if type(value) is not int or value <= 0:
                raise LinuxPerformanceAcceptanceError(f"invalid-{name}")


DEFAULT_LINUX_PERFORMANCE_BUDGETS = LinuxPerformanceBudgets()
MAX_PERFORMANCE_SAMPLES = 100_000
MAX_PERFORMANCE_PAYLOAD_BYTES = 16_777_216
MAX_LATENCY_NS = 1_000_000_000_000


def _require_samples(samples: tuple[int, ...], name: str) -> None:
    if (
        type(samples) is not tuple
        or len(samples) > MAX_PERFORMANCE_SAMPLES
        or any(type(value) is not int or value < 0 or value > MAX_LATENCY_NS for value in samples)
    ):
        raise LinuxPerformanceAcceptanceError(f"invalid-{name}")


def _manifest_digest(
    compile_ns: tuple[int, ...],
    decision_ns: tuple[int, ...],
    observation_ns: tuple[int, ...],
    payload: bytes,
    dropped_events: int,
    subject_digest: str,
    challenge: str,
    expires_at_epoch_seconds: int,
) -> str:
    return canonical_digest(
        {
            "compile_ns": compile_ns,
            "decision_ns": decision_ns,
            "observation_ns": observation_ns,
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
            "dropped_events": dropped_events,
            "subject_digest": subject_digest,
            "challenge": challenge,
            "expires_at_epoch_seconds": expires_at_epoch_seconds,
        }
    )


@dataclass(frozen=True, slots=True)
class LinuxPerformanceEvidence:
    compile_ns: tuple[int, ...]
    decision_ns: tuple[int, ...]
    observation_ns: tuple[int, ...]
    payload: bytes
    dropped_events: int
    manifest_digest: str
    collector_signature: bytes = field(repr=False, compare=False)
    subject_digest: str
    challenge: str
    expires_at_epoch_seconds: int

    def __post_init__(self) -> None:
        _require_samples(self.compile_ns, "compile-ns")
        _require_samples(self.decision_ns, "decision-ns")
        _require_samples(self.observation_ns, "observation-ns")
        if not (len(self.compile_ns) == len(self.decision_ns) == len(self.observation_ns)):
            raise LinuxPerformanceAcceptanceError("mismatched-sample-counts")
        if type(self.payload) is not bytes or len(self.payload) > MAX_PERFORMANCE_PAYLOAD_BYTES:
            raise LinuxPerformanceAcceptanceError("invalid-evidence-payload")
        if type(self.dropped_events) is not int or self.dropped_events < 0:
            raise LinuxPerformanceAcceptanceError("invalid-dropped-events")
        if (
            type(self.subject_digest) is not str
            or len(self.subject_digest) != 64
            or any(character not in "0123456789abcdef" for character in self.subject_digest)
            or type(self.challenge) is not str
            or not self.challenge
            or not 1 <= len(self.challenge) <= 256
            or type(self.expires_at_epoch_seconds) is not int
        ):
            raise LinuxPerformanceAcceptanceError("invalid-evidence-binding")
        expected_digest = _manifest_digest(
            self.compile_ns,
            self.decision_ns,
            self.observation_ns,
            self.payload,
            self.dropped_events,
            self.subject_digest,
            self.challenge,
            self.expires_at_epoch_seconds,
        )
        if self.manifest_digest != expected_digest:
            raise LinuxPerformanceAcceptanceError("manifest-digest-mismatch")
        if type(self.collector_signature) is not bytes or len(self.collector_signature) != 64:
            raise LinuxPerformanceAcceptanceError("collector-attestation-invalid")


@dataclass(frozen=True, slots=True)
class LinuxPerformanceAcceptanceReport:
    accepted: bool
    reasons: tuple[str, ...]
    compile_p95_ns: int
    decision_p95_ns: int
    observation_p95_ns: int
    operation_max_ns: int
    evidence_bytes: int
    sample_count: int
    evidence_digest: str


def capture_linux_network_performance(
    compile_operation: Callable[[], object],
    decision_operation: Callable[[], object],
    observation_operation: Callable[[], object],
    *,
    sample_count: int,
    payload: bytes,
    dropped_events: int,
    collector_private_key: object,
    subject_digest: str,
    challenge: str,
    expires_at_epoch_seconds: int,
) -> LinuxPerformanceEvidence:
    """Measure paired real operations and seal their evidence in this process."""
    if type(sample_count) is not int or sample_count <= 0 or sample_count > MAX_PERFORMANCE_SAMPLES:
        raise LinuxPerformanceAcceptanceError("invalid-sample-count")
    if (
        type(payload) is not bytes
        or len(payload) > MAX_PERFORMANCE_PAYLOAD_BYTES
        or type(dropped_events) is not int
        or dropped_events < 0
        or not isinstance(collector_private_key, Ed25519PrivateKey)
        or type(subject_digest) is not str
        or len(subject_digest) != 64
        or any(character not in "0123456789abcdef" for character in subject_digest)
        or type(challenge) is not str
        or not 1 <= len(challenge) <= 256
        or type(expires_at_epoch_seconds) is not int
        or expires_at_epoch_seconds <= 0
        or expires_at_epoch_seconds <= int(time.time())
    ):
        raise LinuxPerformanceAcceptanceError("invalid-collector-input")
    vectors: list[list[int]] = [[], [], []]
    for _ in range(sample_count):
        for vector, operation in zip(
            vectors, (compile_operation, decision_operation, observation_operation), strict=True
        ):
            started = time.perf_counter_ns()
            _ = operation()
            vector.append(time.perf_counter_ns() - started)
    compile_ns, decision_ns, observation_ns = (tuple(vector) for vector in vectors)
    if expires_at_epoch_seconds <= int(time.time()):
        raise LinuxPerformanceAcceptanceError("performance-evidence-expired")
    digest = _manifest_digest(
        compile_ns,
        decision_ns,
        observation_ns,
        payload,
        dropped_events,
        subject_digest,
        challenge,
        expires_at_epoch_seconds,
    )
    return LinuxPerformanceEvidence(
        compile_ns=compile_ns,
        decision_ns=decision_ns,
        observation_ns=observation_ns,
        payload=payload,
        dropped_events=dropped_events,
        manifest_digest=digest,
        collector_signature=collector_private_key.sign(digest.encode()),
        subject_digest=subject_digest,
        challenge=challenge,
        expires_at_epoch_seconds=expires_at_epoch_seconds,
    )


def _percentile_95(samples: tuple[int, ...]) -> int:
    ordered = sorted(samples)
    return ordered[(95 * len(ordered) - 1) // 100]


def assess_linux_network_performance(
    evidence: LinuxPerformanceEvidence,
    collector_public_key: object,
    *,
    expected_subject_digest: str,
    expected_challenge: str,
    now_epoch_seconds: int,
    budgets: LinuxPerformanceBudgets = DEFAULT_LINUX_PERFORMANCE_BUDGETS,
) -> LinuxPerformanceAcceptanceReport:
    """Evaluate sealed hot-path measurements against explicit inclusive budgets."""
    if (
        type(evidence) is not LinuxPerformanceEvidence
        or type(budgets) is not LinuxPerformanceBudgets
        or not isinstance(collector_public_key, Ed25519PublicKey)
        or type(expected_subject_digest) is not str
        or len(expected_subject_digest) != 64
        or any(character not in "0123456789abcdef" for character in expected_subject_digest)
        or type(expected_challenge) is not str
        or not 1 <= len(expected_challenge) <= 256
        or type(now_epoch_seconds) is not int
        or now_epoch_seconds < 0
    ):
        raise LinuxPerformanceAcceptanceError("invalid-performance-input")
    if (
        type(evidence.subject_digest) is not str
        or len(evidence.subject_digest) != 64
        or any(character not in "0123456789abcdef" for character in evidence.subject_digest)
        or type(evidence.challenge) is not str
        or not 1 <= len(evidence.challenge) <= 256
        or type(evidence.expires_at_epoch_seconds) is not int
        or evidence.expires_at_epoch_seconds <= 0
    ):
        raise LinuxPerformanceAcceptanceError("invalid-evidence-binding")
    if (
        evidence.subject_digest != expected_subject_digest
        or evidence.challenge != expected_challenge
        or evidence.expires_at_epoch_seconds <= now_epoch_seconds
    ):
        raise LinuxPerformanceAcceptanceError("performance-evidence-binding-invalid")
    compile_ns = evidence.compile_ns
    decision_ns = evidence.decision_ns
    observation_ns = evidence.observation_ns
    payload = evidence.payload
    dropped_events = evidence.dropped_events
    signature = evidence.collector_signature
    _require_samples(compile_ns, "compile-ns")
    _require_samples(decision_ns, "decision-ns")
    _require_samples(observation_ns, "observation-ns")
    if not (len(compile_ns) == len(decision_ns) == len(observation_ns)):
        raise LinuxPerformanceAcceptanceError("mismatched-sample-counts")
    if type(payload) is not bytes or len(payload) > MAX_PERFORMANCE_PAYLOAD_BYTES:
        raise LinuxPerformanceAcceptanceError("invalid-evidence-payload")
    if type(dropped_events) is not int or dropped_events < 0:
        raise LinuxPerformanceAcceptanceError("invalid-dropped-events")
    manifest_digest = _manifest_digest(
        compile_ns,
        decision_ns,
        observation_ns,
        payload,
        dropped_events,
        evidence.subject_digest,
        evidence.challenge,
        evidence.expires_at_epoch_seconds,
    )
    if manifest_digest != evidence.manifest_digest:
        raise LinuxPerformanceAcceptanceError("manifest-digest-mismatch")
    try:
        collector_public_key.verify(signature, manifest_digest.encode())
    except (InvalidSignature, TypeError, ValueError) as error:
        raise LinuxPerformanceAcceptanceError("collector-attestation-invalid") from error
    if not compile_ns:
        raise LinuxPerformanceAcceptanceError("empty-performance-evidence")
    compile_p95 = _percentile_95(compile_ns)
    decision_p95 = _percentile_95(decision_ns)
    observation_p95 = _percentile_95(observation_ns)
    operation_max = max(max(compile_ns), max(decision_ns), max(observation_ns))
    evidence_bytes = len(payload) + 8 * (len(compile_ns) + len(decision_ns) + len(observation_ns))
    reasons: list[str] = []
    if len(compile_ns) < budgets.minimum_samples:
        reasons.append("insufficient-samples")
    if dropped_events:
        reasons.append("dropped-events")
    if compile_p95 > budgets.compile_p95_ns:
        reasons.append("compile-p95-exceeded")
    if decision_p95 > budgets.decision_p95_ns:
        reasons.append("decision-p95-exceeded")
    if observation_p95 > budgets.observation_p95_ns:
        reasons.append("observation-p95-exceeded")
    if operation_max > budgets.operation_max_ns:
        reasons.append("operation-max-exceeded")
    if evidence_bytes > budgets.evidence_max_bytes:
        reasons.append("evidence-size-exceeded")
    report_evidence = {"budgets": asdict(budgets), "manifest_digest": manifest_digest, "reasons": reasons}
    return LinuxPerformanceAcceptanceReport(
        accepted=not reasons,
        reasons=tuple(reasons),
        compile_p95_ns=compile_p95,
        decision_p95_ns=decision_p95,
        observation_p95_ns=observation_p95,
        operation_max_ns=operation_max,
        evidence_bytes=evidence_bytes,
        sample_count=len(compile_ns),
        evidence_digest=hashlib.sha256(canonical_json(report_evidence).encode()).hexdigest(),
    )


__all__ = [
    "DEFAULT_LINUX_PERFORMANCE_BUDGETS",
    "MAX_LATENCY_NS",
    "MAX_PERFORMANCE_PAYLOAD_BYTES",
    "MAX_PERFORMANCE_SAMPLES",
    "LinuxPerformanceAcceptanceError",
    "LinuxPerformanceAcceptanceReport",
    "LinuxPerformanceBudgets",
    "LinuxPerformanceEvidence",
    "assess_linux_network_performance",
    "capture_linux_network_performance",
]
