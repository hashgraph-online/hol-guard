"""Retain bounded SLO failure observations without exporting response bodies."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar

from scripts.native_slo_adapter import Observation
from scripts.native_slo_failure import FixtureFailureError, failure_evidence
from scripts.native_slo_semantic_diagnostic import semantic_diagnostic

_RECOVERY_OBSERVATION: ContextVar[dict[str, object] | None] = ContextVar(
    "qualification_recovery_observation", default=None
)


@contextmanager
def capture_recovery_observation() -> Iterator[dict[str, object]]:
    """Capture only this serial recovery call, never a concurrent peer's result."""
    detail: dict[str, object] = {}
    context = _RECOVERY_OBSERVATION.set(detail)
    try:
        yield detail
    finally:
        _RECOVERY_OBSERVATION.reset(context)


def retain_failed_recovery_observation(
    observation: Observation,
    response: Mapping[str, object],
    before: Mapping[str, int],
    after: Mapping[str, int],
) -> None:
    """Record closed evidence only if the active recovery result is unexpected."""
    detail = _RECOVERY_OBSERVATION.get()
    if detail is None or (observation.allowed and observation.route == "native_resident"):
        return
    detail.update(
        routes_before=dict(before),
        routes_after=dict(after),
        observed_semantics=verdict_evidence(response),
    )


def verdict_evidence(response: object = None, native: object = None) -> dict[str, object]:
    """Keep closed action labels; every non-frozen reason is a digest only."""
    result = semantic_diagnostic(response if isinstance(response, Mapping) else {}, native, cases=())
    if not isinstance(response, Mapping):
        result["delivered"] = {"available": False}
    for label in ("delivered", "native"):
        observed = result[label]
        if not isinstance(observed, dict):
            continue
        # The generic privacy sanitizer rejects fields containing 'output'.
        # These finite aliases preserve action evidence without relaxing it.
        for original, alias in (
            ("model_output_action", "model_action"),
            ("model_output_action_digest", "model_action_digest"),
        ):
            if original in observed:
                observed[alias] = observed.pop(original)
    return result


def contextual_failure(error: Exception, **detail: object) -> FixtureFailureError:
    """Enrich an existing failure once, preserving its original local message."""
    observed = dict(error.detail) if isinstance(error, FixtureFailureError) else failure_evidence(error)
    observed.update(detail)
    return FixtureFailureError(observed, message=str(error))


def _recovery_stop_evidence(value: object) -> dict[str, object]:
    """Copy fixed stop fields before cleanup can replace the session record."""

    result: dict[str, object] = {
        "available": False,
        "capture_boundary": "recovery_phase_exception_before_session_cleanup",
    }
    if not isinstance(value, Mapping) or value.get("schema") != "hol-guard.native-resident-stop-diagnostic.v1":
        return result
    statuses = {"not-run", "already-stopped", "contained", "failed", "contained_client_cleanup_failed"}
    if value.get("status") not in statuses:
        return result
    result.update(available=True, operation="resident-stop", status=value["status"])
    states = {"verified", "unknown", "true", "false", "free", "busy", "unverified", "absent", "present", "failed"}
    for field in (
        "acknowledged",
        "authenticated",
        "generation_present",
        "owner_lock",
        "marker_lock",
        "endpoint",
        "serving_shutdown",
        "client_cleanup",
    ):
        observed = value.get(field)
        if type(observed) is str and observed in states:
            result[field] = observed
    error = value.get("error")
    if type(error) is str and re.fullmatch(r"native_resident_stop_[a-z_]{1,64}", error):
        result["error"] = error
    return result


class SloProgress:
    """Keep completed phases/counts when a later phase or cleanup raises."""

    def __init__(self) -> None:
        self.completed: list[str] = []
        self.counts: dict[str, int] = {}

    @contextmanager
    def phase(self, name: str, *, stop_diagnostic: Callable[[], object] | None = None) -> Iterator[None]:
        try:
            yield
        except Exception as error:
            detail = dict(error.detail) if isinstance(error, FixtureFailureError) else {}
            if stop_diagnostic is not None:
                try:
                    detail["recovery_stop"] = _recovery_stop_evidence(stop_diagnostic())
                except Exception:
                    # Optional evidence must keep the original exception and
                    # all existing cleanup behavior, even if capture fails.
                    detail["recovery_stop"] = {"available": False, "capture_failed": True}
            prior_phases = detail.get("completed_phases", [])
            prior_counts = detail.get("completed_sample_counts", {})
            completed = list(self.completed)
            if isinstance(prior_phases, list):
                completed.extend(name for name in prior_phases if isinstance(name, str) and name not in completed)
            counts = dict(self.counts)
            if isinstance(prior_counts, Mapping):
                counts.update(
                    (key, count)
                    for key, count in prior_counts.items()
                    if isinstance(key, str) and isinstance(count, int) and not isinstance(count, bool) and count >= 0
                )
            raise contextual_failure(
                error,
                **({"recovery_stop": detail["recovery_stop"]} if "recovery_stop" in detail else {}),
                failed_phase=detail.get("failed_phase", name),
                completed_phases=completed[:32],
                completed_sample_counts=counts,
            ) from error
        self.completed.append(name)
