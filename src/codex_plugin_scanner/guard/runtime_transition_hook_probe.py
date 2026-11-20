"""Thin transport to the native runtime's transition hook probe correlation.

A probe ID requests diagnostics only. It never grants approval, changes a
decision, or enables a fallback. The native runtime reads the probe and decides
whether a receipt observes it; this module only carries the question.
"""

from __future__ import annotations

from collections.abc import Mapping

from .native_context import _resolve_existing_digest_home, native_context_digest

PROBE_FIELD = "guard_transition_probe"
OBSERVATION_FIELD = "guard_transition_observation"
PROBE_SCHEMA = "hol-guard.transition-hook-probe.v1"
OBSERVATION_SCHEMA = "hol-guard.transition-hook-observation.v1"


def _answer(payload: Mapping[str, object], receipt: object) -> dict[str, object] | None:
    # Only a payload that carries the field can name a probe; every other hook
    # skips the runtime round trip.
    if PROBE_FIELD not in payload:
        return None
    material = {"payload": dict(payload), "receipt": dict(receipt) if isinstance(receipt, Mapping) else None}
    result = native_context_digest(
        "transition_hook_observation", material, guard_home=_resolve_existing_digest_home(None)
    )
    answer = result.get("transition_hook_observation") if isinstance(result, dict) else None
    return answer if isinstance(answer, dict) else None


def transition_hook_probe(payload: Mapping[str, object]) -> tuple[str, str] | None:
    answer = _answer(payload, None)
    if answer is None:
        return None
    return str(answer["operation_id"]), str(answer["request_id"])


def transition_hook_observation(payload: Mapping[str, object], receipt: object) -> dict[str, object] | None:
    answer = _answer(payload, receipt)
    observation = answer.get("observation") if answer is not None else None
    return observation if isinstance(observation, dict) else None
