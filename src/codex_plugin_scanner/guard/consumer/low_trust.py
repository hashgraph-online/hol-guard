"""Review floor for skills, MCP servers and plugins with a low HOL Registry trust score.

Python holds the registry lookup because it is network IO with an on-disk
cache. Every judgement around it belongs to the resident: whether the artifact
qualifies for a score at all, what the ``low_trust_artifact`` risk class
resolves to, whether the score is below the threshold, and the signal that
explains the floor.

The lookup is costly, so the resident asks for it rather than being handed it.
A first query carries no score; only when the floor would otherwise apply does
the answer come back with ``score_required``, and the score is then read and
sent in a second query. A configured, settled or unscored artifact, or an
allowed risk class, is answered without touching the network, exactly as the
Python resolution short-circuited.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from ..config import GuardConfig, risk_action_config_facts
from ..models import GuardArtifact
from ..native_consumer_artifact_compose import NativeConsumerComposeError, native_consumer_compose
from ..registry_trust import registry_trust_score
from ..runtime.signals import RiskSignalV2

_FLOOR_INVALID = "native_consumer_artifact_compose_low_trust_floor_invalid"


@dataclass(frozen=True, slots=True)
class LowTrustFloor:
    action: str
    score: int
    signal: RiskSignalV2


def low_trust_floor(
    guard_home: Path | None,
    config: GuardConfig,
    *,
    harness: str,
    artifact: GuardArtifact,
    configured_action: str | None,
    fresh_decision: bool,
) -> LowTrustFloor | None:
    """Return the review floor for a low-trust artifact, or ``None``.

    Only an unconfigured artifact that is first seen or changed is scored: a
    configured override or an unchanged, already decided artifact keeps its
    decision, and a saved Always allow still applies after the floor raises the
    action.

    Raises ``NativeConsumerComposeError`` when the resident cannot answer. The
    caller fails the artifact closed rather than evaluating it with no floor.
    """

    facts: dict[str, object] = {
        "risk_action_config": risk_action_config_facts(config),
        "harness": harness if isinstance(harness, str) else None,
        "artifact_type": artifact.artifact_type,
        "artifact_id": artifact.artifact_id,
        "artifact_name": artifact.name,
        "configured_action": configured_action,
        "fresh_decision": bool(fresh_decision),
        "trust_score": None,
    }
    answer = _compose(facts, guard_home)
    if answer is not None and answer["score_required"]:
        score = registry_trust_score(guard_home, artifact_type=artifact.artifact_type, name=artifact.name)
        # No score is no answer, and never a review.
        answer = None if score is None else _compose({**facts, "trust_score": score}, guard_home)
    floor = None if answer is None else answer["floor"]
    return None if floor is None else _decode(cast(Mapping[str, object], floor))


def _compose(facts: Mapping[str, object], guard_home: Path | None) -> dict[str, object]:
    """The resident's answer to one floor query.

    ``NativeConsumerComposeError`` is deliberately not caught. A failed query
    is not "no floor": the floor only ever strengthens an action, and these
    failures are per request, so the floor query can fail — on a timeout, an
    unbound reply, or a resident that cannot decode this query kind — while the
    ``current_action`` query a moment later succeeds. Swallowing it would leave
    a fresh, low-trust artifact composed with no review floor and nothing in
    the record to say why. Raising fails the evaluation closed in the same call.
    """

    return native_consumer_compose("low_trust_floor", facts, guard_home=guard_home)


def _decode(floor: Mapping[str, object]) -> LowTrustFloor:
    """The decoded floor, or a compose failure.

    The resident answered, so a floor that does not decode is a contract
    mismatch, not an absent floor, and it fails the artifact closed as well.
    """

    action, score, signal = floor.get("action"), floor.get("score"), floor.get("signal")
    if not isinstance(action, str) or not isinstance(score, int) or isinstance(score, bool):
        raise NativeConsumerComposeError(_FLOOR_INVALID)
    if not isinstance(signal, Mapping):
        raise NativeConsumerComposeError(_FLOOR_INVALID)
    try:
        decoded = RiskSignalV2.from_dict(signal)
    except (TypeError, ValueError) as error:
        raise NativeConsumerComposeError(_FLOOR_INVALID) from error
    return LowTrustFloor(action=action, score=score, signal=decoded)


__all__ = ["LowTrustFloor", "low_trust_floor"]
