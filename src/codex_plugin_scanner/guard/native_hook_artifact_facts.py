"""Resident bridge for the ``hook_artifact_facts`` op.

The native configured-policy action reads a small set of per-artifact facts:
whether the prompt asks to bypass Guard, the command-action floor, whether an
explicit catalog permission earned a verified allow, which risk classes the
artifact carries, how strong its evidence is, whether it installs a boot item.
Each of those decides part of the verdict the resident then applies, so the
resident derives them from the artifact itself. This module ships the artifact
type and its metadata unchanged and hands the answer back; nothing is computed
here, so an unavailable resident cannot soften a fact into a quieter action.

``configured_override`` is the one input the caller still supplies: it is the
artifact, publisher or harness setting the config resolves, not a reading of
the artifact, and it rides through the op so the facts leave here complete.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast
from uuid import uuid4

from .native_context import _resolve_digest_home, ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_hook_artifact_compose import HOOK_ARTIFACT_COMPOSE_POLICY_TAIL_FEATURE
from .native_store_policy import _payload

# The facts answer ``skip_native_floor`` only once the policy-stack tail is
# served, so the facts are asked for under that feature: a runtime without it
# omits the fact the hook now reads. It ships with ``hook-artifact-facts-v1``.
HOOK_ARTIFACT_FACTS_FEATURE = HOOK_ARTIFACT_COMPOSE_POLICY_TAIL_FEATURE
_REQUEST_SCHEMA = "guard-hook-artifact-facts-request.v1"
_RESULT_SCHEMA = "guard-hook-artifact-facts-result.v1"
_TIMEOUT_SECONDS = 10.0
# Mirrors ``HOOK_ARTIFACT_FACTS_MAX_ARTIFACTS``: the resident refuses a request
# carrying more artifacts than this.
_MAX_ARTIFACTS = 64
_MAX_REQUEST_BYTES = 4 * 1024 * 1024


class HookArtifactFactsUnavailableError(RuntimeError):
    """The resident could not derive the artifact facts."""

    code = "native_hook_artifact_facts_unavailable"


def native_hook_artifact_facts(
    artifacts: Sequence[Mapping[str, object]],
    *,
    guard_home: Path | None = None,
) -> list[dict[str, object]]:
    """Return one resident ``PolicyArtifactFactsV1`` per artifact, in order.

    An evaluation reads facts for more than one artifact, so they are asked for
    together: a hook that asked once per artifact would put the resident on the
    critical path of every tool call more than once.

    Raises ``HookArtifactFactsUnavailableError`` when the resident cannot
    answer, which the hook pipeline's fail-closed handling turns into an
    availability response rather than a verdict.
    """

    if not artifacts:
        return []
    try:
        home = Path(_resolve_digest_home(guard_home))
    except (OSError, RuntimeError, ValueError):
        raise HookArtifactFactsUnavailableError from None
    if not ensure_resident_prerequisite(home):
        raise HookArtifactFactsUnavailableError
    answers: list[dict[str, object]] = []
    for start in range(0, len(artifacts), _MAX_ARTIFACTS):
        answers.extend(_facts_for_batch(artifacts[start : start + _MAX_ARTIFACTS], home))
    return answers


def _facts_for_batch(
    artifacts: Sequence[Mapping[str, object]],
    home: Path,
) -> list[dict[str, object]]:
    """Ask the resident about one batch the contract is willing to accept."""

    wire: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"hook-artifact-facts-{uuid4().hex}",
        "artifacts": [
            {
                "artifact_type": artifact["artifact_type"],
                "metadata": dict(cast("Mapping[str, object]", artifact.get("metadata") or {})),
                "configured_override": artifact.get("configured_override"),
            }
            for artifact in artifacts
        ],
    }
    try:
        response = _resident_request(
            operation="hook_artifact_facts",
            request=wire,
            guard_home=home,
            timeout_seconds=_TIMEOUT_SECONDS,
            required_feature=HOOK_ARTIFACT_FACTS_FEATURE,
            response_schema=_RESULT_SCHEMA,
            max_request_bytes=_MAX_REQUEST_BYTES,
            record_success=False,
        )
    except (TypeError, ValueError, OSError, RuntimeError):
        raise HookArtifactFactsUnavailableError from None
    payload = _payload(response, wire, home)
    if not isinstance(payload, dict):
        raise HookArtifactFactsUnavailableError
    facts = payload.get("facts")
    if not isinstance(facts, list) or len(facts) != len(artifacts):
        raise HookArtifactFactsUnavailableError
    if not all(isinstance(item, dict) for item in facts):
        raise HookArtifactFactsUnavailableError
    return cast("list[dict[str, object]]", facts)
