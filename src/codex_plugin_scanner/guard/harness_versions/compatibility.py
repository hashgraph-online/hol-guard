"""Decide whether an observed harness version is covered by bundled evidence.

The native runtime owns the decision, the manifest validation, and the
acknowledgement store. Its result is display data only: it never feeds
policy, approval, or tool admission. Every uncertain input lands on an
uncertain state; nothing falls through to ``tested``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

from ..adapters.contracts import HARNESS_CONTRACTS
from .discovery import VersionObservation

OBSERVATION_MAX_AGE_SECONDS = 15 * 60

STATE_TESTED = "tested"
STATE_UNTESTED = "untested"
STATE_VERSION_UNKNOWN = "version_unknown"
STATE_COVERAGE_UNAVAILABLE = "coverage_unavailable"
PAYLOAD_SCHEMA = "hol-guard-harness-version-compatibility.v1"

_FEATURE: Final = "native-harness-version-compatibility-v1"
_COMMAND: Final = "harness-version-compatibility"
_SCHEMA: Final = "harness-version-compatibility.v1"
_OUTPUT_LIMIT: Final = 256 * 1024
_TIMEOUT_SECONDS: Final = 10.0


def _contracts() -> dict[str, list[dict[str, object]]]:
    return {
        contract.harness: [
            {"event": row.event, "transport": row.transport, "declared_actions": list(row.declared_actions)}
            for row in contract.capability_events
        ]
        for contract in HARNESS_CONTRACTS
    }


def runtime_request(op: str, guard_home: Path, harness: str, **fields: object) -> dict[str, object] | None:
    """One ``harness-version-compatibility`` answer, or ``None`` without a runtime."""

    from ..mdm.runtime_request import runtime_answer

    request: dict[str, object] = {
        "schema": _SCHEMA,
        "op": op,
        "guard_home": str(guard_home),
        "harness": harness,
        **fields,
    }
    return runtime_answer(_FEATURE, _COMMAND, request, output_limit=_OUTPUT_LIMIT, timeout_seconds=_TIMEOUT_SECONDS)


def decide_compatibility(
    *,
    harness: str,
    observation: VersionObservation,
    manifest_path: Path,
    guard_version: str,
    platform: str,
    now: float,
    guard_home: Path,
) -> dict[str, object]:
    """Return the version-compatibility payload for one App coverage row."""

    answer = runtime_request(
        "decide",
        guard_home,
        harness,
        manifest_path=str(manifest_path),
        guard_version=guard_version,
        platform=platform,
        now=now,
        observation={
            "state": observation.state,
            "version": observation.version,
            "source": observation.source,
            "installation_id": observation.installation_id,
            "reason": observation.reason,
            "observed_at": observation.observed_at,
        },
        contracts=_contracts(),
    )
    if answer is None:
        return {
            "schema": PAYLOAD_SCHEMA,
            "harness": harness,
            "state": STATE_VERSION_UNKNOWN,
            "reason": "runtime_unavailable",
            "enforcement_effect": "none",
        }
    return answer
