"""Decide whether an observed harness version is covered by bundled evidence.

This is a pure function of the observation, the manifest, and the running
Guard build. Its result is display data only: it never feeds policy, approval,
or tool admission. Every uncertain input lands on an uncertain state; nothing
falls through to ``tested``.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from ..adapters.contracts import contract_for
from .discovery import VersionObservation
from .manifest import CoverageRecord, ManifestLoad

OBSERVATION_MAX_AGE_SECONDS = 15 * 60

STATE_TESTED = "tested"
STATE_UNTESTED = "untested"
STATE_VERSION_UNKNOWN = "version_unknown"
STATE_COVERAGE_UNAVAILABLE = "coverage_unavailable"
PAYLOAD_SCHEMA = "hol-guard-harness-version-compatibility.v1"


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def declared_events(harness: str) -> tuple[str, ...]:
    """Events the adapter declares an active protection transport for."""

    contract = contract_for(harness)
    if contract is None:
        return ()
    events = {
        row.event
        for row in contract.capability_events
        if row.transport not in {"none", "adapter_declared"} and "unavailable" not in row.declared_actions
    }
    return tuple(sorted(events))


def acknowledgement_key(*, harness: str, installation_id: str, version: str, revision: str, guard_version: str) -> str:
    """Bind an acknowledgement to installation, exact version, and coverage."""

    material = "\0".join(("hvc-ack.v1", harness, installation_id, version, revision, guard_version))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _base_payload(
    harness: str, observation: VersionObservation, now: float, guard_version: str, platform: str
) -> dict[str, object]:
    fresh = observation.state == "observed" and 0 <= now - observation.observed_at <= OBSERVATION_MAX_AGE_SECONDS
    return {
        "schema": PAYLOAD_SCHEMA,
        "harness": harness,
        "state": STATE_VERSION_UNKNOWN,
        "reason": observation.reason,
        "detected_version": observation.version.canonical if observation.version else None,
        "version_is_prerelease": bool(observation.version and observation.version.is_prerelease),
        "version_source": observation.source,
        "observed_at": _iso(observation.observed_at),
        "observation_fresh": fresh,
        "guard_version": guard_version,
        "platform": platform,
        "coverage_revision": None,
        "tested_versions": [],
        "tested_scope": None,
        "tested_events": [],
        "declared_events": list(declared_events(harness)),
        "evidence": [],
        "limitations": [],
        "remediation": [],
        "acknowledgement": {"eligible": False, "acknowledged": False, "key": None},
        # Compatibility is informational. Enforcement never reads this payload.
        "enforcement_effect": "none",
    }


def decide_compatibility(
    *,
    harness: str,
    observation: VersionObservation,
    manifest_load: ManifestLoad,
    guard_version: str,
    platform: str,
    now: float,
    acknowledged_keys: frozenset[str] = frozenset(),
) -> dict[str, object]:
    """Return the version-compatibility payload for one App coverage row."""

    payload = _base_payload(harness, observation, now, guard_version, platform)
    manifest = manifest_load.manifest
    coverage = manifest.harnesses.get(harness) if manifest else None
    if manifest is not None:
        payload["coverage_revision"] = manifest.revision
    if coverage is not None:
        payload["limitations"] = list(coverage.limitations)
        payload["remediation"] = [{"label": link.label, "url": link.url} for link in coverage.remediation]
    applicable: list[CoverageRecord] = []
    if coverage is not None:
        applicable = [
            record
            for record in coverage.records
            if record.guard_version == guard_version and platform in record.platforms
        ]
    payload["tested_versions"] = sorted({record.harness_version.canonical for record in applicable})

    if observation.state != "observed" or observation.version is None:
        payload["reason"] = observation.reason or "version_unobserved"
        return payload
    if not payload["observation_fresh"]:
        payload["reason"] = "observation_stale"
        return payload
    if manifest is None:
        payload["state"] = STATE_COVERAGE_UNAVAILABLE
        payload["reason"] = manifest_load.error or "manifest_invalid"
        return payload
    if coverage is None or not coverage.records:
        payload["state"] = STATE_COVERAGE_UNAVAILABLE
        payload["reason"] = "harness_not_covered"
        return payload
    if not applicable:
        payload["state"] = STATE_COVERAGE_UNAVAILABLE
        payload["reason"] = "no_evidence_for_this_build"
        return payload

    detected = observation.version.canonical
    matching = [record for record in applicable if record.harness_version.canonical == detected]
    if not matching:
        payload["state"] = STATE_UNTESTED
        payload["reason"] = "version_not_in_evidence"
        key = acknowledgement_key(
            harness=harness,
            installation_id=observation.installation_id or "",
            version=detected,
            revision=manifest.revision,
            guard_version=guard_version,
        )
        payload["acknowledgement"] = {
            "eligible": observation.installation_id is not None,
            "acknowledged": observation.installation_id is not None and key in acknowledged_keys,
            "key": key if observation.installation_id is not None else None,
        }
        return payload

    tested_events = sorted({event for record in matching for event in record.events})
    payload["state"] = STATE_TESTED
    payload["reason"] = None
    payload["tested_events"] = tested_events
    declared = set(declared_events(harness))
    payload["tested_scope"] = "all_declared_events" if declared and declared <= set(tested_events) else "partial"
    payload["evidence"] = [record.to_dict() for record in matching]
    return payload
