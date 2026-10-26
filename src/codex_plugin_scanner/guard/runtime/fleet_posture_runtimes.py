"""The optional ``runtimes`` section of ``fleet-posture/v1``.

It carries the runtimes configured MCP servers launch, as ``hol-guard runtime posture``
observes them, without paths, server names or command lines: the executable is
named by its content digest and its location by a keyed digest. Nothing is
started and no running process is enumerated, so the scope is never complete and
no runtime is reported safe.

Observing launches hashes executables, which is too slow to repeat on every
receipt sync, so the section is cached in the store for an hour. The cache entry
is bound to the workspace it observed, the key its location digests were made
with and the cached bundle's verification inputs, so a sync for another workspace,
a key change or a new bundle observes again; it also lapses when the bundle does.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Mapping
from datetime import datetime
from typing import TYPE_CHECKING, Any, cast

from .fleet_posture_common import HARNESS_IDS, clip, iso, keyed_digest, parse_timestamp

if TYPE_CHECKING:
    from ..adapters.base import HarnessContext
    from ..store import GuardStore

_LOGGER = logging.getLogger(__name__)

RUNTIMES_STATE_KEY = "fleet_posture_runtimes"
RUNTIMES_TTL_SECONDS = 3600
MAX_RUNTIMES = 64
MAX_ADVISORY_IDS = 16
MAX_UNRESOLVED_LAUNCHES = 10_000
ASSURANCES = frozenset({"vendor_verified", "locally_trusted", "self_reported", "unknown"})
LOCATION_STATES = frozenset({"present", "missing", "unknown"})
STATUSES = frozenset({"ok", "partial", "unavailable"})

_CODE = re.compile(r"^[a-z0-9_]{1,64}$")
_SHA256_HEX = re.compile(r"^[a-f0-9]{64}$")


def runtimes_section(
    store: GuardStore,
    context: HarnessContext,
    *,
    hash_key: bytes,
    now: datetime,
    ttl_seconds: int = RUNTIMES_TTL_SECONDS,
) -> dict[str, object] | None:
    """The cached section, refreshed when older than ``ttl_seconds``; ``None`` when it cannot be built."""

    advisory = _advisory_bundle(store)
    scope = _cache_scope(context, hash_key, advisory)
    if ttl_seconds > 0:
        cached = store.get_sync_payload(RUNTIMES_STATE_KEY)
        if (
            isinstance(cached, dict)
            and cached.get("scope") == scope
            and isinstance(section := cached.get("section"), dict)
        ):
            fetched = parse_timestamp(cached.get("at"))
            valid_until = cached.get("valid_until")
            # Matches from a bundle are good only until that bundle expires.
            fresh_bundle = valid_until is None or (
                isinstance(valid_until, (int, float)) and now.timestamp() < valid_until
            )
            if fetched is not None and fresh_bundle and 0 <= (now - fetched).total_seconds() < ttl_seconds:
                return cast("dict[str, object]", section)
    try:
        posture = _observe(context, now, advisory)
        section = project_runtime_posture(posture, hash_key=hash_key)
    except Exception:
        _LOGGER.debug("fleet posture: runtime posture could not be observed", exc_info=True)
        return None
    if ttl_seconds > 0:
        source = posture.get("advisory_source")
        valid_until = source.get("valid_until") if isinstance(source, Mapping) else None
        entry: dict[str, object] = {"at": iso(now), "scope": scope, "section": section}
        entry["valid_until"] = valid_until if isinstance(valid_until, (int, float)) else None
        try:
            store.set_sync_payload(RUNTIMES_STATE_KEY, entry, iso(now))
        except Exception:
            _LOGGER.debug("fleet posture: runtime posture cache could not be saved", exc_info=True)
    return section


def _advisory_bundle(store: GuardStore) -> tuple[Mapping[str, object] | None, str | None]:
    from ..runtime_advisory_bundle import BUNDLE_UNREADABLE, cached_advisory_bundle

    try:
        return cached_advisory_bundle(store)
    except Exception:
        _LOGGER.debug("fleet posture: cached advisory bundle could not be read", exc_info=True)
        return None, BUNDLE_UNREADABLE


def _cache_scope(
    context: HarnessContext, hash_key: bytes, advisory: tuple[Mapping[str, object] | None, str | None]
) -> str:
    # Keyed, so the stored scope names no path and changes whenever the key does.
    # Every input native verification reads (the Cloud workspace, the recorded
    # keyring and entitlement, and the bundle itself) is part of the scope, so a
    # workspace switch, key change or new sync rematches on the next report.
    workspace = str(context.workspace_dir.resolve()) if context.workspace_dir is not None else ""
    bundle, reason = advisory
    if bundle is None:
        tag = f"none:{reason}"
    else:
        response = bundle.get("response")
        signed = response.get("bundle") if isinstance(response, Mapping) else None
        inputs = {
            "workspace_id": bundle.get("workspace_id"),
            "sync_keyring": bundle.get("sync_keyring"),
            "entitlement": bundle.get("entitlement"),
            "signed": signed,
            "signature": response.get("signature") if isinstance(response, Mapping) else None,
        }
        tag = "bundle:" + json.dumps(inputs, sort_keys=True, default=str)
    return keyed_digest(hash_key, f"fleet-posture-runtimes\0{workspace}\0{tag}")


def _observe(
    context: HarnessContext, now: datetime, advisory: tuple[Mapping[str, object] | None, str | None]
) -> Mapping[str, Any]:
    from ..adapters.harness_mcp_discovery import configured_harness_detections
    from ..runtime_posture import build_runtime_posture

    skipped: list[str] = []
    detections = configured_harness_detections(
        context.home_dir, context.guard_home, context.workspace_dir, skipped=skipped
    )
    return build_runtime_posture(
        detections,
        generated_at=iso(now),
        workspace_dir=context.workspace_dir,
        skipped_harnesses=skipped,
        advisory_bundle=advisory[0],
        advisory_bundle_reason=advisory[1],
    )


def project_runtime_posture(posture: Mapping[str, Any], *, hash_key: bytes) -> dict[str, object]:
    """Reduce a ``hol-guard runtime posture`` payload to the contract's ``runtimes`` section."""

    status = posture.get("status")
    if status not in STATUSES:
        raise ValueError("unexpected runtime posture status")
    coverage = posture.get("coverage")
    rows = posture.get("runtimes")
    rows = [row for row in rows if isinstance(row, Mapping)] if isinstance(rows, list) else []
    unresolved = posture.get("unresolved_launches")
    truncated = len(rows) > MAX_RUNTIMES
    error = posture.get("error")
    reason = _code(error) if error is not None else None
    if truncated and status == "ok":
        status, reason = "partial", "runtime_candidate_limit_reached"
    return {
        "status": status,
        "reason": reason,
        "coverage": "observed_only",
        "scopeComplete": False,
        "advisoriesAvailable": isinstance(coverage, Mapping) and coverage.get("advisories_available") is True,
        "candidateLimitReached": bool(posture.get("candidate_limit_reached")) or truncated,
        "unresolvedLaunches": min(len(unresolved) if isinstance(unresolved, list) else 0, MAX_UNRESOLVED_LAUNCHES),
        "items": [_item(row, hash_key) for row in rows[:MAX_RUNTIMES]],
    }


def _item(row: Mapping[str, Any], hash_key: bytes) -> dict[str, object]:
    version = row.get("version")
    executable = row.get("executable_sha256")
    path = row.get("path")
    reason = row.get("reason")
    assurance = row.get("identity_assurance")
    state = row.get("location_state")
    launched = row.get("launched_by")
    harnesses: set[str] = set()
    for entry in launched if isinstance(launched, list) else []:
        harness = entry.get("harness") if isinstance(entry, Mapping) else None
        if isinstance(harness, str) and harness in HARNESS_IDS:
            harnesses.add(harness)
    return {
        "family": _code(row.get("family"), fallback="unknown"),
        "version": clip(version, 64) if isinstance(version, str) and version else None,
        "identityAssurance": assurance if assurance in ASSURANCES else "unknown",
        "executableHash": f"sha256:{executable}"
        if isinstance(executable, str) and _SHA256_HEX.match(executable)
        else None,
        "os": _code(row.get("os"), fallback="unknown"),
        "arch": _code(row.get("arch"), fallback="unknown"),
        "locationState": state if state in LOCATION_STATES else "unknown",
        "reason": _code(reason) if reason is not None else None,
        "locationHash": keyed_digest(hash_key, path) if isinstance(path, str) and path else None,
        "harnesses": sorted(harnesses),
        "advisoryIds": _advisory_ids(row.get("advisory_matches")),
    }


def _advisory_ids(matches: object) -> list[str]:
    ids: list[str] = []
    for match in matches if isinstance(matches, list) else []:
        advisory_id = match.get("advisory_id") if isinstance(match, Mapping) else match
        if isinstance(advisory_id, str) and 0 < len(advisory_id) <= 128 and advisory_id not in ids:
            ids.append(advisory_id)
    return ids[:MAX_ADVISORY_IDS]


def _code(value: object, *, fallback: str = "unknown") -> str:
    return value if isinstance(value, str) and _CODE.match(value) else fallback


__all__ = [
    "MAX_RUNTIMES",
    "RUNTIMES_STATE_KEY",
    "RUNTIMES_TTL_SECONDS",
    "project_runtime_posture",
    "runtimes_section",
]
