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
from collections.abc import Mapping
from datetime import datetime
from typing import TYPE_CHECKING, Any, cast

from .fleet_posture_common import iso, keyed_digest, parse_timestamp

if TYPE_CHECKING:
    from pathlib import Path

    from ..adapters.base import HarnessContext
    from ..store import GuardStore

_LOGGER = logging.getLogger(__name__)

RUNTIMES_STATE_KEY = "fleet_posture_runtimes"
RUNTIMES_TTL_SECONDS = 3600
MAX_RUNTIMES = 64
# The native request parser refuses wider arrays; long lists cross in chunks.
_NATIVE_JSON_WIDTH = 4096


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
        section = project_runtime_posture(posture, hash_key=hash_key, guard_home=context.guard_home)
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
        instance_home=context.guard_home,
    )


def project_runtime_posture(
    posture: Mapping[str, Any], *, hash_key: bytes, guard_home: Path | None = None
) -> dict[str, object]:
    """Reduce a ``hol-guard runtime posture`` payload to the contract's ``runtimes`` section.

    The native runtime shapes the section; a posture it refuses raises.
    """

    from ..native_runner_authority import native_runner_authority

    request = dict(posture)
    for key in ("runtimes", "unresolved_launches"):
        values = request.get(key)
        request[key] = _chunks(values) if isinstance(values, list) else None
    answer = native_runner_authority(
        "fleet_runtime_posture",
        {"posture": request, "hash_key": hash_key.decode("utf-8")},
        guard_home,
    )
    return cast("dict[str, object]", answer)


def _chunks(values: list[Any]) -> list[list[Any]]:
    return [values[start : start + _NATIVE_JSON_WIDTH] for start in range(0, len(values), _NATIVE_JSON_WIDTH)]


__all__ = [
    "MAX_RUNTIMES",
    "RUNTIMES_STATE_KEY",
    "RUNTIMES_TTL_SECONDS",
    "project_runtime_posture",
    "runtimes_section",
]
