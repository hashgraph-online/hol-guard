"""Dashboard API for harness version compatibility.

Reads attach a ``version_compatibility`` object to each ``GET /v1/harnesses``
item. Writes (refresh, acknowledge, clear) are header-token routes. None of
these routes touch policy, approvals, or harness installations.
"""

from __future__ import annotations

import logging
from typing import Protocol, cast

from ..adapters.base import HarnessContext
from ..adapters.contracts import contract_for
from ..harness_versions import service
from ..harness_versions.compatibility import PAYLOAD_SCHEMA, STATE_VERSION_UNKNOWN

_LOGGER = logging.getLogger(__name__)

REFRESH_PATH = "/v1/harness-versions/refresh"
ACKNOWLEDGE_PATH = "/v1/harness-versions/acknowledge"
CLEAR_PATH = "/v1/harness-versions/clear-acknowledgement"
WRITE_PATHS = frozenset({REFRESH_PATH, ACKNOWLEDGE_PATH, CLEAR_PATH})


class _JsonWriter(Protocol):
    def _write_json(self, payload: dict[str, object], *, status: int = 200) -> None: ...


def _failed_payload(harness: str) -> dict[str, object]:
    return {
        "schema": PAYLOAD_SCHEMA,
        "harness": harness,
        "state": STATE_VERSION_UNKNOWN,
        "reason": "discovery_failed",
        "enforcement_effect": "none",
    }


def compatibility_or_unknown(harness: str, context: HarnessContext, *, force: bool = False) -> dict[str, object]:
    try:
        return service.compatibility_for(harness, context, force=force)
    except Exception:
        _LOGGER.exception("Guard could not determine the %s version", harness)
        return _failed_payload(harness)


def attach_version_compatibility(items: list[dict[str, object]], context: HarnessContext) -> list[dict[str, object]]:
    for item in items:
        harness = str(item.get("harness", ""))
        item["version_compatibility"] = compatibility_or_unknown(harness, context)
    return items


def _canonical_harness(payload: dict[str, object]) -> str | None:
    harness = payload.get("harness")
    if not isinstance(harness, str) or len(harness) > 64:
        return None
    contract = contract_for(harness)
    if contract is None or contract.harness != harness:
        return None
    return harness


def handle_harness_version_write(
    handler: object, path: str, payload: dict[str, object], context: HarnessContext
) -> None:
    target = cast(_JsonWriter, handler)
    harness = _canonical_harness(payload)
    if harness is None:
        target._write_json({"error": "invalid_harness"}, status=400)
        return
    if path == REFRESH_PATH:
        service.invalidate(context.guard_home, harness)
        target._write_json({"version_compatibility": compatibility_or_unknown(harness, context, force=True)})
        return
    try:
        if path == ACKNOWLEDGE_PATH:
            result = service.acknowledge(harness, payload.get("acknowledgement_key"), context)
        else:
            result = service.clear_acknowledgement(harness, context)
    except service.AcknowledgementRejectedError as error:
        target._write_json({"error": str(error)}, status=409)
        return
    except OSError:
        target._write_json({"error": "acknowledgement_store_unavailable"}, status=500)
        return
    target._write_json({"version_compatibility": result})
