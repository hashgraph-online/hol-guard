"""Live "always allow via extension" recommendation for one pending approval request.

The queue-time hint records which configurable permissions would have let the
command run. The resident (``approval_extension_recommendation``) re-checks that
hint against the catalog it admitted and the current control authority on every
read, so stale or no-longer-applicable advice is never shown. Payloads carry
catalog identifiers and labels only, never command text. Python hands the
resident the hint and the control view it already holds and shape-checks the
answer; there is no Python evaluator and no fallback, so an unavailable
resident means no recommendation.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Any, Final

from ..native_daemon_route import _decide
from ..native_extension_control import _layer_wire  # pyright: ignore[reportPrivateUsage]
from ..native_resident_decision import ResidentOperation, shape_fields
from ..runtime.command_extensions import CommandSafetyExtensionRegistry
from ..runtime.extension_allow_hint import validated_extension_allow_hint
from ..runtime.extension_control_runtime import ExtensionControlRuntimeSnapshot

_LOGGER = logging.getLogger(__name__)
RECOMMENDATION_SCHEMA = "guard.approval-extension-recommendation.v1"
APPROVAL_EXTENSION_RECOMMENDATION_FEATURE: Final = "approval-extension-recommendation-v1"
_TIMEOUT_SECONDS: Final = 3.0
# The resident refuses a canonical request over 4 MiB; the envelope adds a
# little around it, so a request the resident would refuse is never sent.
_MAX_REQUEST_BYTES: Final = 4 * 1024 * 1024 + 64 * 1024
_MAX_PERMISSIONS: Final = 12
_MAX_CONCURRENT_ASKS: Final = 4
_SLOTS: Final = threading.BoundedSemaphore(_MAX_CONCURRENT_ASKS)
_STATUSES: Final = frozenset({"available", "authority_unavailable"})
_OPT_STR: Final = (str, type(None))
_RECOMMENDATION_FIELDS: Final = {
    "schema": str,
    "status": str,
    "permissions": list,
    "caution": bool,
    "revision": int,
    "catalog_digest": str,
}
_PERMISSION_FIELDS: Final = {
    "permission_id": str,
    "label": _OPT_STR,
    "description": _OPT_STR,
    "example_command": _OPT_STR,
    "extension_id": str,
    "extension_name": _OPT_STR,
    "rule_id": _OPT_STR,
    "risk_tier": str,
    "caution": bool,
    "caution_reason": _OPT_STR,
    "caution_detail": _OPT_STR,
    "cli_command": str,
}


class NativeApprovalExtensionRecommendationError(RuntimeError):
    """No authoritative answer; ``code`` says why, for diagnostics only."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


_OPERATION: Final = ResidentOperation(
    operation="approval_extension_recommendation",
    feature=APPROVAL_EXTENSION_RECOMMENDATION_FEATURE,
    prefix="native_approval_extension_recommendation",
    request_schema="guard-approval-extension-recommendation-request.v1",
    request_id_prefix="approval-extension-recommendation",
    result_schema="guard-approval-extension-recommendation-result.v1",
    timeout_seconds=_TIMEOUT_SECONDS,
    error=NativeApprovalExtensionRecommendationError,
)


def _invalid() -> RuntimeError:
    return _OPERATION.fail(_OPERATION.invalid)


def _checked(recommendation: object) -> dict[str, object]:
    value = shape_fields(recommendation, _RECOMMENDATION_FIELDS, _invalid)
    permissions: list[object] = value["permissions"]
    if (
        value["schema"] != RECOMMENDATION_SCHEMA
        or value["status"] not in _STATUSES
        or not 0 < len(permissions) <= _MAX_PERMISSIONS
    ):
        raise _invalid()
    for permission in permissions:
        shape_fields(permission, _PERMISSION_FIELDS, _invalid)
    return value


def _ask(
    query: dict[str, object],
    guard_home: Path | None,
    fields: Mapping[str, Any],
    parse: Callable[[dict[str, Any]], Any],
) -> Any:
    parsed: list[Any] = []

    def validate(payload: dict[str, Any]) -> None:
        parsed.append(parse(payload))

    _decide(
        query,
        guard_home,
        fields,
        validate,
        operation=_OPERATION,
        max_request_bytes=_MAX_REQUEST_BYTES,
        slots=_SLOTS,
    )
    return parsed[0]


def native_caution_risk_classes(risk_classes: Iterable[str], *, guard_home: Path | None = None) -> frozenset[str]:
    """The subset of ``risk_classes`` whose Allow calls for a caution, as the resident decides.

    Raises ``NativeApprovalExtensionRecommendationError`` when the resident gave
    no authoritative answer; the caller must treat that as unknown, never safe.
    """

    asked = sorted(set(risk_classes))
    if not asked:
        return frozenset()

    def parse(payload: dict[str, Any]) -> frozenset[str]:
        answered = payload["risk_classes"]
        if not all(isinstance(item, str) for item in answered) or not set(answered) <= set(asked):
            raise _invalid()
        return frozenset(answered)

    return _ask({"kind": "caution_risk_classes", "risk_classes": asked}, guard_home, {"risk_classes": list}, parse)


def build_approval_extension_recommendation(
    approval: dict[str, object],
    *,
    registry: CommandSafetyExtensionRegistry,
    snapshot: ExtensionControlRuntimeSnapshot,
    guard_home: Path | None = None,
) -> dict[str, object] | None:
    """Return the recommendation for a pending request, or None when not applicable."""

    if approval.get("status") != "pending":
        return None
    hint = validated_extension_allow_hint(approval.get("extension_allow_hint"))
    if hint is None:
        return None
    query: dict[str, object] = {
        "kind": "recommend",
        "hint": hint,
        "registry_catalog_digest": registry.catalog_digest,
        "snapshot": {
            "health": snapshot.health.value,
            "revision": snapshot.revision,
            "catalog_digest": snapshot.catalog_digest,
            "layers": [_layer_wire(layer) for layer in snapshot.layers],
        },
    }

    def parse(payload: dict[str, Any]) -> dict[str, object] | None:
        recommendation = payload["recommendation"]
        return None if recommendation is None else _checked(recommendation)

    return _ask(query, guard_home, {"recommendation": (dict, type(None))}, parse)


def with_approval_extension_recommendation(
    approval: dict[str, object],
    *,
    registry: CommandSafetyExtensionRegistry | None,
    snapshot: ExtensionControlRuntimeSnapshot | None,
    include: bool,
    guard_home: Path | None = None,
) -> dict[str, object]:
    """Replace the private queue hint with a live recommendation; never fails the read."""

    payload = {key: value for key, value in approval.items() if key != "extension_allow_hint"}
    if not include or registry is None or snapshot is None:
        return payload
    try:
        recommendation = build_approval_extension_recommendation(
            approval, registry=registry, snapshot=snapshot, guard_home=guard_home
        )
    except NativeApprovalExtensionRecommendationError as error:
        _LOGGER.warning("Extension recommendation unavailable (%s)", error.code)
        recommendation = None
    except (AttributeError, KeyError, RuntimeError, TypeError, ValueError) as error:
        _LOGGER.warning("Extension recommendation unavailable (%s)", type(error).__name__)
        recommendation = None
    if recommendation is not None:
        payload["extension_recommendation"] = recommendation
    return payload
