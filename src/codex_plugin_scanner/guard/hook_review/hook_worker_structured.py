"""The daemon's side of Oh My Pi structured-output mediation.

The Rust edge resolves the managed policy and mediates the model-visible
content of an Oh My Pi or Pi ``PostToolUse``, and answers with the disposition
already in its harness response. The daemon only reads Guard config, which
only it can, and sends the edge the managed-policy view with the hook. Once
the edge forwards, or allows content it found nothing to mediate on, it reads
the config again: the answer stands only while the config still holds the view
the edge reviewed under.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Mapping

from ..native_content_sensitivity import content_query
from ..native_policy_snapshot_direct_lane_structured import structured_output_view

_LOG = logging.getLogger(__name__)

MEDIATION_FIELD = "structured_content_mediation"
_MEDIATION_SCHEMA = "guard-structured-content-mediation.v1"
_PI_ALIASES = {"pi-agent": "pi", "pi-coding-agent": "pi", "oh-my-pi": "omp"}


def withholds_structured_destination(*, harness: str, event_name: str) -> bool:
    """Return whether this hook can carry a managed structured destination."""

    # The spelling is presentation, not a policy decision; the edge
    # independently normalizes it and checks the policy's harnesses.
    normalized = harness.strip().lower().replace("_", "-")
    return event_name == "PostToolUse" and _PI_ALIASES.get(normalized, normalized) in {"pi", "omp"}


def _withheld(reason_code: str, native_decision_id: object = None) -> dict[str, object]:
    disposition: dict[str, object] = {
        "schema": _MEDIATION_SCHEMA,
        "action": "withhold",
        "reason_code": reason_code,
    }
    if isinstance(native_decision_id, str) and native_decision_id:
        disposition["native_decision_id"] = native_decision_id
    return disposition


def withhold_structured_destination(response: dict[str, object]) -> dict[str, object]:
    """Withhold the structured destination on an answer without native proof."""

    return {**response, MEDIATION_FIELD: _withheld("structured_native_edge_unavailable")}


def read_structured_view(load_config: Callable[[], object]) -> dict[str, object]:
    """The managed-policy view of Guard config, or ``{}`` when it cannot be read.

    The edge resolves ``{}`` as a config the daemon could not establish: a
    destination is required and no binding may release the content.
    """

    try:
        config = load_config()
        view = None if config is None else structured_output_view(config)
    except Exception as exc:
        # A config read failure cannot establish whether the managed route is
        # enrolled. Keep the model-visible destination fail-closed.
        _LOG.warning("structured managed policy read failed: %s", type(exc).__name__)
        view = None
    return view if view is not None else {}


def structured_destination_required(view: Mapping[str, object], *, harness: str) -> bool:
    """Whether ``view`` requires this harness's structured destination withheld.

    Only an answer the edge never gave needs this: the edge resolves the same
    query itself. Anything but a native ``required: false`` reads as required.
    """

    if not view:
        return True
    try:
        result = content_query("resolution", {"config": dict(view), "harness": harness})
    except Exception:
        return True
    return not (isinstance(result, dict) and result.get("required") is False)


def _expired(deadline: float | None) -> bool:
    return deadline is not None and time.monotonic() >= deadline


def _stale_reason(view: Mapping[str, object], load_config: Callable[[], object], deadline: float | None) -> str | None:
    if _expired(deadline):
        return "structured_review_deadline_exceeded"
    reason = _changed_reason(view, load_config)
    # The reread itself can run past the hook's budget.
    if reason is None and _expired(deadline):
        return "structured_review_deadline_exceeded"
    return reason


def _changed_reason(view: Mapping[str, object], load_config: Callable[[], object]) -> str | None:
    try:
        config = load_config()
        current = None if config is None else structured_output_view(config)
    except Exception as exc:
        # Only the class is logged: the message may carry a private path.
        _LOG.warning("structured binding recheck failed: %s", type(exc).__name__)
        return "structured_binding_recheck_failed"
    return None if current == dict(view) else "structured_binding_changed"


def withhold_stale_forward(
    response: dict[str, object],
    *,
    view: Mapping[str, object],
    load_config: Callable[[], object],
    deadline: float | None,
    allowed: bool = False,
) -> dict[str, object]:
    """Release the edge's answer only while the config still holds ``view``.

    This second read is a revocation check after the scan; reusing the first
    read would permit a stale forward. An ``allowed`` answer the edge attached
    no disposition to is checked too: the view required none, and a policy
    activated during the review must not let the content through unmediated.
    A withhold needs no check.
    """

    disposition = response.get(MEDIATION_FIELD)
    if isinstance(disposition, dict) and disposition.get("action") == "forward":
        reason = _stale_reason(view, load_config, deadline)
        native_decision_id = disposition.get("native_decision_id")
    elif disposition is None and allowed:
        # Nothing was mediated, so only a changed view can withhold it.
        reason = _changed_reason(view, load_config)
        native_decision_id = None
    else:
        return response
    if reason is None:
        return response
    return {**response, MEDIATION_FIELD: _withheld(reason, native_decision_id)}
