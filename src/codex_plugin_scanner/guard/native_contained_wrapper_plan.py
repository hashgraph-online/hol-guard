"""Resident bridge for the ``contained_wrapper_plan`` op.

Rust owns which wrapper a command carries. The execution sink used to peel the
shape a second time here, from its own lexer, its own sibling-repository rule
and its own output-filter grammar. Two peels of one shape drift: this copy
could not read a Windows owner SID, so it accepted checkouts the classifier had
refused and handed the sandbox a core no receipt covered. The classifier now
answers the question it already decided, and this module only carries the
answer. When the resident is unavailable the caller raises rather than peeling
anything itself.
"""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from .native_context import _resolve_digest_home, ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_store_policy import _payload

CONTAINED_WRAPPER_PLAN_FEATURE = "contained-wrapper-plan-v1"
_REQUEST_SCHEMA = "guard-contained-wrapper-plan-request.v1"
_RESULT_SCHEMA = "guard-contained-wrapper-plan-result.v1"
_TIMEOUT_SECONDS = 10.0
_MAX_REQUEST_BYTES = 256 * 1024


class ContainedWrapperPlanUnavailableError(RuntimeError):
    """Raised when the resident cannot say what the sink should run."""


def native_contained_wrapper_plan(
    command: str,
    *,
    workspace: Path,
    cwd: Path | None = None,
    home: Path | None = None,
    project_root_query: Path | None = None,
    guard_home: Path | None = None,
) -> dict[str, object]:
    """Return the peel the classifier resolved for ``command``.

    The answer carries ``plan`` (the core, its directory and its output
    handling), ``refusal`` for a wrapped shape the classifier does not peel,
    the two sibling repository roots the sink rebases to, and
    ``project_root`` for the directory named by ``project_root_query``.
    """

    digest_home = Path(_resolve_digest_home(guard_home))
    if not ensure_resident_prerequisite(digest_home):
        raise ContainedWrapperPlanUnavailableError
    wire: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"contained-wrapper-plan-{uuid4().hex}",
        "command": command,
        "workspace": str(workspace),
        "cwd": str(cwd) if cwd is not None else None,
        "home_dir": str(home) if home is not None else None,
        "project_root_query": str(project_root_query) if project_root_query is not None else None,
    }
    try:
        response = _resident_request(
            operation="contained_wrapper_plan",
            request=wire,
            guard_home=digest_home,
            timeout_seconds=_TIMEOUT_SECONDS,
            required_feature=CONTAINED_WRAPPER_PLAN_FEATURE,
            response_schema=_RESULT_SCHEMA,
            max_request_bytes=_MAX_REQUEST_BYTES,
            record_success=False,
        )
    except (TypeError, ValueError, OSError, RuntimeError):
        raise ContainedWrapperPlanUnavailableError from None
    payload = _payload(response, wire, digest_home)
    if not isinstance(payload, dict):
        raise ContainedWrapperPlanUnavailableError
    return payload
