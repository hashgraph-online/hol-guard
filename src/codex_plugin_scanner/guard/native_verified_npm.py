"""Resident bridge for the ``verified_npm`` op.

The resident owns the proof that a package install really is the standard npm
the agent's ``PATH`` resolves: it resolves ``npm`` and ``node``, reads the npm
manifest and the npm config files above the project, checks the exported
loader paths, and resolves the output filters the command pipes through. The
caller forwards the stamped execution environment unchanged and applies the
answer; it never re-derives any part of it.

An unavailable or malformed native answer raises
:class:`NativeVerifiedNpmError`. There is no Python fallback, so a resident
that cannot answer leaves the install in review rather than proving it safe.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from .native_context import _canonical_request_sha256, ensure_resident_prerequisite
from .native_package_authority import _REQUEST_SCHEMA, _RESULT_SCHEMA, _request_id, _resident_request

_VERIFIED_NPM_FEATURE = "verified-npm-v1"
_TIMEOUT_SECONDS = 2.0


class NativeVerifiedNpmError(RuntimeError):
    """No authoritative native npm proof was available."""


def verified_npm_proof(
    environment: object,
    *,
    workspace: Path,
    guard_home: Path,
    filter_programs: Sequence[str] = (),
    deadline: float | None = None,
) -> tuple[str | None, bool]:
    """The proven npm version and whether every output filter stays outside.

    A ``None`` version means the resident could not prove which npm will run,
    which is an answer, not a failure: the caller keeps reviewing.
    """

    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": _request_id(),
        "guard_home": str(guard_home),
        "workspace": str(workspace),
        "environment": environment,
        "filter_programs": list(filter_programs),
    }
    try:
        request_sha256 = "sha256:" + _canonical_request_sha256(request)
    except (TypeError, ValueError) as error:
        raise NativeVerifiedNpmError("Native npm proof request invalid") from error
    if not ensure_resident_prerequisite(guard_home):
        raise NativeVerifiedNpmError("Native npm proof unavailable")
    response = _resident_request(
        operation="verified_npm",
        request=request,
        guard_home=guard_home,
        timeout_seconds=_TIMEOUT_SECONDS,
        deadline_monotonic=deadline,
        required_features=(_VERIFIED_NPM_FEATURE,),
    )
    if (
        not isinstance(response, dict)
        or response.get("schema") != _RESULT_SCHEMA
        or response.get("request_id") != request["request_id"]
        or response.get("request_sha256") != request_sha256
        or response.get("status") != "ok"
        or response.get("code") != "ok"
    ):
        raise NativeVerifiedNpmError("Native npm proof unavailable or invalid")
    payload = response.get("payload")
    if not isinstance(payload, dict) or set(payload) != {"version", "filters_outside_workspace"}:
        raise NativeVerifiedNpmError("Native npm proof invalid")
    version = payload["version"]
    outside = payload["filters_outside_workspace"]
    if not isinstance(outside, bool) or not (version is None or (isinstance(version, str) and version)):
        raise NativeVerifiedNpmError("Native npm proof invalid")
    return version, outside
