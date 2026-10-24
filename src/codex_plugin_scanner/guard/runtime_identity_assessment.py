"""Bridge to the native ``runtime-identity-assess`` command.

The native command owns every decision: version parsing, vendor and family
matching, identity assurance and whether a fix is proven. This module only
sends the observed artifacts, locations, instances and cached advisories and
checks the reply's shape. It reads no files and starts nothing but the
compiled runtime.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Literal, cast

RUNTIME_IDENTITY_FEATURE = "runtime-identity-assess-v1"
RUNTIME_IDENTITY_COMMAND = "runtime-identity-assess"
RUNTIME_IDENTITY_SCHEMA = "guard.runtime-identity-assessment.v1"

AdvisoryVerdict = Literal[
    "affected", "restart_required", "fix_unverified", "fixed_verified", "unknown", "not_affected", "not_observed"
]
_VERDICTS = frozenset(AdvisoryVerdict.__args__)  # type: ignore[attr-defined]

_VERDICT_LISTS = ("reasons", "affected_artifact_ids", "affected_instance_ids", "replacement_instance_ids")

_TIMEOUT_SECONDS = 10.0
_OUTPUT_LIMIT_BYTES = 4 * 1024 * 1024
_CHILD_ENVIRONMENT_KEYS = ("SYSTEMROOT", "WINDIR", "TMPDIR", "TEMP", "TMP")


class RuntimeIdentityError(RuntimeError):
    """The native assessment was unavailable or returned an unusable reply."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class RuntimeAdvisoryVerdict:
    advisory_id: str
    verdict: AdvisoryVerdict
    reasons: tuple[str, ...]
    affected_artifact_ids: tuple[str, ...]
    affected_instance_ids: tuple[str, ...]
    replacement_instance_ids: tuple[str, ...]


@dataclass(frozen=True)
class RuntimeIdentityAssessment:
    scope_complete: bool
    artifacts: tuple[dict[str, object], ...]
    advisories: tuple[RuntimeAdvisoryVerdict, ...]


def assess_runtime_identity(request: dict[str, object]) -> RuntimeIdentityAssessment:
    reply = _native_request(request)
    if reply.get("ok") is not True:
        error = reply.get("error")
        raise RuntimeIdentityError(error if isinstance(error, str) and error else "runtime_identity_failed")
    return _parse_result(reply.get("result"))


def _native_request(request: dict[str, object]) -> dict[str, object]:
    import os

    from .codex_hook_launch_runtime import run_isolated_hook_process
    from .native_runtime import _windows_native_dll_directories, native_runtime_status

    status = native_runtime_status()
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or RUNTIME_IDENTITY_FEATURE not in status.capabilities.features
    ):
        raise RuntimeIdentityError("runtime_identity_native_unavailable")
    runtime = status.identity.path
    environment = {key: value for key in _CHILD_ENVIRONMENT_KEYS if (value := os.environ.get(key))}
    if os.name == "nt":
        # Same loader path the capability probe used, so a runtime whose CRT
        # sits beside the base interpreter starts here too.
        dll_path = os.pathsep.join(_windows_native_dll_directories())
        if dll_path:
            environment["PATH"] = dll_path
    completed = run_isolated_hook_process(
        (str(runtime), RUNTIME_IDENTITY_COMMAND, "--stdin"),
        input_text=json.dumps(request, sort_keys=True, separators=(",", ":")),
        cwd=runtime.parent,
        environment=environment,
        timeout_seconds=_TIMEOUT_SECONDS,
        output_limit=_OUTPUT_LIMIT_BYTES,
    )
    if (
        completed.returncode != 0
        or completed.timed_out
        or completed.output_limit_exceeded
        or completed.containment_failed
    ):
        raise RuntimeIdentityError("runtime_identity_failed")
    try:
        response = json.loads(completed.stdout)
    except ValueError as error:
        raise RuntimeIdentityError("runtime_identity_failed") from error
    if not isinstance(response, dict) or not isinstance(response.get("ok"), bool):
        raise RuntimeIdentityError("runtime_identity_failed")
    return response


def _parse_result(result: object) -> RuntimeIdentityAssessment:
    if not isinstance(result, dict) or result.get("schema") != RUNTIME_IDENTITY_SCHEMA:
        raise RuntimeIdentityError("runtime_identity_failed")
    artifacts = result.get("artifacts")
    advisories = result.get("advisories")
    scope_complete = result.get("scope_complete")
    if not isinstance(artifacts, list) or not isinstance(advisories, list) or not isinstance(scope_complete, bool):
        raise RuntimeIdentityError("runtime_identity_failed")
    if not all(_artifact_row_ok(row) for row in artifacts):
        raise RuntimeIdentityError("runtime_identity_failed")
    return RuntimeIdentityAssessment(
        scope_complete=scope_complete,
        artifacts=tuple(artifacts),
        advisories=tuple(_parse_verdict(row) for row in advisories),
    )


def _artifact_row_ok(row: object) -> bool:
    if not isinstance(row, dict):
        return False
    fingerprint = row.get("identity_fingerprint")
    matches = row.get("matches")
    return (
        isinstance(row.get("artifact_id"), str)
        and isinstance(fingerprint, str)
        and len(fingerprint) == 64
        and all(char in "0123456789abcdef" for char in fingerprint)
        and isinstance(row.get("identity_assurance"), str)
        and isinstance(matches, list)
        and all(isinstance(match, dict) and _has_text_fields(match) for match in matches)
    )


def _has_text_fields(match: dict[str, object]) -> bool:
    return all(isinstance(match.get(key), str) for key in ("advisory_id", "status", "reason"))


def _parse_verdict(row: object) -> RuntimeAdvisoryVerdict:
    if not isinstance(row, dict):
        raise RuntimeIdentityError("runtime_identity_failed")
    advisory_id = row.get("advisory_id")
    verdict = row.get("verdict")
    if not isinstance(advisory_id, str) or not isinstance(verdict, str) or verdict not in _VERDICTS:
        raise RuntimeIdentityError("runtime_identity_failed")
    reasons, artifact_ids, instance_ids, replacement_ids = (_text_tuple(row.get(key)) for key in _VERDICT_LISTS)
    return RuntimeAdvisoryVerdict(
        advisory_id=advisory_id,
        verdict=cast(AdvisoryVerdict, verdict),
        reasons=reasons,
        affected_artifact_ids=artifact_ids,
        affected_instance_ids=instance_ids,
        replacement_instance_ids=replacement_ids,
    )


def _text_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise RuntimeIdentityError("runtime_identity_failed")
    return tuple(str(item) for item in value)


__all__ = [
    "RUNTIME_IDENTITY_FEATURE",
    "RuntimeAdvisoryVerdict",
    "RuntimeIdentityAssessment",
    "RuntimeIdentityError",
    "assess_runtime_identity",
]
