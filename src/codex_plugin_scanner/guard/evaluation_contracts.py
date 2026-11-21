"""Strict, versioned contracts for bounded local evaluation runs.

The contracts describe an evaluation profile and its results.  They do not
execute scenarios or change Guard policy.  JSON Schema provides the stable
wire shape; the native runtime's semantic checks bind paths and endpoints to a
local, temporary test scope.
"""

from __future__ import annotations

import copy
import json
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from jsonschema import Draft202012Validator

EVALUATION_PROFILE_SCHEMA_VERSION = "guard.evaluation-profile.v1"
EVALUATION_RESULT_SCHEMA_VERSION = "guard.evaluation-result.v1"

EVALUATION_STATUSES: frozenset[str] = frozenset({"passed", "failed", "unsupported", "blocked_environment", "not_run"})


class EvaluationContractError(ValueError):
    """A profile or result failed structural or local-scope validation."""


def _load_schema(filename: str) -> dict[str, object]:
    schema_path = Path(__file__).resolve().parent / "schemas" / filename
    try:
        return cast(dict[str, object], json.loads(schema_path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvaluationContractError(f"unable to load evaluation schema {filename}") from exc


def evaluation_profile_schema() -> dict[str, object]:
    """Return a copy of the profile JSON Schema."""

    return copy.deepcopy(_load_schema("evaluation-profile-v1.schema.json"))


def evaluation_result_schema() -> dict[str, object]:
    """Return a copy of the result JSON Schema."""

    return copy.deepcopy(_load_schema("evaluation-result-v1.schema.json"))


def _mapping(value: object, name: str) -> dict[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise EvaluationContractError(f"{name} must be an object")
    return dict(value)


def _schema_validate(payload: object, schema: dict[str, object], name: str) -> dict[str, object]:
    candidate = _mapping(payload, name)
    validator = Draft202012Validator(schema)
    error = next(iter(validator.iter_errors(cast(Any, candidate))), None)
    if error is not None:
        # jsonschema messages and paths may contain caller-supplied values.
        raise EvaluationContractError(f"{name} is invalid (schema rule: {error.validator})") from None
    return candidate


# The resident takes requests up to 4 MiB; keep headroom for the envelope.
_MAX_CHECK_BYTES = 3 * 1024 * 1024
# Host checks resolve every witness path, so they get a wider budget.
_HOST_CHECK_TIMEOUT_SECONDS = 30.0


def _without_notes(result: dict[str, object]) -> dict[str, object]:
    """Witness notes are free text the runtime never reads; leave them out of the request."""
    cases = result.get("cases")
    if not isinstance(cases, list):
        return result
    stripped: list[object] = []
    for case in cases:
        witness = case.get("witness") if isinstance(case, dict) else None
        if isinstance(witness, dict) and "note" in witness:
            case = {**case, "witness": {key: value for key, value in witness.items() if key != "note"}}
        stripped.append(case)
    return {**result, "cases": stripped}


def _native_check(request: dict[str, object]) -> None:
    """Paths, endpoints, timestamps and the profile binding (``evaluation_contract.rs``)."""
    from .native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    request["temp_root"] = tempfile.gettempdir()
    try:
        # The runtime parses UTF-8 JSON, so an unpaired surrogate is invalid text, not an outage.
        _ = json.dumps(request, ensure_ascii=False).encode("utf-8")
    except UnicodeEncodeError:
        raise EvaluationContractError("evaluation record contains invalid text") from None
    if len(json.dumps(request, separators=(",", ":")).encode()) > _MAX_CHECK_BYTES:
        raise EvaluationContractError("evaluation record is too large to check")
    timeout = None if request.get("portable") else _HOST_CHECK_TIMEOUT_SECONDS
    try:
        answer = native_runner_authority("evaluation_contract", request, timeout_seconds=timeout)
    except NativeRunnerAuthorityError:
        raise EvaluationContractError("evaluation record could not be checked") from None
    error = answer.get("error")
    if isinstance(error, str):
        raise EvaluationContractError(error)
    if answer != {"ok": True}:
        raise EvaluationContractError("evaluation record could not be checked")


def validate_evaluation_profile(payload: object, *, portable: bool = False) -> None:
    """Validate a profile; portable mode checks recorded paths without host filesystem access."""

    profile = _schema_validate(payload, evaluation_profile_schema(), "evaluation profile")
    _native_check({"op": "profile", "profile": profile, "portable": portable})


def validate_evaluation_result(payload: object, profile: object | None = None, *, portable: bool = False) -> None:
    """Validate a result and, when supplied, bind it to its profile."""

    result = _schema_validate(payload, evaluation_result_schema(), "evaluation result")
    profile_mapping = None
    if profile is not None:
        profile_mapping = _mapping(profile.data if isinstance(profile, EvaluationProfile) else profile, "profile")
        _ = _schema_validate(profile_mapping, evaluation_profile_schema(), "evaluation profile")
    _native_check({"op": "result", "result": _without_notes(result), "profile": profile_mapping, "portable": portable})


@dataclass(frozen=True, slots=True)
class EvaluationProfile:
    """Validated profile payload retained for deterministic round-tripping."""

    data: dict[str, object]

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> EvaluationProfile:
        validate_evaluation_profile(payload)
        return cls(copy.deepcopy(dict(payload)))

    def to_dict(self) -> dict[str, object]:
        return copy.deepcopy(self.data)


@dataclass(frozen=True, slots=True)
class EvaluationResult:
    """Validated result payload retained for deterministic round-tripping."""

    data: dict[str, object]

    @classmethod
    def from_dict(
        cls,
        payload: Mapping[str, object],
        *,
        profile: EvaluationProfile | Mapping[str, object] | None = None,
    ) -> EvaluationResult:
        validate_evaluation_result(payload, profile)
        return cls(copy.deepcopy(dict(payload)))

    def to_dict(self) -> dict[str, object]:
        return copy.deepcopy(self.data)


__all__ = [
    "EVALUATION_PROFILE_SCHEMA_VERSION",
    "EVALUATION_RESULT_SCHEMA_VERSION",
    "EVALUATION_STATUSES",
    "EvaluationContractError",
    "EvaluationProfile",
    "EvaluationResult",
    "evaluation_profile_schema",
    "evaluation_result_schema",
    "validate_evaluation_profile",
    "validate_evaluation_result",
]
