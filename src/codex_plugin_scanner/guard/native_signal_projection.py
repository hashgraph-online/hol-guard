"""Bound transport for native persistence projections."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any


class NativeSignalProjectionError(ValueError):
    """The native owner returned an incomplete projection."""


class NativeSignalProjectionUnavailableError(RuntimeError):
    """Projection transport failed independently of persisted decision validity."""


def _request(kind: str, args: Mapping[str, object], *, guard_home: Path | None = None) -> dict[str, Any]:
    from .native_runner_authority import (
        NativeRunnerAuthorityError,
        NativeRunnerAuthorityRefusalError,
        native_runner_authority,
    )

    try:
        return native_runner_authority(kind, args, guard_home=guard_home)
    except NativeRunnerAuthorityRefusalError as error:
        raise NativeSignalProjectionError(str(error)) from error
    except NativeRunnerAuthorityError as error:
        raise NativeSignalProjectionUnavailableError(str(error)) from error


def signal_projection(kind: str, args: Mapping[str, object], *, guard_home: Path | None = None) -> Any:
    result = _request(kind, args, guard_home=guard_home)
    if (
        result.get("status") == "error"
        and result.get("error_type") == "ValueError"
        and isinstance(result.get("message"), str)
    ):
        raise ValueError(result["message"])
    value = result.get("value")
    inputs = args.get("rows")
    valid = (
        kind == "projection_surfaces_batch"
        and result.get("status") == "ok"
        and isinstance(value, list)
        and isinstance(inputs, list)
        and len(value) == len(inputs)
    )
    keys = {"contract_error", "policy_action", "decision_v2_json", "action_envelope_json"}
    for row in value if isinstance(value, list) else [value]:
        if not isinstance(row, dict) or set(row) != keys or not isinstance(row.get("policy_action"), str):
            raise NativeSignalProjectionError("native_signal_projection_result_invalid")
        valid = valid and (row["contract_error"] is None or isinstance(row["contract_error"], str))
        valid = valid and isinstance(row.get("decision_v2_json"), dict)
        valid = valid and (row.get("action_envelope_json") is None or isinstance(row["action_envelope_json"], dict))
    if not valid:
        raise NativeSignalProjectionError("native_signal_projection_result_invalid")
    return value
