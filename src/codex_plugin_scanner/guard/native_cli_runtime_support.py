"""Bound resident CLI input and server identity projection; no local oracle."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .native_runner_authority import native_runner_authority


def cli_runtime_support(operation: str, params: Mapping[str, Any], *, guard_home: Path | None = None) -> Any:
    payload = native_runner_authority(
        "cli_runtime_support", {"operation": operation, "params": dict(params)}, guard_home
    )
    if set(payload) != {"result"}:
        raise ValueError("native_cli_runtime_support_result_invalid")
    return payload["result"]
