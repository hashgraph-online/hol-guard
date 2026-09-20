"""Argument handling for the private installed SLO daemon fixture."""

from __future__ import annotations

import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Protocol

from scripts.native_slo_failure import failure_evidence


class _Serve(Protocol):
    def __call__(
        self, runtime: Path, setup: str, policy: str, workspace_count: int | None, *, native_phases: bool
    ) -> int: ...


def main(serve: _Serve, emit: Callable[[Mapping[str, object]], None]) -> int:
    try:
        arguments = sys.argv[1:]
        native_phases = bool(arguments and arguments[-1] == "--native-phases")
        if native_phases:
            arguments.pop()
        if len(arguments) not in {4, 5} or arguments[0] != "--serve":
            raise ValueError("private daemon fixture invocation required")
        return serve(
            Path(arguments[1]).resolve(strict=True),
            arguments[2],
            arguments[3],
            int(arguments[4]) if len(arguments) == 5 else None,
            native_phases=native_phases,
        )
    except Exception as error:
        emit({"error": "fixture_failed", "detail": failure_evidence(error)})
        return 1
