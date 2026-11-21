"""Credential-free process stage markers for parent-controlled operations."""

from __future__ import annotations

import json
import sys
import time
from contextlib import suppress


class RuntimeStageTimings:
    """Diagnostic evidence only; callers supply fixed names, never private data."""

    def __init__(self, started: float) -> None:
        self.started = started
        self.stage_started = started
        self.stage: str | None = None

    def enter(self, stage: str) -> None:
        self.finish()
        self.stage_started = time.monotonic()
        self.stage = stage
        self._emit("started")

    def _emit(self, phase: str) -> None:
        if self.stage is None:
            return
        now = time.monotonic()
        # Diagnostic loss must preserve the operation's first cause.
        with suppress(OSError, ValueError):
            print(
                "guard_runtime_stage "
                + json.dumps(
                    {
                        "stage": self.stage,
                        "phase": phase,
                        "elapsed_ms": max(0, int((now - self.started) * 1000)),
                        "duration_ms": 0 if phase == "started" else max(0, int((now - self.stage_started) * 1000)),
                    },
                    sort_keys=True,
                ),
                file=sys.stderr,
                flush=True,
            )

    def finish(self) -> None:
        self._emit("finished")
        self.stage = None
