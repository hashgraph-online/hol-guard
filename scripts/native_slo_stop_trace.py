"""Explicit diagnostic observation of unchanged strict Stop helper calls.

No caller uses this observer by default. Keep raw stderr and process identities
in memory only; persist fixed phase labels and aggregate resource changes.
"""

from __future__ import annotations

import os
import re
import subprocess
import time
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from unittest.mock import patch

_PHASE = re.compile(rb"native_resident_phase phase=([a-z_]+) status=(start|ok|error) elapsed_ms=([0-9]+)")
_LABELS = {"client_connect", "client_authenticate", "client_request_write", "client_response_read"}
_ERRORS = {"native_resident_stop_timeout", "native_resident_stop_unavailable", "native_resident_stop_ack_invalid"}


class StopTrace:
    def __init__(self, runtime: Path, sampler, *, case: Callable[[], str] | None = None) -> None:
        self.runtime, self.sampler = str(runtime), sampler
        self.case = "setup"
        self._case = case
        self.events: list[dict] = []
        self._original = subprocess.run

    def __enter__(self):
        self._patch = patch.object(subprocess, "run", self.run)
        self._patch.start()
        return self

    def __exit__(self, *_args):
        self._patch.stop()

    def _snapshot(self):
        try:
            return self.sampler.sample_with_identities()
        except Exception as error:
            return {"sampling_error_type": type(error).__name__}, {}

    def run(self, *args, **kwargs):
        command = args[0] if args else kwargs.get("args")
        if not (
            isinstance(command, (list, tuple))
            and len(command) >= 2
            and str(command[0]) == self.runtime
            and command[1] == "resident-stop"
        ):
            return self._original(*args, **kwargs)
        if len(self.events) >= 32:
            raise RuntimeError("strict Stop trace event budget exceeded")
        before, identities = self._snapshot()
        row = {
            "case": self._case() if self._case is not None else self.case,
            "declared_timeout_seconds": kwargs.get("timeout"),
            "before": before,
        }
        self.events.append(row)
        # Diagnostic helper stderr only; no resident/SDK setting is changed.
        options = dict(kwargs)
        options["env"] = dict(options.get("env") or os.environ, HOL_GUARD_NATIVE_DIAGNOSTIC="1")
        diagnostic = b""
        started = time.perf_counter()
        try:
            result = self._original(*args, **options)
            row.update(process_outcome="exited", returncode=result.returncode)
            diagnostic = result.stderr or b""
            return result
        except subprocess.TimeoutExpired as error:
            row["process_outcome"] = "timed_out"
            diagnostic = error.stderr or b""
            raise
        except OSError as error:
            row.update(process_outcome="launch_failed", error_type=type(error).__name__)
            raise
        finally:
            row["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 3)
            after, current = self._snapshot()
            row["after"] = after
            row["new_counts"] = dict(Counter(kind for identity, kind in current.items() if identity not in identities))
            row["gone_counts"] = dict(Counter(kind for identity, kind in identities.items() if identity not in current))
            if isinstance(diagnostic, str):
                diagnostic = diagnostic.encode()
            row["stderr_within_bound"] = len(diagnostic) <= 64 * 1024
            phases, errors = [], []
            if row["stderr_within_bound"]:
                for line in diagnostic.splitlines():
                    match = _PHASE.fullmatch(line)
                    if match and match[1].decode() in _LABELS and len(phases) < 32:
                        phases.append(
                            {"phase": match[1].decode(), "status": match[2].decode(), "elapsed_ms": int(match[3])}
                        )
                    elif line.decode(errors="replace") in _ERRORS:
                        errors.append(line.decode())
            row["phases"], row["finite_errors"] = phases, errors[:4]
