"""Bounded startup diagnostics without frame locals, paths, or exception text.

The one-shot watchdog is cancelled before hook measurements. Its creation and
cleanup remain included in the separately reported full fixture startup time.
It neither extends the fixture deadline nor changes the native ACK barrier.
"""

from __future__ import annotations

import re
import sys
import threading
from collections.abc import Callable, Mapping
from pathlib import Path
from types import FrameType

PROGRESS_STAGES = frozenset(
    {
        "construct",
        "construct_workspace",
        "construct_store",
        "construct_daemon",
        "register_workspace",
        "start",
        "fault",
        "serve",
        "cleanup",
    }
)
_STDLIB_STARTUP_LOCATIONS = frozenset(
    {
        ("socket", "getfqdn"),
        ("http.server", "HTTPServer.server_bind"),
        ("socketserver", "TCPServer.server_bind"),
        ("socketserver", "TCPServer.server_activate"),
    }
)


def startup_code_locations(frame: FrameType | None) -> list[dict[str, object]]:
    """Keep eight shipped or exact allowed stdlib locations, never frame data."""
    locations: list[dict[str, object]] = []
    examined = 0
    while frame is not None and len(locations) < 8 and examined < 128:
        module = str(frame.f_globals.get("__name__", ""))
        qualified_name = str(getattr(frame.f_code, "co_qualname", frame.f_code.co_name))
        stdlib_location = (module, qualified_name) in _STDLIB_STARTUP_LOCATIONS
        if (
            stdlib_location
            or module.startswith(("scripts.", "codex_plugin_scanner."))
            or (module == "__main__" and Path(frame.f_code.co_filename).name == "native_slo_daemon_fixture.py")
        ):
            origin = (
                module + "." + qualified_name
                if stdlib_location
                else Path(frame.f_code.co_filename).stem + "." + frame.f_code.co_name
            )
            origin = origin.replace("secret", "sensitive").replace("token", "credential")
            if re.fullmatch(r"[A-Za-z0-9_.]{1,96}", origin):
                locations.append({"origin": origin, "line": frame.f_lineno})
        frame = frame.f_back
        examined += 1
    return locations


class StartupDiagnostic:
    """Emit one startup stack sample only if setup remains blocked for 20 s."""

    def __init__(self, emit: Callable[[Mapping[str, object]], None], *, after_seconds: float = 20.0) -> None:
        self._emit = emit
        self._owner = threading.get_ident()
        self._stage = "construct"
        self._lock = threading.Lock()
        self._active = False
        self._timer = threading.Timer(after_seconds, self._snapshot)
        self._timer.daemon = True

    def __enter__(self) -> StartupDiagnostic:
        self._active = True
        self._timer.start()
        return self

    def progress(self, stage: str) -> None:
        if stage not in PROGRESS_STAGES:
            raise ValueError("daemon fixture invalid progress stage")
        with self._lock:
            self._stage = stage
            self._emit({"state": "progress", "stage": stage})

    def _snapshot(self) -> None:
        with self._lock:
            if self._active:
                locations = startup_code_locations(sys._current_frames().get(self._owner))
                self._emit({"state": "startup_diagnostic", "stage": self._stage, "stack": locations})

    def __exit__(self, *_args: object) -> None:
        with self._lock:
            self._active = False
        self._timer.cancel()
        self._timer.join(timeout=0.1)
