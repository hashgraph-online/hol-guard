"""Best-effort fixture recovery after an already failed strict Stop check.

This is outside every measured native interval. It cannot change the strict
diagnostic or qualify that check. Rust still owns resident containment.
"""

from __future__ import annotations

import time
from pathlib import Path

from codex_plugin_scanner.guard.native_resident_client import close_native_residents


def recover_failed_stop(guard_home: Path) -> dict[str, object]:
    started = time.monotonic()
    result: dict[str, object] = {"attempted": True, "contained": False}
    try:
        result["contained"] = close_native_residents(guard_home, deadline_monotonic=started + 10.0) is True
    except Exception as error:
        # Never retain process output, state contents, credentials or paths.
        result["error_type"] = type(error).__name__
    result["seconds"] = round(time.monotonic() - started, 3)
    return result
