"""Independent containment steps and private cleanup diagnostics."""

from __future__ import annotations

import traceback
from pathlib import Path
from typing import Any

from ci.native_runtime import probe_installed_pi_output as probe


def cleanup_case_resources(daemon: Any, identity: Any, guard_home: Path, private: Path) -> dict[str, Any]:
    """Attempt both containment steps even when the first one fails."""
    failures: list[Exception] = []
    diagnostics: list[str] = []
    for label, cleanup in (
        ("installed-daemon", lambda: probe._cleanup_installed_daemon(daemon)),
        ("native-resident", lambda: probe._cleanup_native(identity, guard_home)),
    ):
        try:
            cleanup()
        except Exception as exc:
            failures.append(exc)
            diagnostics.append(f"{label}\n{traceback.format_exc()}")
    if failures:
        # Exception messages and paths stay out of public evidence exports.
        result = {"cleanup_ok": False, "cleanup_error": type(failures[0]).__name__}
        try:
            (private / "cleanup-error.txt").write_text("\n".join(diagnostics), encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            result["cleanup_diagnostic_error"] = type(exc).__name__
        return result
    return {"cleanup_ok": True}
