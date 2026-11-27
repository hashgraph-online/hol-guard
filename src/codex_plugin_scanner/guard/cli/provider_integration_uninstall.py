"""Uninstall glue: the native runtime forgets every provider integration on this device."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from .update_retirement import resident_stop_executable

PROVIDER_PURGE_NOTE = (
    "Could not delete provider integration keys. Disconnect each provider in the dashboard, or run the uninstall again."
)


def forget_provider_integrations(guard_home: Path) -> dict[str, object] | None:
    """Delete every provider key and provider row under ``guard_home``.

    Uninstall calls this while the package, and so the runtime, is still installed. Returns the
    runtime's counts, or ``None`` when the purge could not run or did not finish.
    """

    if not guard_home.is_dir():
        return {"keys_deleted": 0, "providers_forgotten": 0}
    command = [str(resident_stop_executable()), "forget-provider-integrations", "--guard-home", str(guard_home)]
    try:
        result = subprocess.run(command, capture_output=True, check=False, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    try:
        purge = json.loads(result.stdout)
    except ValueError:
        return None
    return purge if isinstance(purge, dict) else None
