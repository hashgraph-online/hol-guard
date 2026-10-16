"""The Guard extension each live case loads, exactly as an install writes it.

Generated extensions answer each hook through the native runtime's
``pi-hook-bridge`` when the installed runtime advertises it, and through their
own loopback ``fetch`` otherwise. ``observer.ts`` wraps both lanes, so the
transport is left to the wheel under test instead of being pinned here: a case
exercises whichever lane an installed user would get.
"""

from __future__ import annotations

from pathlib import Path

from ci.native_runtime import probe_installed_pi_output as probe


def generate_observed_extension(extension: Path, *, guard_home: Path, home: Path, settings_path: Path) -> None:
    """Write the extension the installer would write for this Guard home."""

    probe._generate_extension(extension, guard_home=guard_home, home=home, settings_path=settings_path)
