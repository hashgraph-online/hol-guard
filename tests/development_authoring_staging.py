"""Stage this checkout's command packs for uninstalled native authoring."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]


def development_staging(compiler: Path, directory: Path) -> dict[str, object]:
    """Stage this checkout's command packs for an uninstalled authoring request."""
    scripts = str(REPOSITORY / "scripts")
    sys.path.insert(0, scripts)
    try:
        import build_native_command_packs as packs

        packs.stage(compiler, directory, source_root=REPOSITORY)
    finally:
        sys.path.remove(scripts)
    manifest = (directory / "release.json").read_bytes()
    return {"root": json.loads(manifest), "source_context": hashlib.sha256(manifest).hexdigest()}


def register_checkout_staging() -> None:
    """Let a process running against this checkout author without an installed bundle.

    The runtime refuses to compile an uninstalled bundle unless a caller that
    owns a checkout stages it. Pytest registers it through conftest; a test that
    spawns its own interpreter registers it before invoking the CLI.
    """
    from codex_plugin_scanner.guard.extension_builder.bundle_baseline import register_development_staging

    register_development_staging(development_staging)
