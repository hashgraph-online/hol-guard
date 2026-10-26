"""Stage this checkout's command packs for uninstalled native authoring."""

from __future__ import annotations

import atexit
import hashlib
import json
import shutil
import sys
import tempfile
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]

# Compiling every command pack takes seconds, and each authoring request stages
# them again into its own cache. The checkout does not change during a run, so
# one staging per compiler binary is copied into each request's directory.
# Authoring runs a fresh private copy of the compiler for every request, so the
# cache is keyed by the compiler's bytes rather than its path.
_staged: dict[str, Path] = {}


def _checkout_packs(compiler: Path) -> Path:
    digest = hashlib.sha256()
    with compiler.open("rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    key = digest.hexdigest()
    staged = _staged.get(key)
    if staged is None:
        staged = Path(tempfile.mkdtemp(prefix="hol-guard-checkout-packs-")).resolve() / "packs"
        atexit.register(shutil.rmtree, staged.parent, True)
        scripts = str(REPOSITORY / "scripts")
        sys.path.insert(0, scripts)
        try:
            import build_native_command_packs as packs

            packs.stage(compiler, staged, source_root=REPOSITORY)
        finally:
            sys.path.remove(scripts)
        _staged[key] = staged
    return staged


def development_staging(compiler: Path, directory: Path) -> dict[str, object]:
    """Stage this checkout's command packs for an uninstalled authoring request."""
    shutil.copytree(_checkout_packs(compiler), directory, dirs_exist_ok=True)
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
