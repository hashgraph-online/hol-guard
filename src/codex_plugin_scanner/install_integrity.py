"""Startup install-integrity self-check.

Detects the silent "stale install shadowing" failure where a long-running
daemon process (launched with system Python) imports an ancient
``codex_plugin_scanner`` from user site-packages or Homebrew global site, while
the user believes they are running the latest ``hol-guard`` from a pipx venv.
The symptom is that the daemon runs months-old code with no new features
(memory decision events, etc.) and nothing surfaces the discrepancy.

The check is non-fatal: it prints a loud warning to stderr when a shadowing
install is detected, so the user sees it in daemon logs and CLI output. It
never raises or blocks, so it cannot break a working install.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _package_root_name() -> str:
    return "codex_plugin_scanner"


def detect_shadowed_install() -> str | None:
    """Return a human-readable warning if a stale install shadows the loaded one.

    Returns ``None`` when the install looks healthy (single source, or the
    loaded package is the newest reachable). Returns a warning string when a
    different ``codex_plugin_scanner`` directory on ``sys.path`` reports a
    newer version than the loaded one, or when multiple package roots are
    reachable.
    """
    try:
        import codex_plugin_scanner as _loaded
        from codex_plugin_scanner.version import __version__ as loaded_version
    except Exception:
        return None

    loaded_path = Path(getattr(_loaded, "__file__", "")).resolve().parent.parent
    package_name = _package_root_name()
    seen_roots: list[tuple[str, str]] = []
    for entry in sys.path:
        if not entry:
            continue
        candidate_root = Path(entry) / package_name
        init_file = candidate_root / "__init__.py"
        if not init_file.is_file():
            continue
        version_file = candidate_root / "version.py"
        version_value = _read_version_file(version_file)
        if version_value:
            seen_roots.append((str(candidate_root.resolve()), version_value))

    # Deduplicate by path (the loaded package will appear once).
    unique_roots: dict[str, str] = {}
    for root_path, version_value in seen_roots:
        unique_roots.setdefault(root_path, version_value)

    if len(unique_roots) <= 1:
        return None

    # Multiple reachable installs. Warn if any non-loaded root reports a newer
    # version than the loaded one, or simply that more than one exists.
    newer_roots = [
        (path, version)
        for path, version in unique_roots.items()
        if _version_tuple(version) > _version_tuple(loaded_version)
    ]
    if not newer_roots:
        # Multiple installs but the loaded one is newest — still note it, but
        # lower urgency.
        other_roots = [f"  - {path} ({version})" for path, version in unique_roots.items() if path != str(loaded_path)]
        if not other_roots:
            return None
        return (
            "hol-guard: multiple codex_plugin_scanner installs detected on sys.path.\n"
            "This can cause long-running daemons to import the wrong copy.\n"
            + "\n".join(other_roots)
            + f"\nLoaded: {loaded_path} ({loaded_version})"
        )

    stale_lines = [f"  - {path} ({version}) is NEWER than the loaded copy" for path, version in newer_roots]
    return (
        "hol-guard WARNING: a newer codex_plugin_scanner install is being shadowed.\n"
        "The currently running process loaded an older copy; features may be missing.\n"
        + "\n".join(stale_lines)
        + f"\nLoaded: {loaded_path} ({loaded_version})\n"
        "Fix: uninstall the stale copy (pip uninstall codex-plugin-scanner) or "
        "restart the process with the Python that has the newer install."
    )


def warn_if_shadowed() -> None:
    """Print a shadowing warning to stderr if one is detected. Never raises."""
    try:
        warning = detect_shadowed_install()
    except Exception:
        return
    if warning:
        print(f"\n{warning}\n", file=sys.stderr)


def _read_version_file(version_file: Path) -> str | None:
    if not version_file.is_file():
        return None
    try:
        spec = importlib.util.spec_from_file_location("_hol_guard_version_probe", version_file)
        if spec is None or spec.loader is None:
            return None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # type: ignore[union-attr]
        value = getattr(module, "__version__", None)
        return value if isinstance(value, str) and value else None
    except Exception:
        return None


def _version_tuple(value: str) -> tuple[int, ...]:
    parts: list[int] = []
    for piece in value.split("."):
        digits = "".join(ch for ch in piece if ch.isdigit())
        if digits:
            parts.append(int(digits))
    return tuple(parts)
