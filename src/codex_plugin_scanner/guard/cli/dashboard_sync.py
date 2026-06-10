from pathlib import Path

from ..redaction import redact_sensitive_text

_DASHBOARD_SYNC_SOURCE_ENV = "HOL_GUARD_DASHBOARD_SYNC_SOURCE"


def sync_dashboard_assets() -> dict[str, object] | None:
    """Copy pre-built dashboard assets from an explicitly configured source checkout.

    When HOL Guard is installed from PyPI/uv/pipx, the wheel may not include a local
    dashboard Vite build that a developer wants to test. This function only uses a
    source checkout when the operator explicitly points to one with
    ``HOL_GUARD_DASHBOARD_SYNC_SOURCE``. It intentionally does not discover sources
    from the current working directory: update commands can be run from untrusted
    projects, and copying executable dashboard assets from an implicit checkout would
    let those projects poison the installed local approval-center UI.
    """
    import importlib.util
    import shutil

    # Find the installed package's static directory
    spec = importlib.util.find_spec("codex_plugin_scanner.guard.daemon.server")
    if spec is None or spec.origin is None:
        return None
    installed_static = Path(spec.origin).with_name("static")
    try:
        if not installed_static.is_dir():
            return None
    except OSError:
        return None

    try:
        source_checkout = find_source_checkout()
    except OSError:
        return {"source_checkout_found": False, "installed_static": str(installed_static)}
    if source_checkout is None:
        return {"source_checkout_found": False, "installed_static": str(installed_static)}

    try:
        dashboard_dir = source_checkout / "dashboard"
        source_static = dashboard_dir / "src" / "codex_plugin_scanner" / "guard" / "daemon" / "static"
        # Fallback: if the repo builds into src/codex_plugin_scanner/guard/daemon/static
        if not source_static.is_dir():
            source_static = source_checkout / "src" / "codex_plugin_scanner" / "guard" / "daemon" / "static"
        if not source_static.is_dir():
            return {
                "source_checkout_found": True,
                "source_checkout": str(source_checkout),
                "dashboard_dir_found": False,
                "notes": [
                    "Source checkout found but no built dashboard assets. "
                    "Run `npm run build` in the dashboard directory.",
                ],
            }
    except OSError as error:
        return {
            "source_checkout_found": True,
            "source_checkout": str(source_checkout),
            "copied": False,
            "error": redact_sensitive_text(str(error)),
            "notes": ["Dashboard asset sync failed due to file system error."],
        }

    # Compare source vs installed to decide if copy is needed
    source_index = source_static / "index.html"
    installed_index = installed_static / "index.html"
    needs_copy = True
    try:
        if installed_index.is_file() and source_index.is_file():
            installed_mtime = installed_index.stat().st_mtime
            source_mtime = source_index.stat().st_mtime
            needs_copy = source_mtime > installed_mtime
    except OSError:
        needs_copy = True

    if not needs_copy:
        return {
            "source_checkout_found": True,
            "source_checkout": str(source_checkout),
            "copied": False,
            "reason": "installed assets are already up to date",
        }

    # Copy all files from source static to installed static
    copied_count = 0
    try:
        for src_file in source_static.rglob("*"):
            if not src_file.is_file():
                continue
            relative = src_file.relative_to(source_static)
            dest = installed_static / relative
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src_file, dest)
            copied_count += 1
    except OSError as error:
        return {
            "source_checkout_found": True,
            "source_checkout": str(source_checkout),
            "copied": False,
            "error": redact_sensitive_text(str(error)),
            "notes": ["Dashboard asset sync failed. The daemon may serve stale UI."],
        }

    return {
        "source_checkout_found": True,
        "source_checkout": str(source_checkout),
        "installed_static": str(installed_static),
        "copied": True,
        "copied_files": copied_count,
        "notes": [f"Synced {copied_count} dashboard asset files to the installed package."],
    }


def find_source_checkout() -> Path | None:
    """Return an explicitly configured hol-guard source checkout, if any.

    The sync source must be supplied with ``HOL_GUARD_DASHBOARD_SYNC_SOURCE``.
    Earlier versions walked up from the current working directory and inspected
    nearby git repositories, but update commands commonly run inside arbitrary
    workspaces. CWD-based discovery turns a spoofable local repository into a
    source of executable dashboard assets, so it is deliberately disabled.
    """
    import os

    source = os.environ.get(_DASHBOARD_SYNC_SOURCE_ENV)
    if source is None or not source.strip():
        return None
    try:
        path = Path(source).expanduser().resolve()
    except OSError:
        return None
    return verify_source_checkout(path)


def verify_source_checkout(path: Path) -> Path | None:
    """Verify a user-selected directory has the expected hol-guard source shape.

    This is a sanity check for the explicit sync path, not a trust decision for
    ambient directories. It intentionally avoids reading ``.git/config`` because
    repository metadata is attacker-controlled and cannot prove that uncommitted
    dashboard build outputs are safe to install.
    """
    try:
        if not (path / "dashboard" / "package.json").is_file():
            return None
        if not (path / "src" / "codex_plugin_scanner").is_dir():
            return None
    except OSError:
        return None
    return path
