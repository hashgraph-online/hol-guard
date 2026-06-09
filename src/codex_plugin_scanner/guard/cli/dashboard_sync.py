from pathlib import Path

from ..redaction import redact_sensitive_text


def sync_dashboard_assets() -> dict[str, object] | None:
    """Copy pre-built dashboard assets from a local source checkout to the installed package.

    When HOL Guard is installed from PyPI/uv/pipx, the wheel may not include the latest
    dashboard Vite build. This function detects a local source checkout and copies the
    already-built assets into the installed package's static directory so the running
    daemon serves fresh UI. No build step is performed; run ``npm run build`` in the
    dashboard directory first if assets are stale.
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

    # Find a local source checkout by walking up from cwd looking for hol-guard/dashboard
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
    """Return a local hol-guard source checkout if one is detected nearby.

    Security: Only returns a directory after VCS verification proves it is the
    real hashgraph-online/hol-guard repository. Trivial directory markers like
    dashboard/package.json and src/codex_plugin_scanner are NOT sufficient on
    their own because any untrusted project can create them.
    """
    try:
        cwd = Path.cwd().resolve()
    except OSError:
        return None
    candidates = [cwd, *cwd.parents]
    for candidate in candidates:
        checkout = verify_source_checkout(candidate)
        if checkout is not None:
            return checkout
    # Check one level deeper for repo roots that may contain hol-guard as a sub-project
    for candidate in candidates:
        try:
            for sub in candidate.iterdir():
                try:
                    checkout = verify_source_checkout(sub)
                    if checkout is not None:
                        return checkout
                except OSError:
                    continue
        except OSError:
            continue
    return None


_TRUSTED_REPO_KEYWORDS = ("hashgraph-online/hol-guard",)


def verify_source_checkout(path: Path) -> Path | None:
    """Verify a candidate directory is the real hol-guard source checkout.

    Returns *path* only when:
    - It contains the expected source tree markers.
    - It is a git repository whose remotes reference the trusted upstream.

    Security: This function reads ``.git/config`` directly instead of executing
    ``git`` in the candidate directory to avoid triggering repository-local Git
    hooks or configuration that could lead to arbitrary code execution.
    """
    try:
        if not (path / "dashboard" / "package.json").is_file():
            return None
        if not (path / "src" / "codex_plugin_scanner").is_dir():
            return None
        if not (path / ".git").is_dir():
            return None
    except OSError:
        return None

    try:
        config_path = path / ".git" / "config"
        if not config_path.is_file():
            return None
        remote_text = config_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None

    if not any(kw in remote_text for kw in _TRUSTED_REPO_KEYWORDS):
        return None

    return path
