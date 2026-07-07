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

Version files are read via AST parsing only — never executed — so a rogue
``version.py`` on ``sys.path`` cannot run arbitrary code during the check.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

PACKAGE_NAME = "codex_plugin_scanner"


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

    loaded_package_dir = Path(getattr(_loaded, "__file__", "")).resolve().parent
    seen_roots: dict[str, str] = {}
    for entry in sys.path:
        if not entry:
            continue
        candidate_root = Path(entry) / PACKAGE_NAME
        if not (candidate_root / "__init__.py").is_file():
            continue
        version_value = _read_version_via_ast(candidate_root / "version.py")
        if version_value:
            seen_roots[str(candidate_root.resolve())] = version_value

    if len(seen_roots) <= 1:
        return None

    loaded_key = str(loaded_package_dir)
    loaded_tuple = _parse_version(loaded_version)

    newer_roots = [
        (path, version)
        for path, version in seen_roots.items()
        if path != loaded_key and _parse_version(version) > loaded_tuple
    ]
    other_roots = [f"  - {path} ({version})" for path, version in seen_roots.items() if path != loaded_key]
    if not other_roots:
        return None

    if not newer_roots:
        return (
            "hol-guard: multiple codex_plugin_scanner installs detected on sys.path.\n"
            "This can cause long-running daemons to import the wrong copy.\n"
            + "\n".join(other_roots)
            + f"\nLoaded: {loaded_package_dir} ({loaded_version})"
        )

    stale_lines = [f"  - {path} ({version}) is NEWER than the loaded copy" for path, version in newer_roots]
    return (
        "hol-guard WARNING: a newer codex_plugin_scanner install is being shadowed.\n"
        "The currently running process loaded an older copy; features may be missing.\n"
        + "\n".join(stale_lines)
        + f"\nLoaded: {loaded_package_dir} ({loaded_version})\n"
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


def _read_version_via_ast(version_file: Path) -> str | None:
    """Read ``__version__`` from a version.py via AST parsing (no execution)."""
    if not version_file.is_file():
        return None
    try:
        tree = ast.parse(version_file.read_text(encoding="utf-8"))
    except (OSError, SyntaxError):
        return None
    for node in ast.walk(tree):
        # Support both plain assignments (__version__ = "...") and annotated
        # assignments (__version__: str = "...").
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            assign_targets = [node.target]
            assign_value = node.value
        elif isinstance(node, ast.Assign):
            assign_targets = node.targets
            assign_value = node.value
        else:
            continue
        if not isinstance(assign_value, ast.Constant) or not isinstance(assign_value.value, str):
            continue
        for target in assign_targets:
            if isinstance(target, ast.Name) and target.id == "__version__":
                return assign_value.value
    return None


_RELEASE_SEGMENT_RE = re.compile(r"\d+(?:\.\d+)*")
_PRE_RELEASE_RE = re.compile(r"(a|b|rc|alpha|beta|pre|preview)(\d*)", re.IGNORECASE)
_POST_RELEASE_RE = re.compile(r"\.(post|rev|r)(\d*)", re.IGNORECASE)
_DEV_RELEASE_RE = re.compile(r"\.?(dev)(\d*)", re.IGNORECASE)

# Sort sentinels for PEP 440 ordering: dev < pre < final < post.
_DEV_SENTINEL = -3
_PRE_SENTINEL = -2
_FINAL_SENTINEL = 0
_POST_SENTINEL = 1


def _parse_version(value: str) -> tuple[int, ...]:
    """Parse a version string into a comparable tuple.

    Numeric release segments are compared as integers, with PEP 440 suffix
    ordering: dev < pre-release (a/b/rc) < final < post-release.
    """
    match = _RELEASE_SEGMENT_RE.search(value)
    if not match:
        return (0,)
    release = tuple(int(part) for part in match.group(0).split("."))
    suffix = value[match.end() :]
    pre_match = _PRE_RELEASE_RE.search(suffix)
    post_match = _POST_RELEASE_RE.search(suffix)
    dev_match = _DEV_RELEASE_RE.search(suffix)
    if dev_match:
        dev_number = int(dev_match.group(2)) if dev_match.group(2) else 0
        return (*release, _DEV_SENTINEL, dev_number)
    if pre_match:
        pre_number = int(pre_match.group(2)) if pre_match.group(2) else 0
        # Rank the pre-release type so a < b < rc (PEP 440).
        pre_type_rank = _pre_release_type_rank(pre_match.group(1))
        return (*release, _PRE_SENTINEL, pre_type_rank, pre_number)
    if post_match:
        post_number = int(post_match.group(2)) if post_match.group(2) else 0
        return (*release, _POST_SENTINEL, post_number)
    return (*release, _FINAL_SENTINEL)


_PRE_RELEASE_TYPE_RANK = {
    "a": 0,
    "alpha": 0,
    "b": 1,
    "beta": 1,
    "pre": 2,
    "preview": 2,
    "rc": 2,
}


def _pre_release_type_rank(label: str) -> int:
    return _PRE_RELEASE_TYPE_RANK.get(label.lower(), 0)
