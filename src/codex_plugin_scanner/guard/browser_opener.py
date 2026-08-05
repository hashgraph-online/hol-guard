"""Open browser URLs without leaking Linux launcher failures to the terminal."""

from __future__ import annotations

import os
import platform
import subprocess
import webbrowser
from collections.abc import Mapping


def open_browser_url(url: str) -> bool:
    """Open *url* and report whether a browser launch was accepted.

    Linux environments without a graphical session cannot open a local dashboard.
    Avoid invoking a browser there, where Chromium sandbox diagnostics would otherwise
    be written to the caller's terminal.
    """

    if platform.system() == "Linux":
        return _open_linux_browser_url(url)
    try:
        return bool(webbrowser.open(url))
    except Exception:
        return False


def _open_linux_browser_url(url: str, *, environ: Mapping[str, str] | None = None) -> bool:
    if not _has_linux_graphical_session(environ or os.environ):
        return False
    try:
        process = subprocess.Popen(
            ["xdg-open", url],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError:
        return False
    try:
        return process.wait(timeout=0.2) == 0
    except subprocess.TimeoutExpired:
        return True


def _has_linux_graphical_session(environ: Mapping[str, str]) -> bool:
    return bool(environ.get("DISPLAY") or environ.get("WAYLAND_DISPLAY"))
