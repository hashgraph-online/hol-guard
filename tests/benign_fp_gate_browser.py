"""Browser driver rows for the benign false-positive gate's ``mcp_cases``.

The gate replays browser calls through the same native stdio relay as its other MCP rows, against
the Gauntlet's browser driver stand-in (``ci/gauntlet/browser_driver_server.py``): the reference
driver under its real server name with its recorded tool list, and a driver no profile matches.
Nothing opens a browser or a socket.

Browser rows add two optional fields, each a closed list (PRD 8.2):

- ``state`` seeds the Guard home before the call. Only ``none`` (nothing seeded) is wired so far;
  every other preset names the feature that wires it and fails the row until it lands.
- ``page`` names the scripted page the driver starts on.
"""

from __future__ import annotations

import sys
from pathlib import Path

from ci.gauntlet.browser_fixtures import (
    PAGE_NAMES,
    REFERENCE_DRIVER,
    UNPROFILED_DRIVER,
    install_server,
)

BROWSER_SERVERS = (REFERENCE_DRIVER, UNPROFILED_DRIVER)

# PRD 8.2 state presets, in the order the PRD lists them.
BROWSER_STATES = (
    "none",
    "site-grant",
    "session-site-grant",
    "saved-exact",
    "saved-verb-site",
    "site-blocked",
    "pending-same-call",
    "shared-profile",
    "provider-ok",
    "provider-unknown",
    "provider-down",
    "provider-caution",
    "provider-caution-verified",
    "provider-danger",
    "provider-danger-enforced",
    "two-providers",
)
WIRED_STATES = frozenset({"none"})


def validate_browser_fields(case_id: str, server: str, state: str, page: str | None) -> None:
    """Refuse a row whose ``state`` or ``page`` is not on its closed list."""
    if state not in BROWSER_STATES:
        raise ValueError(f"{case_id}: unknown state preset {state!r}")
    if page is not None and page not in PAGE_NAMES:
        raise ValueError(f"{case_id}: unknown page {page!r}")
    if (state != "none" or page is not None) and server not in BROWSER_SERVERS:
        raise ValueError(f"{case_id}: state and page apply to browser driver rows only")


def unwired_state(state: str) -> str | None:
    """Why a valid preset cannot seed yet, or None when it can."""
    if state in WIRED_STATES:
        return None
    return f"state preset {state!r} is not wired into the gate yet"


def _root(home: Path) -> Path:
    return home / ".local" / "lib" / "browser-fixture"


def write_browser_servers(home: Path) -> None:
    """Install the driver stand-in and both tool lists in the fixture home."""
    install_server(home)


def browser_server_command(home: Path, server: str, page: str | None) -> list[str]:
    """The launch a harness config writes for one browser stand-in, optionally on a start page."""
    root = _root(home)
    command = [
        sys.executable,
        "-u",
        str(root / "server.py"),
        str(root / f"{server}.tools.json"),
        str(home / ".local" / "state" / "browser-fixture" / "browser-calls.jsonl"),
        server,
    ]
    return [*command, page] if page is not None else command
