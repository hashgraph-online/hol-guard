"""Browser driver rows for the benign false-positive gate's ``mcp_cases``.

The gate replays browser calls through the same native stdio relay as its other MCP rows, against
the Gauntlet's browser driver stand-in (``ci/gauntlet/browser_driver_server.py``): the reference
driver under its real server name with its recorded tool list, and a driver no profile matches.
Nothing opens a browser or a socket.

Browser rows add two optional fields, each a closed list (PRD 8.2):

- ``state`` seeds the Guard home before the call. ``none`` seeds nothing; ``pending-same-call``
  makes the same call once first and leaves its review unanswered; ``site-grant`` navigates to
  another page of the row's origin first and answers that review with a one-hour ``site`` grant, as
  the approval card would. Every other preset names the feature that wires it and fails the row
  until it lands.
- ``page`` names the scripted page the driver starts on. It reaches the driver through a
  ``start-page`` file next to the call journal, not through argv, so every row relays the same
  connector identity the harness config declares.
"""

from __future__ import annotations

import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from ci.gauntlet.approval_rows import await_rows
from ci.gauntlet.browser_cases import BROWSER_FIXTURES
from ci.gauntlet.browser_driver_server import START_PAGE_FILE
from ci.gauntlet.browser_fixtures import (
    PAGE_NAMES,
    REFERENCE_DRIVER,
    UNPROFILED_DRIVER,
    install_server,
)

BROWSER_SERVERS = (REFERENCE_DRIVER, UNPROFILED_DRIVER)

# PRD 8.2 state presets, shared with the Gauntlet's ``browser_fixture`` field.
BROWSER_STATES = BROWSER_FIXTURES
# R-QUIET-1: the gate makes the same call once before the measured call and leaves it unanswered.
PENDING_SAME_CALL = "pending-same-call"
# BP-T065: an earlier call on the same site was approved with a site grant.
SITE_GRANT = "site-grant"
SEEDED_STATES = frozenset({PENDING_SAME_CALL, SITE_GRANT})
WIRED_STATES = frozenset({"none", *SEEDED_STATES})
# The page of the row's origin the ``site-grant`` seed navigates to.
SITE_GRANT_SEED_PATH = "/guide/getting-started"


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


def _journal(home: Path) -> Path:
    return home / ".local" / "state" / "browser-fixture" / "browser-calls.jsonl"


def browser_server_command(home: Path, server: str) -> list[str]:
    """The launch a harness config writes for one browser stand-in; the start page is not part of it."""
    root = _root(home)
    command = [
        sys.executable,
        "-u",
        str(root / "server.py"),
        str(root / f"{server}.tools.json"),
        str(_journal(home)),
        server,
    ]
    # The reference driver runs in an isolated profile, the shape the loopback quiet set (D10) needs.
    return [*command, "--isolated"] if server == REFERENCE_DRIVER else command


@contextmanager
def start_page(home: Path, page: str | None) -> Iterator[None]:
    """Start every driver launched inside the block on ``page``, or on no page, then clear it."""
    marker = _journal(home).with_name(START_PAGE_FILE)
    marker.parent.mkdir(parents=True, exist_ok=True)
    if page is None:
        marker.unlink(missing_ok=True)
    else:
        marker.write_text(page, encoding="utf-8")
    try:
        yield
    finally:
        marker.unlink(missing_ok=True)


def seed_case(case: Any) -> Any:
    """The call a seeded row makes first: the same call, or for ``site-grant`` the seed navigation."""
    if case.state != SITE_GRANT:
        return case
    url = urlsplit(str(case.arguments.get("url") or ""))
    if not url.scheme or not url.netloc or url.path == SITE_GRANT_SEED_PATH:
        raise ValueError(f"{case.case_id}: a site-grant row navigates to another page of one origin")
    seed_url = urlunsplit((url.scheme, url.netloc, SITE_GRANT_SEED_PATH, "", ""))
    return replace(case, arguments={**case.arguments, "url": seed_url})


def row_counts(store: Any) -> dict[str, int]:
    """Each approval row's id and how many calls it records."""
    return {
        str(row.get("request_id")): int(row.get("dedupe_count") or 1)
        for row in store.list_approval_requests(status=None, limit=500)
        if isinstance(row, dict) and row.get("request_id")
    }


def grant_site(store: Any, known: set[str]) -> None:
    """Answer the one review the seed call queued with a one-hour ``site`` grant."""
    from codex_plugin_scanner.guard.approvals import apply_approval_resolution

    pending = [
        str(row["request_id"])
        for row in store.list_approval_requests(status="pending", limit=500)
        if isinstance(row, dict) and row.get("request_id") and str(row["request_id"]) not in known
    ]
    if len(pending) != 1:
        raise RuntimeError(f"a site-grant seed must queue one review, got {len(pending)}")
    apply_approval_resolution(
        store=store,
        request_id=pending[0],
        action="allow",
        scope="artifact",
        workspace=None,
        reason="benign gate site grant",
        mcp_grant_target="site",
        mcp_grant_duration="1h",
    )


def seed_call(
    case: Any, store: Any, before: dict[str, int], decide: Callable[[Any], dict[str, Any]]
) -> tuple[dict[str, Any] | None, dict[str, int]]:
    """Make a seeded row's first call and settle it.

    ``pending-same-call`` leaves the review unanswered, so the measured call is a retry;
    ``site-grant`` answers it with a site grant. Returns the seed's answer when the relay never
    decided it, and the row counts the measured call's rows are compared with.
    """
    if case.state not in SEEDED_STATES:
        return None, before
    seed = decide(seed_case(case))
    if "relay_defer" in seed:
        return seed, before
    await_rows(store, set(before), waiting="error" in seed, changed_from=before)
    if case.state != SITE_GRANT:
        return None, before
    grant_site(store, set(before))
    return None, row_counts(store)
