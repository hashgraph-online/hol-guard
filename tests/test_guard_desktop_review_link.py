"""The HOL Guard Desktop link Guard offers for a pending approval request."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.desktop_review_link import (
    desktop_opens_requests,
    desktop_request_url,
    desktop_review_url,
)

REQUEST_ID = "2c79d707370b453886adf5b2e7e622ec"


def _marker(home: Path, mode: int = 0o600, **overrides: object) -> None:
    marker: dict[str, object] = {
        "version": 1,
        "scheme": "hol-guard-desktop",
        "routes": ["requests"],
        "app_path": str(home),
    }
    marker.update(overrides)
    path = home / "desktop-deep-link.json"
    path.write_text(json.dumps(marker), encoding="utf-8")
    path.chmod(mode)


def test_installed_desktop_opens_request_links(tmp_path: Path) -> None:
    _marker(tmp_path)

    assert desktop_review_url(tmp_path, REQUEST_ID) == f"hol-guard-desktop://requests/{REQUEST_ID}"


def test_no_marker_offers_no_desktop_link(tmp_path: Path) -> None:
    assert desktop_review_url(tmp_path, REQUEST_ID) is None


@pytest.mark.parametrize(
    "overrides",
    [
        {"version": 2},
        {"scheme": "https"},
        {"routes": ["claim"]},
        {"app_path": ""},
        {"app_path": "/nonexistent/HOL Guard.app"},
    ],
)
def test_a_marker_that_does_not_name_an_installed_request_route_offers_nothing(
    tmp_path: Path, overrides: dict[str, object]
) -> None:
    _marker(tmp_path, **overrides)

    assert not desktop_opens_requests(tmp_path)


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
def test_a_marker_other_users_can_write_offers_nothing(tmp_path: Path) -> None:
    _marker(tmp_path, mode=0o666)

    assert not desktop_opens_requests(tmp_path)


@pytest.mark.parametrize("request_id", ["req-1", REQUEST_ID.upper(), f"{REQUEST_ID}/../x", ""])
def test_only_queue_shaped_request_ids_become_desktop_links(request_id: str) -> None:
    assert desktop_request_url(request_id) is None
