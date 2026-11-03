"""Guard the recorded approval-link strip both implementations replay.

``rust/crates/guard-runtime/src/native_review_link_tests.rs`` reads the same
fixture. The resident renders the agent's deny text with
``native_review_link::without_raw_url``; the fail-closed fallback in
``hook_fail_closed`` composes it in Python, because that path runs only when
the resident cannot answer. A change to either side that this fixture does not
also record is caught here first.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.daemon.hook_fail_closed import _without_raw_url

FIXTURE = Path(__file__).resolve().parents[1] / "tests/fixtures/guard-review-link-strip.v1.json"


def _cases() -> list[dict[str, Any]]:
    document = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert document["schema"] == "guard-review-link-strip-parity.v1"
    cases = document["cases"]
    assert cases, "the fixture records at least one case"
    return cases


@pytest.mark.parametrize("case", _cases(), ids=lambda case: str(case["name"]))
def test_without_raw_url_matches_the_recorded_strip(case: dict[str, Any]) -> None:
    assert _without_raw_url(case["reason"], case["approval_url"]) == case["stripped"]
