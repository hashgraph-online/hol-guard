"""Guard the recorded home-path answers the Rust twin replays.

``rust/crates/guard-command/src/home_path_text_parity_tests.rs`` reads the same
fixture. The module under test is 23 lines of ``pathlib`` and ``os.path``, so
its answers are whichever flavour of those the running interpreter has. The
generator records both flavours by substituting the pure-path and path modules;
this file checks that the substitution still reproduces the fixture, and that
the real module agrees with its own platform's section.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.runtime.home_path_text import expand_home, normalize_path
from scripts.ci import generate_home_path_text_parity as recorder

FIXTURE = Path(__file__).resolve().parents[1] / "tests/fixtures/home-path-text-parity.v1.json"
HOST = "windows" if os.name == "nt" else "posix"


def _document() -> dict[str, Any]:
    document = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert document["schema"] == recorder.SCHEMA
    return document


def _cases(flavour: str, group: str) -> list[dict[str, str]]:
    cases = _document()[flavour][group]
    assert cases, f"the fixture records no {flavour} {group} cases"
    return cases


@pytest.mark.parametrize("flavour", ("posix", "windows"))
def test_the_recorded_answers_are_still_what_python_says(flavour: str) -> None:
    for case in _cases(flavour, "expand_home"):
        recorded = recorder.expand_home(case["value"], case["home"], flavour)
        assert recorded == case["expected"], case
    for case in _cases(flavour, "normpath"):
        assert recorder.normpath(case["value"], flavour) == case["expected"], case


def test_the_module_answers_its_own_platforms_section() -> None:
    """The substitution is only honest if the real module matches it here."""

    for case in _cases(HOST, "expand_home"):
        # ``Path("")`` is ``Path(".")``, which is what the recorder's pure path
        # spells for the same text, so every recorded home round-trips.
        recorded = expand_home(case["value"], Path(case["home"]))
        assert recorded == case["expected"], case
    for case in _cases(HOST, "normpath"):
        assert normalize_path(case["value"], None) == case["expected"], case


def test_a_relative_path_that_collapses_is_the_current_directory() -> None:
    """The divergence this fixture was written for, kept named.

    Rust returned the empty string where ``posixpath`` returns ``.``, and an
    empty string passes a caller's check for ``.``.
    """

    collapsing = [case["value"] for case in _cases("posix", "normpath") if case["expected"] == "."]
    assert {".", "a/..", "./."} <= set(collapsing), collapsing
