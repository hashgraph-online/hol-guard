"""Pure-shape parity vectors recorded from the retired Python implementation.

The environment-independent checks run through the real resident; the full
corpus (including path and shell-context cases) runs in the Rust suite against
the same fixture.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.compound_git_inspection import (
    _safe_repository_path,
    canonical_home_git_c_path,
)

pytestmark = pytest.mark.skipif(
    not (os.environ.get("HOL_GUARD_NATIVE_REGRESSION") == "1" and os.environ.get("HOL_GUARD_NATIVE_BINARY")),
    reason="native runtime binary is not provisioned for this run",
)

_FIXTURE = (
    Path(__file__).resolve().parents[1]
    / "rust"
    / "crates"
    / "guard-runtime"
    / "tests"
    / "fixtures"
    / "compound_git_inspection_vectors.json"
)


def _cases(check: str) -> list[dict[str, object]]:
    corpus = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    return [case for case in corpus["cases"] if case["check"] == check]


@pytest.mark.parametrize("case", _cases("repository_path"), ids=lambda case: repr(case["value"]))
def test_repository_path_matches_the_retired_python_vectors(case: dict[str, object]) -> None:
    assert _safe_repository_path(str(case["value"])) is case["expected"]


@pytest.mark.parametrize("case", _cases("home_git_c_path"), ids=lambda case: repr(case["command_text"]))
def test_home_git_c_path_matches_the_retired_python_vectors(case: dict[str, object]) -> None:
    assert canonical_home_git_c_path(str(case["command_text"])) == case["expected"]
