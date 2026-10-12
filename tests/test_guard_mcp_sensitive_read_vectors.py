"""Shared-vector end-to-end check of the resident sensitive-read decisions.

``tests/fixtures/mcp_sensitive_read/parity_vectors.json`` is language neutral and
was recorded from the Python stdio proxy helpers before they moved into the
resident (see its provenance block). The Rust crate replays it against the
decision functions; this test replays it through the real Python transport and
the real resident. There is no Python oracle: the vectors are the contract.
"""

from __future__ import annotations

import json
import os
from collections import defaultdict
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.native_mcp_proxy_decision import native_mcp_proxy_decide

DOCUMENT = json.loads(
    (Path(__file__).parent / "fixtures" / "mcp_sensitive_read" / "parity_vectors.json").read_text(encoding="utf-8")
)
BY_CHECK: dict[str, list[dict[str, Any]]] = defaultdict(list)
for _vector in DOCUMENT["vectors"]:
    BY_CHECK[_vector["check"]].append(_vector)

pytestmark = pytest.mark.skipif(
    os.environ.get("HOL_GUARD_NATIVE_REGRESSION") != "1",
    reason="needs the resident runtime (HOL_GUARD_NATIVE_REGRESSION=1)",
)


def _is_subset(expected: Any, actual: Any) -> bool:
    if isinstance(expected, dict) and isinstance(actual, dict):
        return all(_is_subset(value, actual.get(key)) for key, value in expected.items())
    if isinstance(expected, list) and isinstance(actual, list):
        return len(expected) == len(actual) and all(
            _is_subset(left, right) for left, right in zip(expected, actual, strict=True)
        )
    return expected == actual


@pytest.fixture(scope="module")
def guard_home(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return tmp_path_factory.mktemp("mcp-sensitive-read-home")


@pytest.mark.parametrize("check", sorted(BY_CHECK))
def test_resident_matches_every_recorded_vector(check: str, guard_home: Path) -> None:
    vectors = BY_CHECK[check]
    assert vectors
    for vector in vectors:
        payload = native_mcp_proxy_decide(vector["request"], guard_home=guard_home)
        assert _is_subset(vector["expected"], payload), (
            f"{vector['id']} diverged\nexpected {vector['expected']}\nactual   {payload}"
        )
