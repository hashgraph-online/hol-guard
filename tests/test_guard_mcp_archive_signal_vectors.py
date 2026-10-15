"""Shared-vector end-to-end check of the resident archive binder and reason projection.

``tests/fixtures/mcp_proxy_decision/archive_signal_vectors.json`` was recorded from
the Python proxy helpers before they moved into the resident (see its provenance
block). This replays it through the real Python transport and the real resident.
There is no Python oracle: the vectors are the contract.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_mcp_proxy_decision import (
    native_external_archive_bind,
    native_package_reason_signals,
)

VECTORS = json.loads(
    (Path(__file__).parent / "fixtures" / "mcp_proxy_decision" / "archive_signal_vectors.json").read_text(
        encoding="utf-8"
    )
)["vectors"]
PLATFORM = "windows" if sys.platform == "win32" else "unix"

pytestmark = pytest.mark.skipif(
    os.environ.get("HOL_GUARD_NATIVE_REGRESSION") != "1",
    reason="needs the resident runtime (HOL_GUARD_NATIVE_REGRESSION=1)",
)


@pytest.fixture(scope="module")
def guard_home(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return tmp_path_factory.mktemp("mcp-archive-signal-home")


def test_archive_binding_matches_every_recorded_vector(guard_home: Path) -> None:
    checked = 0
    for vector in VECTORS:
        request = vector["request"]
        if request["check"] != "external_archive_bind":
            continue
        expected = vector["expected"][PLATFORM]
        bound = native_external_archive_bind(
            request["params"],
            dict(request["replacements"]),
            requires_binding=request["requires_binding"],
            guard_home=guard_home,
        )
        if expected["kind"] == "unbound":
            assert bound is None, vector["id"]
        elif expected["kind"] == "unchanged":
            assert bound == request["params"], vector["id"]
        else:
            assert bound == expected["bound_params"], vector["id"]
        checked += 1
    assert checked > 1500


def test_reason_signals_match_every_recorded_vector(guard_home: Path) -> None:
    checked = 0
    for vector in VECTORS:
        request = vector["request"]
        if request["check"] != "package_reason_signals":
            continue
        signals = native_package_reason_signals(request["reasons"], guard_home=guard_home)
        assert list(signals) == vector["expected"]["signals"], vector["id"]
        checked += 1
    assert checked >= 15
