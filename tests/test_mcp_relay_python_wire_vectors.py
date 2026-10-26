"""The relay's Python-wire vectors match what the proxy writes for each frame.

The native relay re-serializes a host ``tools/call`` frame the way the proxy
does: ``json.dumps(json.loads(frame))``. The Rust side asserts its rewrite
against ``python`` in the shared fixture; this test keeps that column honest.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

FIXTURE = Path(__file__).parent / "fixtures" / "mcp_relay" / "python_wire_vectors.json"


def _vectors() -> list[dict[str, object]]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))["vectors"]


@pytest.mark.parametrize("vector", _vectors(), ids=lambda vector: str(vector["name"]))
def test_python_column_is_the_proxy_wire(vector: dict[str, object]) -> None:
    host = str(vector["host"])
    expected = vector["python"]
    if expected is None:
        if "digit_limit" in str(vector["name"]) and not hasattr(sys, "get_int_max_str_digits"):
            pytest.skip("this Python has no integer digit limit")
        # Undeliverable: `json.loads` raises, or the frame carries a non-finite
        # float the resident's strict JSON decoder refuses.
        with pytest.raises(ValueError):
            json.dumps(json.loads(host), allow_nan=False)
        return
    assert json.dumps(json.loads(host)) == expected
