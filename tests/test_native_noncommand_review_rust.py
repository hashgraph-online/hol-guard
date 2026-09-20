"""Cross-language proof from the actual signed-policy Rust producer control.

Set HOL_GUARD_NONCOMMAND_RECEIPT_FIXTURE_LOG to stdout from the named Rust test
run with HOL_GUARD_NONCOMMAND_RECEIPT_FIXTURE=1 and --nocapture. An explicitly
configured but missing/malformed producer result fails; ordinary Python-only
runs skip these producer-dependent cases.
"""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.store import GuardStore

from .test_native_noncommand_review_binding import (
    _binding,
    _rehash,
    assert_current_review_roundtrip,
)


@pytest.fixture(scope="module")
def rust_cases():
    source = os.environ.get("HOL_GUARD_NONCOMMAND_RECEIPT_FIXTURE_LOG")
    if source is None:
        pytest.skip("explicit signed-policy Rust producer log is required")
    output = Path(source).read_text(encoding="utf-8")
    assert len(output) < 1_000_000
    marker = "HOL_GUARD_NONCOMMAND_RECEIPTS="
    lines = [line.split(marker, 1)[1] for line in output.splitlines() if marker in line]
    assert len(lines) == 1, "expected one successful Rust producer output"
    assert "test result: ok. 1 passed; 0 failed" in output
    values = json.loads(lines[0])
    assert isinstance(values, list)
    cases = {row["case"]: row for row in values}
    assert {"network", "read", "mcp", "mcp_command"} <= set(cases)
    return cases


@pytest.mark.parametrize("name", ["network", "network_url", "read", "mcp"])
def test_actual_rust_review_queues_consumes_once_and_roundtrips_full_receipt(tmp_path, rust_cases, name):
    assert_current_review_roundtrip(GuardStore(tmp_path / "guard-home"), rust_cases[name])


def test_actual_rust_command_receipt_cannot_be_reused_as_unmarked_noncommand(rust_cases):
    case = copy.deepcopy(rust_cases["mcp_command"])
    assert case["edge"]["result"]["action"]["action_type"] == "mcp_tool"
    assert "review_scope" not in case["edge"]["receipt"]
    assert _binding(case)["schema"] == "guard.native-review-policy-binding.v1"
    del case["edge"]["receipt"]["command_extensions"]
    del case["edge"]["result"]["command_extensions"]
    _rehash(case["edge"]["receipt"])
    with pytest.raises(ValueError, match="native_review_policy_binding_invalid"):
        _binding(case)
