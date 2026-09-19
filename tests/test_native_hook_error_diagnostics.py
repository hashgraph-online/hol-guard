"""Error diagnostics cannot reinterpret a failure as an authoritative decision."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.native_hook_edge import _decode_edge, _native_error_code


@pytest.mark.parametrize("retryable", [False, True])
def test_known_native_error_is_diagnostic_only(retryable: bool) -> None:
    payload = {"error": "native_policy_snapshot_not_current", "retryable": retryable}
    assert _native_error_code(payload) == "native_policy_snapshot_not_current"
    assert _decode_edge(payload) is None


@pytest.mark.parametrize(
    "payload",
    [
        None,
        [],
        {"error": "untrusted stderr containing a path", "retryable": False},
        {"error": {"secret": "fixture"}, "retryable": False},
        {"error": "native_policy_snapshot_not_current", "retryable": 1},
        {"error": "native_policy_snapshot_not_current"},
        {"error": "native_policy_snapshot_not_current", "retryable": False, "raw": "fixture"},
    ],
)
def test_unknown_or_malformed_native_errors_are_not_exposed(payload: object) -> None:
    assert _native_error_code(payload) is None
    assert _decode_edge(payload) is None
