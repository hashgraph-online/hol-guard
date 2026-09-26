"""The native queue producer and dashboard parser share a wire fixture."""

import json
from pathlib import Path

from codex_plugin_scanner.guard.daemon.hook_native_review_approval import _native_review_action_envelope


def test_native_review_produces_dashboard_wire_contract() -> None:
    expected = json.loads((Path(__file__).parent / "fixtures/native-review-action-envelope.json").read_text())
    actual = _native_review_action_envelope(
        request_id="native-review-fixture",
        harness="omp",
        tool_name="eval",
        command=None,
        launch_target="tool:eval",
        workspace=None,
    )
    assert actual == expected
