"""Legacy ``hol-guard hook`` permission requests reach the harness prompt."""

import argparse
import io
from typing import cast

import pytest

from codex_plugin_scanner.guard.cli.commands_hook_native_pipeline import run_native_hook_pipeline


class _NoReview:
    def __getattr__(self, name: str) -> object:
        raise AssertionError(f"passthrough permission requests must not reach the edge ({name})")


@pytest.mark.parametrize("harness", ("devin", "zcode"))
@pytest.mark.parametrize("event_name", ("PermissionRequest", "permission_request", "permissionRequestV2"))
def test_permission_request_gets_no_decision(harness: str, event_name: str) -> None:
    output = io.StringIO()
    result = run_native_hook_pipeline(
        argparse.Namespace(harness=harness),
        config=None,
        context=cast("object", _NoReview()),
        payload={"hook_event_name": event_name, "tool_name": "Bash", "tool_input": {"command": "pwd"}},
        runtime_workspace=None,
        store=cast("object", _NoReview()),
        worker=cast("object", _NoReview()),
        output_stream=output,
    )
    # Empty output and exit 0: the harness shows its own approval prompt,
    # where an exit 2 review would have been read as a refusal.
    assert result == 0
    assert output.getvalue() == ""
