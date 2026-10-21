"""Legacy ``hol-guard hook`` permission requests reach the harness prompt."""

import argparse
import io
from types import SimpleNamespace
from typing import cast

import pytest

from codex_plugin_scanner.guard.cli import commands_hook_native_pipeline as pipeline
from codex_plugin_scanner.guard.cli.commands_hook_native_pipeline import run_native_hook_pipeline
from codex_plugin_scanner.guard.native_hook_route import PASSTHROUGH_HANDLER, NativeHookRoute


class _NoReview:
    def __getattr__(self, name: str) -> object:
        raise AssertionError(f"passthrough permission requests must not reach the edge ({name})")


@pytest.mark.parametrize("harness", ("devin", "zcode"))
@pytest.mark.parametrize("event_name", ("PermissionRequest", "permission_request", "permissionRequestV2"))
def test_permission_request_gets_no_decision(monkeypatch: pytest.MonkeyPatch, harness: str, event_name: str) -> None:
    payload = {"hook_event_name": event_name, "tool_name": "Bash", "tool_input": {"command": "pwd"}}
    asked: list[dict[str, object]] = []

    def route(inputs: dict[str, object], **_kwargs: object) -> NativeHookRoute:
        asked.append(inputs)
        return NativeHookRoute((PASSTHROUGH_HANDLER,), "PermissionRequest")

    monkeypatch.setattr(
        pipeline,
        "prepare_native_hook_state",
        lambda *_args, payload, **_kwargs: (payload, None, False, None, None, None, None, None),
    )
    monkeypatch.setattr(pipeline, "native_hook_route", route)
    output = io.StringIO()
    result = run_native_hook_pipeline(
        argparse.Namespace(harness=harness),
        config=cast("object", SimpleNamespace()),
        context=cast("object", SimpleNamespace(guard_home=None, home_dir=None)),
        payload=payload,
        runtime_workspace=None,
        store=cast("object", _NoReview()),
        worker=cast("object", _NoReview()),
        output_stream=output,
    )
    # Empty output and exit 0: the harness shows its own approval prompt,
    # where an exit 2 review would have been read as a refusal.
    assert result == 0
    assert output.getvalue() == ""
    assert [facts["invoked_event"] for facts in asked] == ["PermissionRequest"]
