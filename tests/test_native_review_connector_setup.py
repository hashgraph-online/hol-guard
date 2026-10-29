"""A review held only because Guard was never set up for a local CLI is grouped and worded as setup."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard import config as guard_config
from codex_plugin_scanner.guard.blocked_request_mode import SAFE_ALTERNATIVE_GUIDANCE, connector_setup_reason
from codex_plugin_scanner.guard.daemon import hook_native_review_approval as review
from codex_plugin_scanner.guard.daemon import native_review_connector
from codex_plugin_scanner.guard.local_cli_hook import SetupConnector

_CONNECTOR = SetupConnector(
    cli_id="local-cli.lanectl-0123abcd",
    identity_hash="a" * 64,
    name="lanectl",
    surface="cli",
    queue_group_id="connector:" + "a" * 64 + ":0123456789abcdef",
)
_URL = "http://127.0.0.1:4781/requests/abc"


def _native_review() -> dict[str, object]:
    return {
        "decision": "ask",
        "policy_action": "review",
        "minimum_action": "review",
        "reason_code": "native_command_review_required",
        "reason": "Guard could not prove this command is read-only.",
        "action": {"action_type": "shell"},
    }


def _pause(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    ask: bool,
    connector: SetupConnector | None,
    binding: str | None = "binding",
    token: str | None = None,
    queue_fails: bool = False,
    rendered: dict[str, object] | None = None,
) -> tuple[str, list[dict[str, object]], dict[str, object]]:
    queued: list[dict[str, object]] = []
    silent: dict[str, object] = {}

    def silent_block(_harness: str, inputs: dict[str, Any], **_kwargs: object) -> dict[str, object]:
        # The resident composes the block from these facts; its text is tested in
        # `hook_decision_review_response_tests.rs`.
        silent.update(inputs, verdict=inputs["result"])
        return {"reason": inputs["setup_reason"] or inputs["result"]["reason"]}

    def queue(*_args: object, **kwargs: object) -> dict[str, object] | None:
        queued.append(kwargs)
        if queue_fails:
            return None
        row: dict[str, object] = {"request_id": "abc", "approval_url": _URL}
        return row if rendered is None else {**row, "hook_response": dict(rendered)}

    for name, value in {
        "review_evidence_parts": lambda _evidence: (True, binding, token, None),
        "native_saved_decision_response": lambda *_a, **_k: None,
        "native_review_settle": lambda *_a, **_k: None,
        "native_package_review_response": lambda *_a, **_k: None,
        "native_review_approval_center_url": lambda _store: "http://127.0.0.1:4781",
        "native_review_setup_connector": lambda *_a, **_k: connector,
        "queue_native_pre_tool_review": queue,
        # Rendering is native; the harness shape is tested with the renderers.
        "render_pre_tool": lambda _harness, verdict, **_k: dict(verdict),
        "render_pre_tool_review": lambda _harness, verdict, *, approval, **_k: {
            "reason": f"{verdict['reason']} {approval['approval_url']}"
        },
        "render_silent_review_block": silent_block,
    }.items():
        monkeypatch.setattr(review, name, value)
    mode = SimpleNamespace(blocked_request_mode="ask" if ask else "safe-alternative")
    monkeypatch.setattr(guard_config, "load_guard_config", lambda *_a, **_k: mode)

    response = review.pause_native_pre_tool_for_approval(
        object(),
        harness="codex",
        payload={"tool_name": "Bash", "tool_input": {"command": "lanectl status"}, "cwd": str(tmp_path)},
        native_result=_native_review(),
        native_receipt=None,
        workspace=tmp_path,
        guard_home=tmp_path / "guard",
    )
    return json.dumps(response), queued, silent


def test_default_mode_waits_for_the_users_approval_with_the_link(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    text, queued, silent = _pause(tmp_path, monkeypatch, ask=False, connector=_CONNECTOR)

    assert "HOL Guard has not been set up for `lanectl` (local CLI) on this device." in text
    assert "Allow once or Always allow" in text
    assert "waiting for the user to approve it" in text
    assert SAFE_ALTERNATIVE_GUIDANCE not in text
    assert "seek permission" not in text
    # A local CLI's setup review is an ordinary approvable one, so the resident links it.
    assert (silent["queued"], silent["request_id"], silent["approval_url"]) == (True, "abc", _URL)
    assert (silent["ask"], silent["connector_is_local"], silent["retry_reuses_approval"]) == (False, True, True)
    assert queued[0]["connector"] == _CONNECTOR


def test_a_setup_review_that_could_not_be_queued_never_says_it_is_waiting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _text, queued, silent = _pause(tmp_path, monkeypatch, ask=False, connector=_CONNECTOR, queue_fails=True)

    assert queued
    # With no row the resident drops the setup text and the link.
    assert (silent["queued"], silent["request_id"], silent["approval_url"]) == (False, None, None)


def test_ask_mode_waits_in_the_inbox_with_the_link(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    text, queued, silent = _pause(tmp_path, monkeypatch, ask=True, connector=_CONNECTOR)

    assert "has not been set up for `lanectl`" in text
    assert "Allow once or Always allow" in text
    assert "not an approval of this action" not in text
    assert _URL in text
    assert not silent
    assert queued[0]["connector"] == _CONNECTOR


def test_an_mcp_setup_review_keeps_the_silent_default_text(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    mcp = replace(_CONNECTOR, name="echo-mcp", surface="mcp")
    text, queued, silent = _pause(tmp_path, monkeypatch, ask=False, connector=mcp)

    assert "has not been set up for `echo-mcp` (MCP server)" in text
    assert SAFE_ALTERNATIVE_GUIDANCE in text
    # A remote connector's setup reason in the default mode is never linked.
    assert (silent["ask"], silent["connector_is_local"]) == (False, False)
    assert queued[0]["connector"] == mcp


def test_a_package_script_is_labelled_as_one(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    scripts = replace(_CONNECTOR, name="build", surface="package-scripts")
    text, _queued, silent = _pause(tmp_path, monkeypatch, ask=False, connector=scripts)

    assert "has not been set up for `build` (package script)" in text
    assert "Allow once or Always allow" in text
    assert silent["connector_is_local"] is True


def test_a_row_only_always_allow_can_release_says_so(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _text, queued, silent = _pause(
        tmp_path, monkeypatch, ask=False, connector=_CONNECTOR, binding=None, token="exact-token"
    )

    # The ordinary review text ("just once will not") says only Always allow can release it.
    assert silent["setup_reason"] is None
    assert (silent["retry_reuses_approval"], silent["exact_action_allowable"]) == (False, True)
    assert silent["connector_is_local"] is True
    assert queued[0]["connector"] == _CONNECTOR


def test_a_row_approval_cannot_release_gets_no_link(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    text, queued, silent = _pause(tmp_path, monkeypatch, ask=True, connector=_CONNECTOR, binding=None)

    assert "has not been set up for `lanectl`" in text
    assert SAFE_ALTERNATIVE_GUIDANCE in text
    assert "inbox" not in text.lower()
    assert (silent["retry_reuses_approval"], silent["exact_action_allowable"]) == (False, False)
    assert queued[0]["connector"] == _CONNECTOR


def test_an_ordinary_review_keeps_its_text(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    text, queued, silent = _pause(tmp_path, monkeypatch, ask=False, connector=None)

    assert "has not been set up" not in text
    assert "could not prove this command is read-only" in text
    assert silent["setup_reason"] is None
    assert silent["verdict"] == _native_review()
    assert queued[0]["connector"] is None


@pytest.mark.parametrize(
    "reason_code",
    [
        "native_network_review",
        "native_package_review",
        "native_file_read_review",
        "native_workspace_containment_required",
        None,
    ],
)
def test_a_review_with_a_risk_signal_is_never_setup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reason_code: str | None
) -> None:
    def unexpected(**_kwargs: object) -> SetupConnector:
        raise AssertionError("risk reviews must not ask for the connector")

    monkeypatch.setattr("codex_plugin_scanner.guard.local_cli_hook.local_cli_setup_connector", unexpected)

    assert (
        native_review_connector.native_review_setup_connector(
            object(),
            payload={"tool_name": "Bash", "tool_input": {"command": "lanectl status"}, "cwd": str(tmp_path)},
            native_result={**_native_review(), "reason_code": reason_code},
            workspace=tmp_path,
            home_dir=None,
        )
        is None
    )


@pytest.mark.parametrize(
    "reason_code", ["native_command_review_required", "native_workspace_containment_executable_outside_roots"]
)
def test_an_unrecognised_command_asks_for_its_connector(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reason_code: str
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.local_cli_hook.local_cli_setup_connector", lambda **_kwargs: _CONNECTOR
    )

    assert (
        native_review_connector.native_review_setup_connector(
            object(),
            payload={"tool_name": "Bash", "tool_input": {"command": "lanectl status"}, "cwd": str(tmp_path)},
            native_result={**_native_review(), "reason_code": reason_code},
            workspace=tmp_path,
            home_dir=None,
        )
        == _CONNECTOR
    )


def test_the_lookup_uses_the_path_the_agent_runs_with(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[object] = []

    def lookup(**kwargs: object) -> SetupConnector:
        seen.append(kwargs["path"])
        return _CONNECTOR

    monkeypatch.setattr("codex_plugin_scanner.guard.local_cli_hook.local_cli_setup_connector", lookup)
    payload = {"tool_name": "Bash", "tool_input": {"command": "lanectl status"}, "cwd": str(tmp_path)}

    for stamped in ({"path": "/home/dev/.local/bin:/usr/bin"}, {"path": "bad\0path"}, None):
        native_review_connector.native_review_setup_connector(
            object(),
            payload={**payload, "guard_execution_environment": stamped},
            native_result=_native_review(),
            workspace=tmp_path,
            home_dir=None,
        )

    assert seen == ["/home/dev/.local/bin:/usr/bin", None, None]


def test_a_failed_lookup_leaves_an_ordinary_review(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def failing(**_kwargs: object) -> SetupConnector:
        raise TimeoutError("deadline")

    monkeypatch.setattr("codex_plugin_scanner.guard.local_cli_hook.local_cli_setup_connector", failing)

    assert (
        native_review_connector.native_review_setup_connector(
            object(),
            payload={"tool_name": "Bash", "tool_input": {"command": "lanectl status"}, "cwd": str(tmp_path)},
            native_result=_native_review(),
            workspace=tmp_path,
            home_dir=None,
        )
        is None
    )


@pytest.mark.parametrize(
    ("name", "shown"),
    [
        ("lanectl", "lanectl"),
        ("@scope/echo-mcp", "@scope/echo-mcp"),
        ("bad`name", "this local CLI"),
        ("two\nlines", "this local CLI"),
        ("x" * 80, "this local CLI"),
    ],
)
def test_agent_text_shows_only_plain_names(name: str, shown: str) -> None:
    connector = replace(_CONNECTOR, name=name)

    assert native_review_connector.connector_display_name(connector) == shown


def test_a_local_tool_setup_text_is_an_approval_wait_and_an_mcp_one_is_not() -> None:
    local = connector_setup_reason("lanectl", "package-scripts", ask=False)
    mcp = connector_setup_reason("echo-mcp", "mcp", ask=False)
    mcp_ask = connector_setup_reason("echo-mcp", "mcp", ask=True)

    assert local.startswith("HOL Guard has not been set up for `lanectl` (package script) on this device.")
    assert "Allow once or Always allow" in local
    assert SAFE_ALTERNATIVE_GUIDANCE not in local
    assert mcp.endswith(SAFE_ALTERNATIVE_GUIDANCE)
    assert "approve" not in mcp.lower()
    assert "one-time decision" in mcp_ask
    assert SAFE_ALTERNATIVE_GUIDANCE not in mcp_ask


def test_the_queue_call_renders_the_silent_block_with_its_row(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    text, queued, silent = _pause(
        tmp_path, monkeypatch, ask=False, connector=_CONNECTOR, rendered={"reason": "rendered with the row"}
    )

    assert json.loads(text) == {"reason": "rendered with the row"}
    # The block's facts ride the queue call; no second render is asked for.
    assert not silent
    respond: Any = queued[0]["respond"]
    facts = respond["silent_review_block"]
    assert (facts["ask"], facts["connector_is_local"], facts["retry_reuses_approval"]) == (False, True, True)
    assert facts["exact_action_allowable"] is False
    assert "has not been set up for `lanectl`" in facts["setup_reason"]


def test_the_queue_call_renders_the_paused_review_with_its_row(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    text, queued, _silent = _pause(
        tmp_path, monkeypatch, ask=True, connector=_CONNECTOR, rendered={"reason": "rendered with the row"}
    )

    response = json.loads(text)
    assert response["reason"] == "rendered with the row"
    assert response["prompted"] is True
    assert response["approval_center_url"] == "http://127.0.0.1:4781"
    respond: Any = queued[0]["respond"]
    assert "has not been set up for `lanectl`" in respond["paused_review"]["reason"]
