"""A review held only because Guard was never set up for a local CLI is grouped and worded as setup.

The resident looks up the connector inside the queue call and answers its
setup wording (`guard_store_native_review_queue_tests.rs`); these tests cover
what the hook sends and how it reads the answer.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard import config as guard_config
from codex_plugin_scanner.guard.blocked_request_mode import SAFE_ALTERNATIVE_GUIDANCE, connector_setup_reason
from codex_plugin_scanner.guard.daemon import hook_native_review_approval as review
from codex_plugin_scanner.guard.daemon import native_review_connector

_URL = "http://127.0.0.1:4781/requests/abc"
_SETUP = {
    "name": "lanectl",
    "is_local": True,
    "setup_reason": connector_setup_reason("lanectl", "cli", ask=False),
}


def _native_review() -> dict[str, object]:
    return {
        "decision": "ask",
        "policy_action": "review",
        "minimum_action": "review",
        "reason_code": "native_command_review_required",
        "reason": "Guard could not prove this command is read-only.",
        "action": {"action_type": "shell"},
    }


def _payload(tmp_path: Path, **extra: object) -> dict[str, object]:
    return {"tool_name": "Bash", "tool_input": {"command": "lanectl status"}, "cwd": str(tmp_path), **extra}


def _pause(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    ask: bool,
    setup: dict[str, object] | None,
    binding: str | None = "binding",
    token: str | None = None,
    queue_fails: bool = False,
    rendered: dict[str, object] | None = None,
    reason_code: str = "native_command_review_required",
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
        if setup is not None:
            row["connector_setup"] = dict(setup)
        return row if rendered is None else {**row, "hook_response": dict(rendered)}

    for name, value in {
        "review_evidence_parts": lambda _evidence: (True, binding, token, None),
        "native_saved_decision_response": lambda *_a, **_k: None,
        "native_exact_command_block_response": lambda *_a, **_k: None,
        "native_review_settle": lambda *_a, **_k: None,
        "native_package_review_response": lambda *_a, **_k: None,
        "native_review_approval_center_url": lambda _store: "http://127.0.0.1:4781",
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
        payload=_payload(tmp_path),
        native_result={**_native_review(), "reason_code": reason_code},
        native_receipt=None,
        workspace=tmp_path,
        guard_home=tmp_path / "guard",
        home_dir=tmp_path / "home",
    )
    return json.dumps(response), queued, silent


def test_default_mode_waits_for_the_users_approval_with_the_link(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    text, queued, silent = _pause(tmp_path, monkeypatch, ask=False, setup=_SETUP)

    assert "HOL Guard has not been set up for `lanectl` (local CLI) on this device." in text
    assert "Allow once or Always allow" in text
    assert SAFE_ALTERNATIVE_GUIDANCE not in text
    # A local CLI's setup review is an ordinary approvable one, so the resident links it.
    assert (silent["queued"], silent["request_id"], silent["approval_url"]) == (True, "abc", _URL)
    assert (silent["ask"], silent["connector_is_local"], silent["retry_reuses_approval"]) == (False, True, True)
    lookup: Any = queued[0]["connector_lookup"]
    assert (lookup["command"], lookup["cwd"], lookup["home_dir"]) == (
        "lanectl status",
        str(tmp_path),
        str(tmp_path / "home"),
    )


def test_a_setup_review_that_could_not_be_queued_never_says_it_is_waiting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    text, queued, silent = _pause(tmp_path, monkeypatch, ask=False, setup=_SETUP, queue_fails=True)

    assert queued
    # With no row there is no setup text and no link.
    assert (silent["queued"], silent["request_id"], silent["approval_url"]) == (False, None, None)
    assert (silent["setup_reason"], silent["connector_is_local"]) == (None, False)
    assert "has not been set up" not in text


def test_ask_mode_shows_the_setup_text_the_queue_call_answered(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    asked = {**_SETUP, "setup_reason": connector_setup_reason("lanectl", "cli", ask=True)}
    text, queued, silent = _pause(tmp_path, monkeypatch, ask=True, setup=asked)

    assert "has not been set up for `lanectl`" in text
    assert _URL in text
    assert not silent
    assert queued[0]["connector_lookup"] is not None


def test_an_answer_without_setup_text_keeps_the_review_text(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A local row only an exact-action Always can release keeps the ordinary text.
    exact_only = {**_SETUP, "setup_reason": None}
    _text, _queued, silent = _pause(
        tmp_path, monkeypatch, ask=False, setup=exact_only, binding=None, token="exact-token"
    )

    assert silent["setup_reason"] is None
    assert (silent["retry_reuses_approval"], silent["exact_action_allowable"]) == (False, True)
    assert silent["connector_is_local"] is True


def test_an_ordinary_review_keeps_its_text(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    text, _queued, silent = _pause(tmp_path, monkeypatch, ask=False, setup=None)

    assert "has not been set up" not in text
    assert "could not prove this command is read-only" in text
    assert silent["setup_reason"] is None
    assert silent["verdict"] == _native_review()


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
def test_a_review_with_a_risk_signal_never_looks_up_a_connector(tmp_path: Path, reason_code: str | None) -> None:
    assert (
        native_review_connector.native_review_connector_lookup(
            payload=_payload(tmp_path),
            native_result={**_native_review(), "reason_code": reason_code},
            workspace=tmp_path,
            home_dir=None,
        )
        is None
    )


@pytest.mark.parametrize(
    "reason_code", ["native_command_review_required", "native_workspace_containment_executable_outside_roots"]
)
def test_an_unrecognised_command_looks_up_its_connector(tmp_path: Path, reason_code: str) -> None:
    lookup = native_review_connector.native_review_connector_lookup(
        payload=_payload(tmp_path),
        native_result={**_native_review(), "reason_code": reason_code},
        workspace=tmp_path,
        home_dir=None,
    )

    assert lookup is not None
    assert (lookup["command"], lookup["cwd"], lookup["home_dir"]) == ("lanectl status", str(tmp_path), None)
    assert lookup["user_home"] == str(Path.home())


def test_the_lookup_uses_the_path_the_agent_runs_with(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PATH", "/daemon/bin")
    seen: list[object] = []
    for stamped in ({"path": "/home/dev/.local/bin:/usr/bin"}, {"path": "bad\0path"}, None):
        lookup = native_review_connector.native_review_connector_lookup(
            payload=_payload(tmp_path, guard_execution_environment=stamped),
            native_result=_native_review(),
            workspace=tmp_path,
            home_dir=None,
        )
        assert lookup is not None
        env: Any = lookup["env"]
        seen.append(env["PATH"])

    assert seen == ["/home/dev/.local/bin:/usr/bin", "/daemon/bin", "/daemon/bin"]


def test_a_launch_too_large_for_the_queue_call_queues_an_ordinary_review(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The lookup shares the review's store request; a launch that could push it
    # past the request limit is left out so the review still queues.
    monkeypatch.setenv("HOL_GUARD_TEST_LARGE_VALUE", "x" * (256 * 1024))

    assert (
        native_review_connector.native_review_connector_lookup(
            payload=_payload(tmp_path), native_result=_native_review(), workspace=tmp_path, home_dir=None
        )
        is None
    )


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
        tmp_path, monkeypatch, ask=False, setup=_SETUP, rendered={"reason": "rendered with the row"}
    )

    assert json.loads(text) == {"reason": "rendered with the row"}
    # The block's facts ride the queue call; no second render is asked for.
    assert not silent
    respond: Any = queued[0]["respond"]
    block = respond["silent_review_block"]
    # The resident derives the binding and setup facts itself.
    assert block == {"ask": False, "home_dir": str(tmp_path / "home")}


def test_the_queue_call_renders_the_paused_review_with_its_row(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    text, queued, _silent = _pause(
        tmp_path, monkeypatch, ask=True, setup=_SETUP, rendered={"reason": "rendered with the row"}
    )

    response = json.loads(text)
    assert response["reason"] == "rendered with the row"
    assert response["prompted"] is True
    assert response["approval_center_url"] == "http://127.0.0.1:4781"
    assert queued[0]["respond"] == {"paused_review": {}}
