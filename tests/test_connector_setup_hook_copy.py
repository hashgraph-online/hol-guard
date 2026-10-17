"""Every harness renderer carries the connector setup reason by blocked-request mode.

The default mode keeps the reason, the computed redirect and the safe-alternative
guidance, with no approval link and no approval step; ``ask`` mode keeps the inbox
wait and the link. Rust renders the same strings from the shared vectors.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.bounded_cli_hook_daemon import _daemon_response_to_native
from codex_plugin_scanner.guard.adapters.cursor_hook_payload import _cursor_block_reason
from codex_plugin_scanner.guard.approval_hook_copy import (
    join_native_hook_reason,
    live_hook_approval_context,
    with_approval_review_url,
)
from codex_plugin_scanner.guard.blocked_request_mode import (
    SAFE_ALTERNATIVE_GUIDANCE,
    connector_setup_reason,
    is_unlinked_connector_setup_reason,
)
from codex_plugin_scanner.guard.cli.commands_support_prompts import _copilot_hook_reason
from codex_plugin_scanner.guard.cli.commands_support_runtime_policy import _native_hook_reason_for_harness

_TESTDATA = Path(__file__).resolve().parents[1] / "rust" / "crates" / "guard-runtime" / "testdata"
_URL = "https://guard.example.test/approvals/0123456789abcdef"
_LINK = f"Open HOL Guard to approve or keep this blocked: {_URL}."
_DEFAULT = connector_setup_reason("lanectl", "cli", ask=False)
_ASK = connector_setup_reason("lanectl", "cli", ask=True)


def _vectors(name: str) -> list[dict[str, object]]:
    return json.loads((_TESTDATA / name).read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", _vectors("connector_setup_reason_vectors.json"))
def test_reason_matches_the_rust_vectors(case: dict[str, object]) -> None:
    permitted = case["permitted"]
    assert isinstance(permitted, list)
    text = connector_setup_reason(str(case["name"]), str(case["surface"]), ask=bool(case["ask"]), permitted=permitted)
    assert text == case["text"]
    assert is_unlinked_connector_setup_reason(text) is not case["ask"]


def test_default_mode_names_only_computed_redirects() -> None:
    assert "Permitted on this device" not in _DEFAULT
    redirected = connector_setup_reason("lanectl", "cli", ask=False, permitted=("lanectl status",))
    assert redirected.endswith(f"Permitted on this device: `lanectl status`. {SAFE_ALTERNATIVE_GUIDANCE}")
    assert "ask the user" not in redirected.lower()


@pytest.mark.parametrize("case", _vectors("bounded_hook_bridge/connector_setup_vectors.json"))
def test_bounded_bridge_harnesses_render_the_shared_vectors(case: dict[str, object]) -> None:
    response = json.loads(str(case["response"]))
    stdout, stderr, exit_code = _daemon_response_to_native(
        response, harness=str(case["harness"]), event_name="PreToolUse"
    )
    assert (stdout, stderr, exit_code) == (case["stdout"], case["stderr"], case["exit_code"])
    assert (str(response["approval_url"]) in stdout) is case["ask"]


def test_default_mode_gets_no_link_from_the_shared_hook_copy() -> None:
    assert with_approval_review_url(_DEFAULT, {"approval_url": _URL}) == _DEFAULT
    assert join_native_hook_reason(_DEFAULT, _LINK) == _DEFAULT
    payload = {"reason": _DEFAULT, "approval_url": _URL}
    assert live_hook_approval_context(payload, harness="claude-code", guard_home=Path("/nonexistent")) is None


def test_ask_mode_keeps_the_link_in_the_shared_hook_copy() -> None:
    assert with_approval_review_url(_ASK, {"approval_url": _URL}) == f"{_ASK} {_LINK}"
    assert join_native_hook_reason(_ASK, _LINK) == f"{_ASK} {_LINK}"


@pytest.mark.parametrize(
    ("harness", "render"),
    [
        ("codex", lambda reason: _native_hook_reason_for_harness("codex", reason)),
        ("omp", lambda reason: _native_hook_reason_for_harness("omp", reason)),
        ("claude-code", lambda reason: _native_hook_reason_for_harness("claude-code", reason)),
        ("copilot", _copilot_hook_reason),
        ("cursor", lambda reason: _cursor_block_reason({"reason": reason, "approval_url": _URL})),
    ],
)
def test_harness_copy_by_mode(harness: str, render: object) -> None:
    assert callable(render)
    default = render(_DEFAULT)
    assert default == _DEFAULT, harness
    assert "approve it" not in default.lower()
    ask = render(_ASK)
    assert ask.startswith(_ASK), harness
    assert "Do not retry it" in ask
    if harness == "cursor":
        assert ask.endswith(_LINK)
