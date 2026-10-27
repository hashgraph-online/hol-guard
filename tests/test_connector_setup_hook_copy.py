"""Every harness renderer carries the connector setup reason by blocked-request mode.

An MCP server's default mode keeps the reason, the computed redirect and the safe-alternative
guidance, with no approval link and no approval step; ``ask`` mode keeps the inbox wait and the
link. A local CLI or script is an ordinary review in both modes: the inbox wait and the link.
Rust renders the same strings from the shared vectors.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.approval_hook_copy import (
    join_native_hook_reason,
    with_approval_review_url,
)
from codex_plugin_scanner.guard.blocked_request_mode import (
    SAFE_ALTERNATIVE_GUIDANCE,
    connector_setup_reason,
    is_unlinked_connector_setup_reason,
)

_TESTDATA = Path(__file__).resolve().parents[1] / "rust" / "crates" / "guard-runtime" / "testdata"
_URL = "https://guard.example.test/approvals/0123456789abcdef"
_LINK = f"Open HOL Guard to approve or keep this blocked: {_URL}."
_DEFAULT = connector_setup_reason("echo-mcp", "mcp", ask=False)
_ASK = connector_setup_reason("echo-mcp", "mcp", ask=True)
_LOCAL = connector_setup_reason("lanectl", "cli", ask=False)


def _vectors(name: str) -> list[dict[str, object]]:
    return json.loads((_TESTDATA / name).read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", _vectors("connector_setup_reason_vectors.json"))
def test_reason_matches_the_rust_vectors(case: dict[str, object]) -> None:
    permitted = case["permitted"]
    assert isinstance(permitted, list)
    text = connector_setup_reason(
        str(case["name"]),
        str(case["surface"]),
        ask=bool(case["ask"]),
        permitted=permitted,
        approvable=bool(case["approvable"]),
    )
    assert text == case["text"]
    assert is_unlinked_connector_setup_reason(text) is case["unlinked"]


def test_default_mode_names_only_computed_redirects() -> None:
    assert "Permitted on this device" not in _DEFAULT
    redirected = connector_setup_reason("echo-mcp", "mcp", ask=False, permitted=("echo",))
    assert redirected.endswith(f"Permitted on this device: `echo`. {SAFE_ALTERNATIVE_GUIDANCE}")
    assert "ask the user" not in redirected.lower()


@pytest.mark.parametrize("surface", ["cli", "package-scripts"])
@pytest.mark.parametrize("ask", [False, True])
def test_a_local_tool_is_an_ordinary_review_offering_the_users_choice(surface: str, ask: bool) -> None:
    text = connector_setup_reason("lanectl", surface, ask=ask)
    assert "Allow once or Always allow" in text
    assert "hol-guard approvals" in text
    assert SAFE_ALTERNATIVE_GUIDANCE not in text
    assert "seek permission" not in text
    assert not is_unlinked_connector_setup_reason(text)


def test_a_local_tool_no_approval_can_release_stays_a_plain_block() -> None:
    text = connector_setup_reason("lanectl", "cli", ask=False, approvable=False)
    assert text.endswith(SAFE_ALTERNATIVE_GUIDANCE)
    assert is_unlinked_connector_setup_reason(text)


def test_a_local_tool_gets_the_shared_hook_link_in_the_default_mode() -> None:
    assert with_approval_review_url(_LOCAL, {"approval_url": _URL}) == f"{_LOCAL} {_LINK}"
    assert join_native_hook_reason(_LOCAL, _LINK) == f"{_LOCAL} {_LINK}"


def test_default_mode_gets_no_link_from_the_shared_hook_copy() -> None:
    assert with_approval_review_url(_DEFAULT, {"approval_url": _URL}) == _DEFAULT
    assert join_native_hook_reason(_DEFAULT, _LINK) == _DEFAULT


def test_ask_mode_keeps_the_link_in_the_shared_hook_copy() -> None:
    assert with_approval_review_url(_ASK, {"approval_url": _URL}) == f"{_ASK} {_LINK}"
    assert join_native_hook_reason(_ASK, _LINK) == f"{_ASK} {_LINK}"
