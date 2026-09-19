"""Cross-runtime fixtures for the exact byte selector contract."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.exact_command import (
    EXACT_COMMAND_BLANK_CODEPOINTS,
    EXACT_COMMAND_CONTRACT,
    EXACT_COMMAND_MAX_BYTES,
    exact_command_sha256,
    exact_shell_command_from_hook,
    exact_shell_command_text,
    validate_exact_command_selector,
)

_FIXTURE = json.loads((Path(__file__).parent / "fixtures/exact-command-contract-v1.json").read_text())


@pytest.mark.parametrize("case", _FIXTURE["cases"], ids=lambda case: case["id"])
def test_shared_exact_command_fixtures(case):
    command = exact_shell_command_text(case["toolName"], case["arguments"])
    assert exact_command_sha256(command) == case["expectedSha256"]
    if command is not None:
        assert command in case["arguments"].values()


def test_shared_contract_bounds_and_blank_characters():
    assert _FIXTURE["contractVersion"] == EXACT_COMMAND_CONTRACT
    assert _FIXTURE["maxBytes"] == EXACT_COMMAND_MAX_BYTES
    assert _FIXTURE["blankCodepoints"] == list(EXACT_COMMAND_BLANK_CODEPOINTS)
    assert exact_command_sha256("\ud800") is None


@pytest.mark.parametrize(
    "value",
    [
        None,
        {},
        {"contractVersion": EXACT_COMMAND_CONTRACT},
        {"contractVersion": "v2", "sha256": "a" * 64},
        {"contractVersion": EXACT_COMMAND_CONTRACT, "sha256": "A" * 64},
        {"contractVersion": EXACT_COMMAND_CONTRACT, "sha256": "a" * 63},
        {"contractVersion": EXACT_COMMAND_CONTRACT, "sha256": "a" * 64, "extra": True},
    ],
)
def test_incomplete_or_unsupported_selector_is_rejected(value):
    with pytest.raises(ValueError, match="invalid_exact_command_selector"):
        validate_exact_command_selector(value)


def test_hook_capture_refuses_ambiguous_containers_and_preserves_exact_bytes():
    payload = {"tool_name": "Bash", "tool_input": {"command": "\tprintf 'a  b'\r\n"}}
    assert exact_shell_command_from_hook(payload) == "\tprintf 'a  b'\r\n"
    assert exact_shell_command_from_hook({**payload, "arguments": payload["tool_input"]}) is None
    assert exact_shell_command_from_hook({**payload, "toolName": "Bash"}) is None
    digest = exact_command_sha256("\tprintf 'a  b'\r\n")
    assert digest is not None
    assert validate_exact_command_selector({"contractVersion": EXACT_COMMAND_CONTRACT, "sha256": digest}) == digest
