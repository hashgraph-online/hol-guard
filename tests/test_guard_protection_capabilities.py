"""Harness protection capability contract."""

from __future__ import annotations

from codex_plugin_scanner.guard.adapters.contracts import HARNESS_CONTRACTS
from codex_plugin_scanner.guard.protection_capabilities import (
    capability_for,
    protection_capability_payloads,
)


def test_every_supported_harness_has_a_protection_capability() -> None:
    missing = [contract.harness for contract in HARNESS_CONTRACTS if capability_for(contract.harness) is None]
    assert missing == []


def test_fail_open_harnesses_are_marked_limited() -> None:
    for harness in ("grok", "kimi", "zcode", "pi", "omp"):
        capability = capability_for(harness)
        assert capability is not None
        payload = capability.to_dict()
        assert payload["fail_open_on_hook_failure"] is True
        assert payload["can_ask_inline"] is False
        assert payload["limited"] is True
        sentence = str(payload["honesty_sentence"])
        assert "cannot ask in chat" in sentence
        assert "If Guard is down" in sentence


def test_codex_can_ask_inline_without_claiming_native_remember() -> None:
    capability = capability_for("codex")
    assert capability is not None
    payload = capability.to_dict()
    assert payload["can_pre_block"] is True
    assert payload["can_ask_inline"] is True
    assert payload["has_native_remember"] is False
    assert payload["fail_open_on_hook_failure"] is False
    assert payload["honesty_sentence"] == "Codex asks in chat, then remembers."


def test_cursor_uses_native_prompt_honesty() -> None:
    capability = capability_for("cursor")
    assert capability is not None
    assert capability.to_dict()["honesty_sentence"] == "Cursor uses this app's prompt when it can."


def test_capability_payloads_cover_contracted_harnesses() -> None:
    harnesses = {item["harness"] for item in protection_capability_payloads()}
    assert harnesses == {contract.harness for contract in HARNESS_CONTRACTS}
