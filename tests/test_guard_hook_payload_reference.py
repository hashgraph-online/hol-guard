"""Tests for generic hook payload reference metadata validation.

Hydration/decryption is retired: the Rust edge rejects ``guard_payload_ref``
payloads outright (``native_hook_encrypted_payload_unsupported``), covered by
``rust/crates/guard-runtime/src/edge_tests.rs``. Where the referenced file is
allowed to live is a runtime verdict now, checked in
``rust/crates/guard-runtime/src/hook_path_rules_tests.rs``. The surviving
Python surface is the control-plane metadata validation that runs before the
daemon asks the runtime anything.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.hook_request_parsing import (
    HookPayloadReferenceError,
    hook_payload_reference_size,
    payload_kind,
)


def test_hook_payload_reference_size_ignores_inline_payloads(tmp_path: Path) -> None:
    assert hook_payload_reference_size({"tool_response": "x"}, guard_home=tmp_path) is None
    assert hook_payload_reference_size({"guard_payload_ref": "not-an-object"}, guard_home=tmp_path) is None


def test_hook_payload_reference_classifies_encrypted_ref_kind() -> None:
    assert payload_kind({"guard_payload_ref": {"version": 1}}) == "encrypted_payload_ref"


def test_hook_payload_reference_rejects_bad_digest(tmp_path: Path) -> None:
    ref = {"version": 1, "path": str(tmp_path / "payload.json"), "sha256": "not-a-digest"}
    with pytest.raises(HookPayloadReferenceError):
        _ = hook_payload_reference_size({"guard_payload_ref": ref}, guard_home=tmp_path)


def test_hook_payload_reference_rejects_missing_metadata(tmp_path: Path) -> None:
    with pytest.raises(HookPayloadReferenceError):
        _ = hook_payload_reference_size({"guard_payload_ref": {"version": 1}}, guard_home=tmp_path)
