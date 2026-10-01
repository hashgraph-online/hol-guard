"""Tests for generic hook payload reference metadata validation.

Hydration/decryption is retired: the Rust edge rejects ``guard_payload_ref``
payloads outright (``native_hook_encrypted_payload_unsupported``), covered by
``rust/crates/guard-runtime/src/edge_tests.rs``. The surviving Python surface
is the control-plane metadata/size validation in ``hook_request_parsing``.
"""

from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.hook_request_parsing import (
    _REFERENCE_DIR_PREFIX,
    MAX_HOOK_PAYLOAD_REFERENCE_BYTES,
    HookPayloadReferenceError,
    hook_payload_reference_size,
    payload_kind,
)


def _reference_dir() -> tempfile.TemporaryDirectory[str]:
    return tempfile.TemporaryDirectory(prefix=_REFERENCE_DIR_PREFIX)


def _reference(path: Path, data: bytes) -> dict[str, object]:
    path.write_bytes(data)
    return {
        "version": 1,
        "path": str(path),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def test_hook_payload_reference_reports_bounded_bytes() -> None:
    with _reference_dir() as directory:
        ref = _reference(Path(directory) / "payload.json", b"{}")
        assert hook_payload_reference_size({"guard_payload_ref": ref}) == MAX_HOOK_PAYLOAD_REFERENCE_BYTES


def test_hook_payload_reference_size_ignores_inline_payloads() -> None:
    assert hook_payload_reference_size({"tool_response": "x"}) is None
    assert hook_payload_reference_size({"guard_payload_ref": "not-an-object"}) is None


def test_hook_payload_reference_classifies_encrypted_ref_kind() -> None:
    assert payload_kind({"guard_payload_ref": {"version": 1}}) == "encrypted_payload_ref"


def test_hook_payload_reference_rejects_bad_digest() -> None:
    with _reference_dir() as directory:
        ref = _reference(Path(directory) / "payload.json", b"{}")
        ref["sha256"] = "not-a-digest"
        with pytest.raises(HookPayloadReferenceError):
            hook_payload_reference_size({"guard_payload_ref": ref})


def test_hook_payload_reference_rejects_path_outside_temp_root(tmp_path: Path) -> None:
    ref = _reference(tmp_path / "payload.json", b"{}")
    with pytest.raises(HookPayloadReferenceError):
        hook_payload_reference_size({"guard_payload_ref": ref})


def test_hook_payload_reference_rejects_missing_metadata() -> None:
    with pytest.raises(HookPayloadReferenceError):
        hook_payload_reference_size({"guard_payload_ref": {"version": 1}})
