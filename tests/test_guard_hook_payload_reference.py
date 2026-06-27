"""Tests for generic hook payload references."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from base64 import urlsafe_b64encode
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from codex_plugin_scanner.guard.cli.commands_support_hook_payload import _load_hook_payload
from codex_plugin_scanner.guard.cli.commands_support_runtime_artifacts import _codex_post_tool_output_artifact
from codex_plugin_scanner.guard.runtime.hook_payload_reference import HookPayloadReferenceError


def _b64url(value: bytes) -> str:
    return urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _referenced_input(payload: dict[str, object], reference_dir: Path, *, sha256: str | None = None) -> str:
    raw_payload = json.dumps(payload).encode("utf-8")
    key = os.urandom(32)
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, raw_payload, None)
    reference_path = reference_dir / "payload.json"
    reference_path.write_bytes(ciphertext)
    return json.dumps(
        {
            "hook_event_name": payload.get("hook_event_name"),
            "tool_name": payload.get("tool_name"),
            "guard_payload_ref": {
                "version": 1,
                "path": str(reference_path),
                "sha256": sha256 or hashlib.sha256(ciphertext).hexdigest(),
                "encoding": "json",
                "encryption": "aes-256-gcm",
                "key": _b64url(key),
                "nonce": _b64url(nonce),
            },
        }
    )


def test_hook_payload_reference_hydrates_full_payload_for_runtime_review(tmp_path: Path) -> None:
    secret_path = tmp_path / ".npmrc"
    secret_line = "//registry.npmjs.org/:" + "_authToken=npm_" + "abcdefghijklmnopqrstuvwxyz012345"
    full_output = ("markdown context\n" * 2500) + secret_line
    full_payload = {
        "hook_event_name": "PostToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": str(secret_path)},
        "tool_response": [{"type": "text", "text": full_output}],
        "stdout": full_output[:12_000],
    }

    with tempfile.TemporaryDirectory(prefix="hol-guard-hook-payload-") as reference_dir:
        loaded_payload = _load_hook_payload(
            None,
            input_text=_referenced_input(full_payload, Path(reference_dir)),
            harness="pi",
        )

    assert loaded_payload["tool_response"] == full_payload["tool_response"]
    artifact = _codex_post_tool_output_artifact(
        harness="pi",
        payload=loaded_payload,
        config_path="~/.pi/agent/settings.json",
        source_scope="project",
        cwd=tmp_path,
        home_dir=tmp_path,
    )
    assert artifact is not None
    assert artifact.harness == "pi"


def test_hook_payload_reference_rejects_digest_mismatch() -> None:
    payload = {"hook_event_name": "PostToolUse", "tool_name": "Read", "tool_response": []}

    with (
        pytest.raises(HookPayloadReferenceError, match="digest mismatch"),
        tempfile.TemporaryDirectory(prefix="hol-guard-hook-payload-") as reference_dir,
    ):
        _load_hook_payload(
            None,
            input_text=_referenced_input(payload, Path(reference_dir), sha256="0" * 64),
            harness="pi",
        )


def test_reject_path_outside_temp_root(tmp_path: Path) -> None:
    payload = {"hook_event_name": "PostToolUse", "tool_name": "Read", "tool_response": []}
    with pytest.raises(HookPayloadReferenceError, match="Guard-owned temp directory"):
        _load_hook_payload(
            None,
            input_text=_referenced_input(payload, tmp_path),
            harness="pi",
        )


def test_reject_wrong_prefix_temp_dir() -> None:
    payload = {"hook_event_name": "PostToolUse", "tool_name": "Read", "tool_response": []}
    with (
        pytest.raises(HookPayloadReferenceError, match="Guard-owned temp directory"),
        tempfile.TemporaryDirectory(prefix="wrong-prefix-") as reference_dir,
    ):
        _load_hook_payload(
            None,
            input_text=_referenced_input(payload, Path(reference_dir)),
            harness="pi",
        )


def test_reject_directory_instead_of_file() -> None:
    with (
        pytest.raises(HookPayloadReferenceError, match="must be a file"),
        tempfile.TemporaryDirectory(prefix="hol-guard-hook-payload-") as reference_dir,
    ):
        directory_path = Path(reference_dir) / "payload.json"
        directory_path.mkdir()
        ref = {
            "guard_payload_ref": {
                "version": 1,
                "path": str(directory_path),
                "sha256": "0" * 64,
                "encoding": "json",
                "encryption": "aes-256-gcm",
                "key": _b64url(os.urandom(32)),
                "nonce": _b64url(os.urandom(12)),
            },
        }
        _load_hook_payload(None, input_text=json.dumps(ref), harness="pi")


def test_reject_payload_over_5mb() -> None:
    with (
        pytest.raises(HookPayloadReferenceError, match="exceeds the safe local size limit"),
        tempfile.TemporaryDirectory(prefix="hol-guard-hook-payload-") as reference_dir,
    ):
        ref_path = Path(reference_dir) / "payload.json"
        ref_path.write_bytes(bytes(5 * 1024 * 1024 + 1))
        ref = {
            "guard_payload_ref": {
                "version": 1,
                "path": str(ref_path),
                "sha256": "0" * 64,
                "encoding": "json",
                "encryption": "aes-256-gcm",
                "key": _b64url(os.urandom(32)),
                "nonce": _b64url(os.urandom(12)),
            },
        }
        _load_hook_payload(None, input_text=json.dumps(ref), harness="pi")


def test_reject_invalid_aes_key_length() -> None:
    payload = {"hook_event_name": "PostToolUse", "tool_name": "Read", "tool_response": []}
    with (
        pytest.raises(HookPayloadReferenceError, match="invalid encryption key"),
        tempfile.TemporaryDirectory(prefix="hol-guard-hook-payload-") as reference_dir,
    ):
        ref = json.loads(_referenced_input(payload, Path(reference_dir)))
        ref["guard_payload_ref"]["key"] = _b64url(os.urandom(16))
        _load_hook_payload(None, input_text=json.dumps(ref), harness="pi")


def test_reject_invalid_nonce_length() -> None:
    payload = {"hook_event_name": "PostToolUse", "tool_name": "Read", "tool_response": []}
    with (
        pytest.raises(HookPayloadReferenceError, match="invalid encryption nonce"),
        tempfile.TemporaryDirectory(prefix="hol-guard-hook-payload-") as reference_dir,
    ):
        ref = json.loads(_referenced_input(payload, Path(reference_dir)))
        ref["guard_payload_ref"]["nonce"] = _b64url(os.urandom(8))
        _load_hook_payload(None, input_text=json.dumps(ref), harness="pi")


def test_reject_decrypted_json_list() -> None:
    with (
        pytest.raises(HookPayloadReferenceError, match="must contain a JSON object"),
        tempfile.TemporaryDirectory(prefix="hol-guard-hook-payload-") as reference_dir,
    ):
        key = os.urandom(32)
        nonce = os.urandom(12)
        ciphertext = AESGCM(key).encrypt(nonce, json.dumps([1, 2, 3]).encode("utf-8"), None)
        ref_path = Path(reference_dir) / "payload.json"
        ref_path.write_bytes(ciphertext)
        ref = {
            "guard_payload_ref": {
                "version": 1,
                "path": str(ref_path),
                "sha256": hashlib.sha256(ciphertext).hexdigest(),
                "encoding": "json",
                "encryption": "aes-256-gcm",
                "key": _b64url(key),
                "nonce": _b64url(nonce),
            },
        }
        _load_hook_payload(None, input_text=json.dumps(ref), harness="pi")
