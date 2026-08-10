from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_runtime import (
    native_mode,
    native_runtime_status,
    parity_signature,
)
from codex_plugin_scanner.guard.runtime.hook_review_types import HookReviewResponse


def test_native_mode_defaults_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HOL_GUARD_NATIVE", raising=False)
    assert native_mode() == "off"
    assert native_runtime_status().reason == "native_disabled"


def test_invalid_native_mode_fails_to_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOL_GUARD_NATIVE", "unexpected")
    assert native_mode() == "off"


def test_parity_signature_hashes_excerpt() -> None:
    response = HookReviewResponse(
        decision="allow",
        reason="reviewed",
        model_output_action="replace_with_reviewed_excerpt",
        reviewed_excerpt="safe excerpt",
        notice="excerpt",
        reason_code="reviewed_excerpt",
    )
    signature = parity_signature(response)
    assert signature[0] == "allow"
    assert signature[2] == "reviewed_excerpt"
    assert isinstance(signature[-1], str)
    assert "safe excerpt" not in json.dumps(signature)


@pytest.mark.skipif(os.name == "nt", reason="fake executable uses a POSIX shebang")
def test_explicit_shadow_runtime_is_validated_without_path_lookup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binary = tmp_path / "hol-guard-runtime"
    payload = {
        "protocol_version": 1,
        "runtime_version": "0.0",
        "rule_digest": "abc",
        "build_sha": "test",
        "target": "test",
        "features": [],
    }
    binary.write_text(
        "#!/bin/sh\nprintf '%s\\n' '" + json.dumps(payload, separators=(",", ":")) + "'\n",
        encoding="utf-8",
    )
    binary.chmod(0o700)
    monkeypatch.setenv("HOL_GUARD_NATIVE", "shadow")
    monkeypatch.setenv("HOL_GUARD_NATIVE_BINARY", str(binary))
    status = native_runtime_status()
    assert status.available is True
    assert status.compatible is True
    assert status.identity is not None
    assert status.identity.path == binary.resolve()


def test_override_is_ignored_in_auto_mode(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    binary = tmp_path / "hol-guard-runtime"
    binary.write_text("not executable", encoding="utf-8")
    binary.chmod(0o700)
    monkeypatch.setenv("HOL_GUARD_NATIVE", "auto")
    monkeypatch.setenv("HOL_GUARD_NATIVE_BINARY", str(binary))
    status = native_runtime_status()
    assert status.available is False
