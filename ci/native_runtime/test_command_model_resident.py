from __future__ import annotations

import copy
import os
import tempfile
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_command_model import (
    _decode_command_model,
    review_command_model_native,
)
from codex_plugin_scanner.guard.native_runtime import native_runtime_status
from codex_plugin_scanner.guard.native_runtime_resident import (
    close_resident_native_runtimes,
    resident_service_starts,
)

pytestmark = pytest.mark.skipif(os.name == "nt", reason="resident native service is POSIX-only in this wave")

_EXACT_COMMAND = "PATH=/tmp git status --short"
_DECODER_ARGUMENTS = {
    "command": _EXACT_COMMAND,
    "dialect": "posix",
    "transport": "shell_string",
    "extraction_provenance": "guard-shell",
}


def _runtime_from_environment() -> Path:
    value = os.environ.get("HOL_GUARD_NATIVE_BINARY")
    assert value, "HOL_GUARD_NATIVE_BINARY is required for resident integration"
    return Path(value).resolve(strict=True)


def _exact_payload() -> dict[str, object]:
    return {
        "normalized_text": _EXACT_COMMAND,
        "dialect": "posix",
        "transport": "shell_string",
        "extraction_provenance": "guard-shell",
        "wrapper_chain": [],
        "segments": [
            {
                "text": _EXACT_COMMAND,
                "tokens": ["PATH=/tmp", "git", "status", "--short"],
                "executable": "git",
                "arguments": ["status", "--short"],
                "environment_names": ["PATH"],
                "wrapper_chain": [],
                "path_overridden": True,
                "execution_context": "top:0",
                "pipeline_index": 0,
                "span": {"source": "normalized", "start": 0, "end": len(_EXACT_COMMAND)},
            }
        ],
        "confidence": "exact",
        "uncertainty_reason": None,
        "path_overridden": True,
        "parser_profile": "posix-simple-v1",
    }


def test_command_model_decoder_accepts_bound_exact_response() -> None:
    payload = _exact_payload()
    assert _decode_command_model(payload, **_DECODER_ARGUMENTS) == payload


def test_command_model_decoder_binds_response_to_request() -> None:
    for field, value in (
        ("normalized_text", "git status"),
        ("dialect", "cmd"),
        ("transport", "argv"),
        ("extraction_provenance", "untrusted"),
        ("parser_profile", "future-profile"),
    ):
        payload = _exact_payload()
        payload[field] = value
        assert _decode_command_model(payload, **_DECODER_ARGUMENTS) is None, field


def test_command_model_decoder_enforces_confidence_contract() -> None:
    exact_with_reason = _exact_payload()
    exact_with_reason["uncertainty_reason"] = "unexpected"
    assert _decode_command_model(exact_with_reason, **_DECODER_ARGUMENTS) is None

    uncertain_with_segments = _exact_payload()
    uncertain_with_segments["confidence"] = "uncertain"
    uncertain_with_segments["uncertainty_reason"] = "unsupported"
    assert _decode_command_model(uncertain_with_segments, **_DECODER_ARGUMENTS) is None

    valid_uncertain = {
        "normalized_text": "echo $(uname)",
        "dialect": "posix",
        "transport": "shell_string",
        "extraction_provenance": "guard-shell",
        "wrapper_chain": [],
        "segments": [],
        "confidence": "uncertain",
        "uncertainty_reason": "command_substitution_not_yet_supported",
        "path_overridden": False,
        "parser_profile": "posix-simple-v1",
    }
    assert (
        _decode_command_model(
            valid_uncertain,
            command="echo $(uname)",
            dialect="posix",
            transport="shell_string",
            extraction_provenance="guard-shell",
        )
        == valid_uncertain
    )


def test_command_model_decoder_rejects_inconsistent_segments() -> None:
    mutations: tuple[tuple[str, object], ...] = (
        ("span", {"source": "normalized", "start": 0, "end": len(_EXACT_COMMAND) + 1}),
        ("text", "git status"),
        ("tokens", ["PATH=/tmp", "git", "status"]),
        ("executable", "status"),
        ("arguments", ["--short"]),
        ("environment_names", []),
        ("path_overridden", False),
        ("execution_context", "top:1"),
        ("pipeline_index", True),
    )
    for field, value in mutations:
        payload = copy.deepcopy(_exact_payload())
        segments = payload["segments"]
        assert isinstance(segments, list)
        segment = segments[0]
        assert isinstance(segment, dict)
        segment[field] = value
        assert _decode_command_model(payload, **_DECODER_ARGUMENTS) is None, field

    aggregate_mismatch = _exact_payload()
    aggregate_mismatch["path_overridden"] = False
    assert _decode_command_model(aggregate_mismatch, **_DECODER_ARGUMENTS) is None


def test_command_model_reuses_version_matched_resident_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = _runtime_from_environment()
    monkeypatch.setenv("HOL_GUARD_NATIVE", "force")
    close_resident_native_runtimes()
    with tempfile.TemporaryDirectory(prefix="hgr-", dir="/tmp") as short_tmp:
        guard_home = Path(short_tmp) / "guard-home"
        guard_home.mkdir(mode=0o700)
        try:
            first = review_command_model_native("git status --short", guard_home=guard_home)
            second = review_command_model_native("printf 'a|b' | grep b", guard_home=guard_home)
            assert first is not None
            assert first["confidence"] == "exact"
            assert first["segments"][0]["executable"] == "git"
            assert second is not None
            assert second["confidence"] == "exact"
            assert [segment["pipeline_index"] for segment in second["segments"]] == [0, 1]

            status = native_runtime_status()
            assert status.identity is not None
            assert status.capabilities is not None
            assert "resident-command-model-shadow-v1" in status.capabilities.features
            assert (
                resident_service_starts(
                    executable=runtime,
                    identity_sha256=status.identity.sha256,
                    guard_home=guard_home,
                )
                == 1
            )
        finally:
            close_resident_native_runtimes()


def test_complex_command_remains_non_authoritative(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)
    monkeypatch.setenv("HOL_GUARD_NATIVE", "force")
    close_resident_native_runtimes()
    try:
        model = review_command_model_native("echo $(uname) > out.txt", guard_home=guard_home)
        assert model is not None
        assert model["confidence"] == "uncertain"
        assert model["segments"] == []
        assert model["uncertainty_reason"]
    finally:
        close_resident_native_runtimes()


def test_command_model_bridge_is_disabled_by_default(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)
    monkeypatch.delenv("HOL_GUARD_NATIVE", raising=False)
    assert review_command_model_native("git status", guard_home=guard_home) is None
