from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import NoReturn

import pytest

from codex_plugin_scanner.guard.codex_hook_file_integrity import CodexHookIntegrityError, validate_regular_file
from codex_plugin_scanner.guard.config_source_io import GuardConfigSourceError, capture_guard_config
from scripts import native_slo_failure as failures
from scripts.native_slo_failure import FixtureFailureError, failure_evidence


def test_corpus_failure_names_fixture_and_field_without_output() -> None:
    result = failure_evidence(
        AssertionError("native_qualification_mismatch:codex/PostToolUse/block/1k:field:reason_code")
    )
    assert result["reason"] == "native_qualification_mismatch"
    assert result["case"] == "codex.PostToolUse.block.1k"
    assert result["field"] == "field:reason_code"


def test_unstructured_errors_do_not_publish_paths_or_data() -> None:
    for error in (OSError("/home/someone/private-dump.txt"), RuntimeError("response included ghp_live_credential")):
        result = failure_evidence(error)
        assert result["reason"] == "unclassified_failure"
        assert str(error) not in json.dumps(result)
        digest = result["diagnostic_digest"]
        assert isinstance(digest, str) and len(digest) == 64


def test_remote_fixture_failure_preserves_coarse_diagnostics() -> None:
    detail = failure_evidence(OSError(13, "/home/someone/private-data"))
    result = failure_evidence(FixtureFailureError(detail))
    assert result["errno"] == 13
    assert result["category"] == "PermissionError"
    assert result["reason"] == "qualification_fixture.unclassified_failure"
    assert "/home" not in json.dumps(result)


def test_malformed_corpus_detail_cannot_disclose_response_body() -> None:
    result = failure_evidence(AssertionError("native_qualification_mismatch:safe.case:/home/private-data"))
    assert result["reason"] == "unclassified_failure"


@pytest.mark.skipif(os.name == "nt", reason="POSIX interpreter permission contract")
def test_actual_unsafe_interpreter_failure_is_identified_without_permission_or_byte_repairs(tmp_path, monkeypatch):
    interpreter = tmp_path / "private_identity_marker"
    interpreter.write_bytes(b"diagnostic fixture never executed\n")
    interpreter.chmod(0o777)
    before = interpreter.read_bytes(), interpreter.stat()
    monkeypatch.setattr(failures.sys, "executable", str(interpreter))
    with pytest.raises(CodexHookIntegrityError) as error:
        validate_regular_file(interpreter, role="interpreter", executable_required=True)
    detail = json.loads(json.dumps(failure_evidence(error.value)))
    assert detail["reason"] == "codex_hook_interpreter_permissions_unsafe"
    # This is the exact diagnostic digest retained by ae Linux baseline CI.
    assert detail["diagnostic_digest"] == "3a7dada600dc5f78680385a54e01c8ce4ac4c14b77c2cca25d22f2ada6fc1222"
    assert detail["interpreter_mode"] == 0o777
    assert detail["interpreter_world_writable"] is detail["interpreter_group_writable"] is True
    assert detail["interpreter_owner_current"] is True
    assert detail["interpreter_metadata_phase"] == "after_integrity_rejection"
    assert interpreter.read_bytes() == before[0]
    assert stat.S_IMODE(interpreter.stat().st_mode) == stat.S_IMODE(before[1].st_mode)
    assert interpreter.stat().st_ino == before[1].st_ino
    assert "private_identity_marker" not in json.dumps(detail)


def test_unknown_integrity_reason_is_digest_only_and_does_not_read_interpreter(monkeypatch):
    error = CodexHookIntegrityError("codex_hook_private_identity_marker_permissions_unsafe", "private_identity_marker")
    monkeypatch.setattr(
        failures, "_interpreter_failure_metadata", lambda: pytest.fail("unknown reasons cannot trigger inspection")
    )
    detail = failure_evidence(error)
    assert detail["reason"] == "unclassified_failure"
    assert detail["diagnostic_digest"] == hashlib.sha256(str(error).encode()).hexdigest()
    assert "private_identity_marker" not in json.dumps(detail)


def test_actual_config_capture_retains_wrapped_io_cause_without_private_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard import config_source_io

    path = tmp_path / "config.toml"
    original = b'default_action = "block"\n'
    path.write_bytes(original)
    cause = OSError(32, "private_marker C:\\fixture\\private-file.toml")

    def fail_read(*_args: object) -> NoReturn:
        raise cause

    monkeypatch.setattr(config_source_io, "_read_descriptor", fail_read)
    with pytest.raises(GuardConfigSourceError) as caught:
        _ = capture_guard_config(path)
    assert caught.value.__cause__ is cause
    detail = failure_evidence(caught.value)
    assert detail["category"] == "GuardConfigSourceError"
    assert detail["reason"] == "unclassified_failure"
    assert detail["diagnostic_digest"] == "0738075fe78c3c3f3717ba62fdb3e78611bf0bad995eb513d0e7d83e87c730dc"
    assert detail["config_cause_count"] == 1
    assert detail["config_cause_1_category"] == type(cause).__name__
    assert detail["config_cause_1_errno"] == 32
    assert detail["config_cause_1_origin"] == "config_source_io._capture_in_parent"
    assert "private_marker" not in json.dumps(detail)
    assert path.read_bytes() == original
    forwarded = failure_evidence(FixtureFailureError(detail))
    assert forwarded == {**detail, "reason": "qualification_fixture.unclassified_failure"}


def test_configuration_cause_evidence_is_bounded_and_retains_numeric_windows_error() -> None:
    error = GuardConfigSourceError("guard_config_source_unavailable")
    cause = OSError(13, "private_marker")
    cause.winerror = 32
    error.__cause__ = cause
    detail = failure_evidence(error)
    assert detail["config_cause_1_winerror"] == 32
    assert detail["config_cause_1_errno"] == 13
    assert "private_marker" not in json.dumps(detail)


def test_configuration_cause_collection_never_consults_custom_exception_callbacks() -> None:
    class HostileError(OSError):
        def __getattribute__(self, _name: str) -> NoReturn:
            pytest.fail("custom cause attribute must not be read")

        def __str__(self) -> NoReturn:
            pytest.fail("custom cause message must not be formatted")

    error = GuardConfigSourceError("guard_config_source_unavailable")
    error.__cause__ = HostileError("private_marker")
    detail = failure_evidence(error)
    assert detail["config_cause_count"] == 1
    assert detail["config_cause_1_category"] == "unclassified"
    assert detail["config_cause_unavailable"] is True
    assert "private_marker" not in json.dumps(detail)


def test_configuration_cause_collection_preserves_suppression_and_bounds_cycles() -> None:
    error = GuardConfigSourceError("guard_config_source_unavailable")
    error.__context__ = OSError(13, "private_marker")
    error.__suppress_context__ = True
    assert failure_evidence(error)["config_cause_count"] == 0
    error.__cause__ = error
    detail = failure_evidence(error)
    assert detail["config_cause_cycle"] is True
    assert detail["config_cause_count"] == 0


def test_configuration_cause_collection_stops_after_three_explicit_links() -> None:
    error = GuardConfigSourceError("guard_config_source_unavailable")
    previous: Exception = error
    for _index in range(4):
        current = RuntimeError("private_marker")
        previous.__cause__ = current
        previous = current
    detail = failure_evidence(error)
    assert detail["config_cause_count"] == 3
    assert detail["config_cause_truncated"] is True
    assert not any(key.startswith("config_cause_4_") for key in detail)
    wrapped = {"runs": [{"arms": [{"failure": detail}]}]}
    assert failures.assert_privacy_safe(wrapped) == wrapped


def test_optional_configuration_diagnostic_failure_keeps_primary_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    error = GuardConfigSourceError("guard_config_source_unavailable")

    def fail_diagnostic(_error: Exception) -> NoReturn:
        raise RuntimeError("private_marker")

    monkeypatch.setattr(failures, "_configuration_failure_metadata", fail_diagnostic)
    detail = failure_evidence(error)
    assert detail["category"] == "GuardConfigSourceError"
    assert detail["reason"] == "unclassified_failure"
    assert detail["config_diagnostic_available"] is False
    assert "private_marker" not in json.dumps(detail)
