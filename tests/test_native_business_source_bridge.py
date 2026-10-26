"""Native source MAC transport is separate from approval and installation."""

import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_business_source_bridge as bridge
from codex_plugin_scanner.guard import native_runtime
from codex_plugin_scanner.guard.native_business_document_compile import (
    COMPILE_CAPABILITY,
    compile_business_policy_document,
)
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
from codex_plugin_scanner.guard.policy_document import canonical_json_bytes
from tests.test_native_business_document_compile import document


def test_real_source_codec_retains_whole_document_and_owned_identity(native_hook_force: Path) -> None:
    candidate = compile_business_policy_document(document())
    built = bridge.build_business_source_record(candidate, b"s" * 32, 1)
    assert not built.record_bytes.endswith(b"\n")
    verified = bridge.verify_business_source_record(built.record_bytes, b"s" * 32)
    assert built == verified
    record = json.loads(built.record_bytes)
    assert canonical_json_bytes(record["source_document"]) == candidate.source_bytes
    assert record["import_mode"] == "replace" and "verifier_key" not in record
    assert built.source_digest == candidate.source_digest
    assert built.binding_bytes == candidate.binding_bytes
    assert json.loads(built.retained_identity_bytes)["source_revision"] == 1
    assert not hasattr(built, "installed") and not hasattr(built, "approval")
    assert candidate.source_bytes.decode() not in repr(built)


@pytest.mark.parametrize("case", ["wrong-key", "tampered-source"])
def test_native_source_verifier_refuses_wrong_origin_or_changed_body(native_hook_force: Path, case: str) -> None:
    candidate = compile_business_policy_document(document())
    built = bridge.build_business_source_record(candidate, b"s" * 32, 1)
    record = built.record_bytes
    key = b"t" * 32 if case == "wrong-key" else b"s" * 32
    if case == "tampered-source":
        value = json.loads(record)
        value["source_document"]["metadata"]["name"] = "private-changed-marker"
        record = canonical_json_bytes(value)
    with pytest.raises(NativePolicySnapshotError, match="native_business_source_codec_refused") as failure:
        bridge.verify_business_source_record(record, key)
    assert "private-changed-marker" not in str(failure.value)


def test_candidate_identity_cannot_substitute_for_actual_source(native_hook_force: Path) -> None:
    candidate = compile_business_policy_document(document())
    candidate = replace(candidate, source_digest="f" * 64)
    with pytest.raises(NativePolicySnapshotError, match="native_business_source_codec_response_invalid"):
        bridge.build_business_source_record(candidate, b"s" * 32, 1)


def test_old_consumer_receives_neither_source_nor_key(monkeypatch: pytest.MonkeyPatch) -> None:
    old = SimpleNamespace(
        available=True,
        compatible=True,
        identity=SimpleNamespace(path=Path("unused")),
        capabilities=SimpleNamespace(features=(COMPILE_CAPABILITY, "native-business-policy-retained-floor-v1")),
    )
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda **kwargs: old)
    monkeypatch.setattr(
        native_runtime, "_run_native_process", lambda *args, **kwargs: pytest.fail("key crossed old boundary")
    )
    with pytest.raises(NativePolicySnapshotError, match="native_business_source_consumer_unavailable"):
        bridge.verify_business_source_record(b"{}", b"s" * 32)


def test_failed_constructor_drops_owned_key_references(monkeypatch: pytest.MonkeyPatch) -> None:
    status = SimpleNamespace(identity=SimpleNamespace(path=Path("unused")))
    payload = {"schema": "guard.business-source-build.v1"}
    captured = []

    def fail(*args, **kwargs):
        captured.append(payload["verifier_key"])
        raise RuntimeError("synthetic-process-failure")

    monkeypatch.setattr(native_runtime, "_run_native_process", fail)
    with pytest.raises(RuntimeError, match="synthetic-process-failure"):
        bridge._operation(status, "business-source-build", payload, b"s" * 32, bridge._deadline(None))
    assert "verifier_key" not in payload
    assert captured == [[]]


def test_invalid_record_encoding_uses_finite_diagnostic(monkeypatch: pytest.MonkeyPatch) -> None:
    status = SimpleNamespace(
        available=True,
        compatible=True,
        identity=SimpleNamespace(path=Path("unused")),
        capabilities=SimpleNamespace(features=tuple(bridge._REQUIRED)),
    )
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda **kwargs: status)
    monkeypatch.setattr(
        native_runtime, "_run_native_process", lambda *args, **kwargs: pytest.fail("invalid input sent")
    )
    with pytest.raises(NativePolicySnapshotError, match="native_business_source_codec_response_invalid"):
        bridge.verify_business_source_record(b"\xffprivate-marker", b"s" * 32)
