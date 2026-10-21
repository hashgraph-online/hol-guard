"""A native phase MAC cannot stand in for an installed, retained source."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_business_source_anchor_bridge as anchors
from codex_plugin_scanner.guard import native_business_source_bridge as sources
from codex_plugin_scanner.guard import native_runtime
from codex_plugin_scanner.guard.native_business_document_compile import compile_business_policy_document
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
from codex_plugin_scanner.guard.policy_document import canonical_json_bytes
from tests.test_native_business_document_compile import document


@pytest.mark.parametrize("phase,revision", [("closed", 0), ("committed", 0), ("closed", 1), ("committed", 1)])
def test_native_phase_marker_binds_minimal_exact_identity(native_hook_force: Path, phase: str, revision: int) -> None:
    candidate = compile_business_policy_document(document(revision))
    source = sources.build_business_source_record(candidate, b"s" * 32, 1)
    marker = anchors.build_business_source_anchor(source, b"s" * 32, phase)
    verified = anchors.verify_business_source_anchor(marker.anchor_bytes, b"s" * 32)
    assert verified == marker
    assert marker.phase == phase
    assert marker.retained_identity_bytes == source.retained_identity_bytes
    assert json.loads(marker.retained_identity_bytes)["source_revision"] == revision
    assert not marker.anchor_bytes.endswith(b"\n")
    assert len(marker.anchor_bytes) <= anchors.MAX_ANCHOR_BYTES
    assert b"source_document" not in marker.anchor_bytes
    assert b"Source fixture" not in marker.anchor_bytes
    assert not hasattr(marker, "installed") and not hasattr(marker, "approval")


def test_native_verifier_rejects_changed_phase(native_hook_force: Path) -> None:
    source = sources.build_business_source_record(compile_business_policy_document(document()), b"s" * 32, 1)
    marker = anchors.build_business_source_anchor(source, b"s" * 32, "closed")
    altered = json.loads(marker.anchor_bytes)
    altered["phase"] = "committed"
    with pytest.raises(NativePolicySnapshotError, match="native_business_source_codec_refused"):
        anchors.verify_business_source_anchor(canonical_json_bytes(altered), b"s" * 32)


def test_source_record_cannot_be_rebound_to_another_key(native_hook_force: Path) -> None:
    source = sources.build_business_source_record(compile_business_policy_document(document()), b"s" * 32, 1)
    with pytest.raises(NativePolicySnapshotError, match="native_business_source_codec_refused"):
        anchors.build_business_source_anchor(source, b"t" * 32, "committed")


def test_consumer_without_marker_capability_never_receives_key(monkeypatch: pytest.MonkeyPatch) -> None:
    old = SimpleNamespace(
        available=True,
        compatible=True,
        identity=SimpleNamespace(path=Path("unused")),
        capabilities=SimpleNamespace(features=tuple(sources._REQUIRED)),
    )
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda **kwargs: old)
    monkeypatch.setattr(native_runtime, "_run_native_process", lambda *args, **kwargs: pytest.fail("marker key sent"))
    with pytest.raises(NativePolicySnapshotError, match="native_business_source_consumer_unavailable"):
        anchors.verify_business_source_anchor(b"{}", b"s" * 32)
