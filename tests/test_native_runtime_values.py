"""Malformed artifact metadata cannot become a validated runtime identity."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_runtime as bridge
from codex_plugin_scanner.guard import native_runtime_values as values


def _manifest() -> dict[str, object]:
    return {
        "schema": "hol-guard-native-runtime.v1",
        "protocol_version": 1,
        "package_version": "3.16.0",
        "target": "x86_64-unknown-linux-musl",
        "platform_tag": "musllinux_1_2_x86_64",
        "source_sha": "a" * 40,
        "rule_digest": "b" * 64,
        "runtime_sha256": "c" * 64,
        "runtime_size": 123,
    }


def test_bridge_decoder_returns_the_exported_manifest_type() -> None:
    decoded = bridge._decode_runtime_manifest(_manifest())
    assert isinstance(decoded, bridge.NativeRuntimeManifest)
    assert bridge.NativeRuntimeManifest is values.NativeRuntimeManifest
    assert decoded.source_sha == "a" * 40
    assert decoded.runtime_sha256 == "c" * 64
    assert decoded.runtime_size == 123


@pytest.mark.parametrize("payload", [None, [], "manifest"])
def test_manifest_decoder_rejects_nonobjects(payload: object) -> None:
    assert bridge._decode_runtime_manifest(payload) is None


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("schema", None),
        ("schema", "unknown"),
        ("protocol_version", "1"),
        ("protocol_version", 1.0),
        ("protocol_version", 2),
        ("package_version", None),
        ("package_version", " "),
        ("target", None),
        ("target", ""),
        ("platform_tag", None),
        ("platform_tag", " "),
        ("source_sha", None),
        ("source_sha", "a" * 39),
        ("source_sha", "A" * 40),
        ("rule_digest", None),
        ("rule_digest", "b" * 63),
        ("rule_digest", "g" * 64),
        ("runtime_sha256", None),
        ("runtime_sha256", "c" * 63),
        ("runtime_size", 0),
        ("runtime_size", -1),
        ("runtime_size", True),
        ("runtime_size", 1.5),
    ],
)
def test_manifest_decoder_rejects_invalid_identity_fields(field: str, invalid: object) -> None:
    payload = _manifest()
    payload[field] = invalid
    assert bridge._decode_runtime_manifest(payload) is None


@pytest.mark.parametrize("payload", [None, [], "capabilities", {}, {"protocol_version": "1"}])
def test_capabilities_decoder_rejects_malformed_envelopes(payload: object) -> None:
    assert values._decode_capabilities(payload) is None


def test_capabilities_decoder_rejects_nonstring_features() -> None:
    payload = {
        "protocol_version": 1,
        "runtime_version": "3.16.0",
        "rule_digest": "b" * 64,
        "build_sha": "a" * 40,
        "target": "x86_64-linux",
        "features": ["resident-protocol-v2", 1],
    }
    assert values._decode_capabilities(payload) is None


def test_health_identity_uses_the_artifact_digest_or_unavailable_sentinel() -> None:
    unavailable = bridge.NativeRuntimeStatus("auto", False, False, "native_unavailable")
    assert bridge._identity_key(unavailable) == "0" * 64
    identity = bridge.NativeRuntimeIdentity(Path("/runtime-fixture"), 123, 1, "c" * 64)
    ready = bridge.NativeRuntimeStatus("auto", True, True, "native_ready", identity=identity)
    assert bridge._identity_key(ready) == identity.sha256


def test_missing_package_metadata_stays_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing(_name: str) -> str:
        raise values.importlib.metadata.PackageNotFoundError("hol-guard")

    bridge._python_package_version.cache_clear()
    monkeypatch.setattr(values.importlib.metadata, "version", missing)
    try:
        assert bridge._python_package_version() is None
    finally:
        bridge._python_package_version.cache_clear()
