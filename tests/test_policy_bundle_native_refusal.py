"""A framed resident refusal keeps its own code instead of reading as a schema mismatch."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_policy_bundle as bridge
from codex_plugin_scanner.guard.native_policy_bundle import PolicyBundleNativeUnavailableError


def _serve(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, frame: object) -> None:
    status = SimpleNamespace(
        available=True,
        compatible=True,
        identity=SimpleNamespace(sha256="a" * 64, path=str(tmp_path / "runtime")),
        capabilities=SimpleNamespace(features=(bridge._RESIDENT_PROTOCOL_FEATURE, bridge._FEATURE)),
    )
    monkeypatch.setattr(bridge, "native_runtime_status", lambda **_kwargs: status)
    monkeypatch.setattr(bridge, "_resolve_digest_home", lambda _home: tmp_path)
    monkeypatch.setattr(bridge, "ensure_resident_prerequisite", lambda _home: True)
    monkeypatch.setattr(bridge, "native_resident_client_request", lambda **_kwargs: json.dumps(frame).encode())


@pytest.mark.parametrize(
    ("frame", "expected"),
    (
        ({"error": "native_resident_update_in_progress", "retryable": False}, "native_resident_update_in_progress"),
        ({"error": "not-a-finite-code", "retryable": False}, bridge._SCHEMA_MISMATCH),
        ({"error": "native_resident_update_in_progress"}, bridge._SCHEMA_MISMATCH),
        ({"error": "native_resident_update_in_progress", "retryable": "no"}, bridge._SCHEMA_MISMATCH),
    ),
)
def test_framed_refusal_keeps_only_a_finite_code(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    frame: dict[str, object],
    expected: str,
) -> None:
    _serve(monkeypatch, tmp_path, frame)
    with pytest.raises(PolicyBundleNativeUnavailableError) as raised:
        bridge.native_policy_bundle("verify", {})
    assert raised.value.code == expected
