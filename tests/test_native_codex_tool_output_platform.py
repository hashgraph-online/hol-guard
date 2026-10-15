"""The Codex tool-output bridge refuses platforms whose path model it does not carry."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_codex_tool_output as bridge


def test_windows_is_refused_with_a_typed_code_before_any_native_call(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bridge, "_platform_is_supported", lambda: False)

    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("the resident must not be contacted on an unsupported platform")

    monkeypatch.setattr(bridge, "native_runtime_status", forbidden)
    answer = bridge.codex_tool_output_native("read_only_inspection", command="cat src/a.py")
    assert answer.allowed is False
    assert answer.value is None
    assert answer.error_code == "native_codex_tool_output_unsupported_platform"


@pytest.mark.parametrize("value", ["\ud83d", float("nan")])
def test_unencodable_post_tool_body_is_a_typed_denial(monkeypatch: pytest.MonkeyPatch, value: object) -> None:
    features = {bridge._RESIDENT_PROTOCOL_FEATURE, bridge._FEATURE}
    status = SimpleNamespace(
        available=True,
        compatible=True,
        identity=SimpleNamespace(sha256="sha256:test"),
        capabilities=SimpleNamespace(features=features),
    )
    monkeypatch.setattr(bridge, "_platform_is_supported", lambda: True)
    monkeypatch.setattr(bridge, "native_runtime_status", lambda **_kwargs: status)
    monkeypatch.setattr(bridge, "_resolve_digest_home", lambda _home: None)
    monkeypatch.setattr(bridge, "native_runtime_health_snapshot", lambda *_args: SimpleNamespace(circuit_open=False))
    monkeypatch.setattr(bridge, "ensure_resident_prerequisite", lambda _home: True)
    answer = bridge.codex_tool_output_native("post_tool_output", body={"tool_response": value})
    assert answer.allowed is False
    assert answer.error_code == "native_codex_tool_output_invalid"
