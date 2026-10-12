"""The Codex tool-output bridge refuses platforms whose path model it does not carry."""

from __future__ import annotations

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
