"""Pi managed-extension request-correlation contract tests."""

from pathlib import Path

from codex_plugin_scanner.guard.adapters.pi_extension_source import managed_extension_source


def _managed_source(tmp_path: Path) -> str:
    return managed_extension_source(
        guard_home=tmp_path / "guard-home",
        home_dir=tmp_path / "home",
        settings_path=tmp_path / "home" / ".pi" / "agent" / "settings.json",
    )


def test_pi_pre_tool_payload_forwards_native_tool_call_id(tmp_path: Path) -> None:
    source = _managed_source(tmp_path)

    assert "tool_call_id: typedEvent.toolCallId," in source


def test_pi_post_tool_payload_forwards_native_tool_call_id(tmp_path: Path) -> None:
    source = _managed_source(tmp_path)
    post_handler = source.split('pi.on("tool_result"', maxsplit=1)[1]

    assert "tool_call_id: event.toolCallId," in post_handler
