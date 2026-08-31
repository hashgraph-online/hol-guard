from __future__ import annotations

from codex_plugin_scanner.guard.cli import commands as guard_commands_module


def test_commands_facade_exports_legacy_symbols() -> None:
    for name in (
        "add_guard_parser",
        "add_guard_root_parser",
        "run_guard_command",
        "_build_guard_device_connect_payload",
        "_finalize_guard_connect_payload",
        "_headless_approval_resolver",
        "_native_hook_reason",
        "_resolve_guard_workspace",
        "_runtime_detector_perf_payload",
    ):
        assert getattr(guard_commands_module, name) is not None


def test_commands_facade_wrapped_helpers_report_facade_module() -> None:
    assert guard_commands_module.add_guard_parser.__module__ == guard_commands_module.__name__
    assert guard_commands_module.run_guard_command.__module__ == guard_commands_module.__name__
    assert guard_commands_module._finalize_guard_connect_payload.__module__ == guard_commands_module.__name__
    assert guard_commands_module._headless_approval_resolver.__module__ == guard_commands_module.__name__


def test_commands_facade_restores_propagated_overrides(monkeypatch) -> None:
    from codex_plugin_scanner.guard.cli import commands_hook_generic as generic_commands

    original = generic_commands.schedule_guard_daemon_ensure

    def replacement(_guard_home):
        return "http://127.0.0.1:4455"

    monkeypatch.setattr(guard_commands_module, "schedule_guard_daemon_ensure", replacement)

    with guard_commands_module._support_overrides():
        assert generic_commands.schedule_guard_daemon_ensure is replacement

    assert generic_commands.schedule_guard_daemon_ensure is original
