from __future__ import annotations

import importlib
import sys

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


def test_commands_facade_restores_late_loaded_compatibility_overrides(monkeypatch) -> None:
    from codex_plugin_scanner.guard.cli import commands_support as support

    original = support.queue_blocked_approvals

    def replacement(*_args, **_kwargs):
        return []

    monkeypatch.setattr(guard_commands_module, "queue_blocked_approvals", replacement)
    module_name = f"{guard_commands_module.__package__}.commands_hook_generic"
    package = sys.modules[guard_commands_module.__package__]
    attribute_name = "commands_hook_generic"
    previous_module = sys.modules.pop(module_name, None)
    had_package_attribute = hasattr(package, attribute_name)
    previous_package_attribute = getattr(package, attribute_name, None)
    if had_package_attribute:
        delattr(package, attribute_name)

    try:
        with guard_commands_module._support_overrides():
            late_module = importlib.import_module(module_name)
            assert late_module.queue_blocked_approvals is replacement

        assert late_module.queue_blocked_approvals is original
    finally:
        sys.modules.pop(module_name, None)
        if previous_module is not None:
            sys.modules[module_name] = previous_module
        if hasattr(package, attribute_name):
            delattr(package, attribute_name)
        if had_package_attribute:
            setattr(package, attribute_name, previous_package_attribute)


def test_commands_facade_restores_overrides_captured_by_modules_imported_inside_window(monkeypatch) -> None:
    import sys
    from types import ModuleType

    from codex_plugin_scanner.guard.cli import _commands_shared as shared_commands
    from codex_plugin_scanner.guard.cli import commands_support as support_module

    real_queue = support_module.queue_blocked_approvals

    def replacement(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("override leaked past the scoped call")

    monkeypatch.setattr(guard_commands_module, "queue_blocked_approvals", replacement)

    probe_name = f"{guard_commands_module.__package__}.commands_hook_probe_leak"
    probe = ModuleType(probe_name)
    monkeypatch.setitem(sys.modules, probe_name, probe)

    with guard_commands_module._support_overrides():
        probe.queue_blocked_approvals = shared_commands.queue_blocked_approvals
        assert probe.queue_blocked_approvals is replacement

    assert probe.queue_blocked_approvals is real_queue
