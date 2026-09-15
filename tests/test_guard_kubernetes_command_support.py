from __future__ import annotations

from codex_plugin_scanner.guard.runtime.kubernetes_command_support import (
    shell_command_script,
)


def test_shell_command_script_ignores_long_options_containing_c() -> None:
    assert (
        shell_command_script(("--context", "cluster", "-c", "printf safe"))
        == "printf safe"
    )
    assert (
        shell_command_script(("--config", "settings", "-ec", "printf safe"))
        == "printf safe"
    )


def test_shell_command_script_stops_at_option_terminator() -> None:
    assert shell_command_script(("--", "-c", "printf not-an-option")) is None
