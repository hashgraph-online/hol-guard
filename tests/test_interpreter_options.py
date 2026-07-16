from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.runtime.interpreter_options import shell_interpreter_command_payload


@pytest.mark.parametrize(
    ("parts", "expected_script", "expected_consumed"),
    [
        (["bash", "-c", "sentinel"], "sentinel", 2),
        (["bash", "-lc", "sentinel"], "sentinel", 2),
        (["bash", "-cl", "sentinel"], "sentinel", 2),
        (["bash", "-co", "pipefail", "sentinel"], "sentinel", 3),
        (["bash", "-cOextglob", "sentinel"], "sentinel", 2),
        (["bash", "--noprofile", "-cl", "sentinel"], "sentinel", 3),
        (["bash", "--rcfile", "setup.rc", "-cl", "sentinel"], "sentinel", 4),
    ],
)
def test_shell_interpreter_command_payload_parses_exact_command_operand(
    parts: list[str],
    expected_script: str,
    expected_consumed: int,
) -> None:
    payload = shell_interpreter_command_payload(parts, 0)

    assert payload is not None
    assert payload.script_text == expected_script
    assert payload.tokens_consumed == expected_consumed


@pytest.mark.parametrize(
    "parts",
    [
        ["bash", "-oc", "sentinel"],
        ["bash", "--", "-cl", "sentinel"],
        ["bash", "--rcfile"],
        ["bash", "-cl"],
        ["bash", "script.sh", "-cl", "sentinel"],
    ],
)
def test_shell_interpreter_command_payload_rejects_non_command_operands(parts: list[str]) -> None:
    assert shell_interpreter_command_payload(parts, 0) is None


def test_shell_interpreter_command_payload_does_not_scan_positional_arguments_as_options() -> None:
    payload = shell_interpreter_command_payload(
        ["bash", "-cl", "sentinel", "argument-zero", "-c", "ignored"],
        0,
    )

    assert payload is not None
    assert payload.script_text == "sentinel"
    assert payload.tokens_consumed == 2
