"""Every live Gauntlet native-tools allow command also runs in the static gate.

The live Gauntlet only runs on release candidates. A shell command it expects
to run quietly must therefore also be a static benign false-positive gate case,
so a regression shows up on the pull request that causes it.
"""

from __future__ import annotations

import json
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_SCENARIOS = _ROOT / "ci" / "gauntlet" / "scenarios.json"
_GATE = _ROOT / "tests" / "fixtures" / "benign_false_positive_gate.json"
# Gauntlet fixture placeholders and the gate tokens naming the same layout.
_TOKENS = {
    "{{home}}": "${HOME}",
    "{{workspace}}": "${PARENT}",
    "{{root}}": "${GAUNTLET_ROOT}",
    "{{scratch}}": "${SCRATCH}",
}


def _gauntlet_commands() -> set[str]:
    scenarios = json.loads(_SCENARIOS.read_text(encoding="utf-8"))["scenarios"]
    commands: set[str] = set()
    for scenario in scenarios:
        if scenario.get("expectation") != "allow" or scenario.get("oracle") != "native-tools":
            continue
        for command in scenario.get("commands") or []:
            for placeholder, token in _TOKENS.items():
                command = command.replace(placeholder, token)
            commands.add(command)
    return commands


def _gate_commands() -> set[str]:
    cases = json.loads(_GATE.read_text(encoding="utf-8"))["cases"]
    return {
        case["tool_input"]["command"]
        for case in cases
        if case["tool"] == "shell" and case["expect"] == "allow" and "omp" in case["harnesses"]
    }


def test_gauntlet_native_shell_commands_have_static_gate_cases() -> None:
    commands = _gauntlet_commands()
    assert commands, "no native-tools allow commands found"
    missing = sorted(commands - _gate_commands())
    assert not missing, f"add these Gauntlet allow commands to the benign false-positive gate: {missing}"
