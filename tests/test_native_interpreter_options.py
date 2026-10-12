"""Public interpreter-helper projection through the existing resident client."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from codex_plugin_scanner.guard.runtime.interpreter_options import shell_interpreter_command_payload
from codex_plugin_scanner.guard.runtime.shell_command_wrappers import normalize_transparent_shell_command


def test_interpreter_and_wrapper_public_callers_share_native_option_admission(native_hook_force):
    fixture = json.loads((Path(__file__).parent / "fixtures/shell-helper-python.v1.json").read_text())
    for index in (3, 6, 7, 8, 15):
        vector = fixture["interpreter_vectors"][index]
        payload = shell_interpreter_command_payload(vector["parts"], vector["command_index"])
        assert payload is not None
        assert asdict(payload) == vector["expected"]
    for command in ("bash --command 'echo value'", "bash -co pipefail 'echo value'"):
        expected = next(v["expected"]["normalization"] for v in fixture["vectors"] if v["command"] == command)
        actual = asdict(normalize_transparent_shell_command(command))
        actual["wrapper_chain"] = list(actual["wrapper_chain"])
        assert actual == expected
