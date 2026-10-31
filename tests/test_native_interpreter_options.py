"""Interpreter option payloads through the existing resident client."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from tests.native_shell_helpers_client import call
from tests.shell_wrapper_test_support import native_shell_normalization


def test_interpreter_and_wrapper_public_callers_share_native_option_admission(native_hook_force):
    fixture = json.loads((Path(__file__).parent / "fixtures/shell-helper-python.v1.json").read_text())
    for index in (3, 6, 7, 8, 15):
        vector = fixture["interpreter_vectors"][index]
        payload = call("interpreter_payload", "", parts=vector["parts"], command_index=vector["command_index"])
        assert payload == vector["expected"]
    for command in ("bash --command 'echo value'", "bash -co pipefail 'echo value'"):
        expected = next(v["expected"]["normalization"] for v in fixture["vectors"] if v["command"] == command)
        actual = asdict(native_shell_normalization(command))
        actual["wrapper_chain"] = list(actual["wrapper_chain"])
        assert actual == expected
