"""Original option outcomes through the production resident caller."""

import json
from dataclasses import asdict
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_shell_helpers import NativeShellHelpersError
from codex_plugin_scanner.guard.runtime import command_option_parsing as options


def test_public_option_helpers_replay_native_original_vectors(native_hook_force):
    vectors = json.loads((Path(__file__).parent / "fixtures/shell-helper-python.v1.json").read_text())["option_vectors"]
    names = {
        "argument_semantics": "argument_semantics",
        "matches_subcommands": "matches_subcommands_conservatively",
        "flags_all": "flags_present_in_all_option_parses",
        "option_advance": "known_option_advance",
        "long_flag": "long_flag_assignment_is_enabled",
    }
    for vector in vectors[::40] + vectors[-20:]:
        inputs = dict(vector["input"])
        inputs.pop("known_flags", None) if vector["action"] == "argument_semantics" else None
        for key in ("arguments", "subcommands"):
            if key in inputs:
                inputs[key] = tuple(inputs[key])
        for key in ("options_with_values", "known_flags", "required_flags"):
            if key in inputs:
                inputs[key] = frozenset(inputs[key])
        if "inverse_flag_pairs" in inputs:
            inputs["inverse_flag_pairs"] = frozenset(tuple(pair) for pair in inputs["inverse_flag_pairs"])
        result = getattr(options, names[vector["action"]])(**inputs)
        if vector["action"] == "argument_semantics":
            result = asdict(result)
            result["present_flags"] = sorted(result["present_flags"])
            result["effective_options"] = [list(row) for row in result["effective_options"]]
        assert result == vector["expected"]


def test_option_cache_reuses_native_results_and_rechecks_runtime(monkeypatch, native_hook_force):
    native_call, identity = options.call, options.runtime_key()
    calls = []

    def counted(action, command, **fields):
        calls.append(action)
        return native_call(action, command, **fields)

    monkeypatch.setattr(options, "call", counted)
    monkeypatch.setattr(options, "runtime_key", lambda: identity)
    options._option_result.cache_clear()
    arguments, flags = ("--quiet", "status"), frozenset({"--quiet"})
    operations = (
        lambda: options.argument_semantics(arguments),
        lambda: options.matches_subcommands_conservatively(
            arguments, ("status",), options_with_values=frozenset(), known_flags=flags
        ),
        lambda: options.flags_present_in_all_option_parses(
            arguments, flags, options_with_values=frozenset(), known_flags=flags
        ),
        lambda: options.known_option_advance("--quiet", options_with_values=frozenset(), known_flags=flags),
        lambda: options.long_flag_assignment_is_enabled("--quiet=true"),
    )
    expected = tuple(operation() for operation in operations)
    assert tuple(operation() for operation in operations) == expected
    assert len(calls) == 5
    monkeypatch.setattr(options, "runtime_key", lambda: (*identity, "changed"))
    assert tuple(operation() for operation in operations) == expected
    assert len(calls) == 10

    def unavailable():
        raise NativeShellHelpersError("native_shell_helpers_unavailable")

    monkeypatch.setattr(options, "runtime_key", unavailable)
    for operation in operations:
        with pytest.raises(NativeShellHelpersError, match="unavailable"):
            operation()
    assert len(calls) == 10


def test_option_cache_does_not_store_native_errors(monkeypatch, native_hook_force):
    native_call = options.call
    options._option_result.cache_clear()

    def unavailable(*args, **fields):
        raise NativeShellHelpersError("native_shell_helpers_unavailable")

    monkeypatch.setattr(options, "call", unavailable)
    with pytest.raises(NativeShellHelpersError, match="unavailable"):
        options.long_flag_assignment_is_enabled("--quiet=true")
    assert options._option_result.cache_info().currsize == 0
    monkeypatch.setattr(options, "call", native_call)
    assert options.long_flag_assignment_is_enabled("--quiet=true")
