"""Original option outcomes through the production resident caller."""

import json
from dataclasses import asdict
from pathlib import Path

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
