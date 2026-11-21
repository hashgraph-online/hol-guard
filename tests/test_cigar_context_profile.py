"""Profile projection never reports private filenames, caller graphs or invalid time."""

import cProfile
import io
import json
import pstats
from pathlib import Path

import pytest

from scripts.cigar_context_profile import summarize_profile

ROOTS = {"installed": Path("/qualified"), "stdlib": Path("/python")}


def test_private_and_dynamic_frames_are_unmapped_without_losing_cpu_totals():
    stats = {
        ("/qualified/guard/context.py", 12, "compile_context"): (2, 3, 0.3, 0.5, {"secret-caller": "raw-private-data"}),
        ("/Users/secret/Vault/private.py", 4, "secret_function"): (1, 1, 0.2, 0.2, {}),
        ("~", 0, "<built-in method /private/secret>"): (1, 1, 0.1, 0.1, {}),
    }
    result = summarize_profile(stats, ROOTS)
    encoded = json.dumps(result)
    assert "secret" not in encoded and "raw-private-data" not in encoded and "/Users/" not in encoded
    assert result["unmapped_functions"] == 2
    assert result["unmapped_self_elapsed_seconds"] == pytest.approx(0.3)
    assert result["total_self_elapsed_seconds"] == pytest.approx(0.6)
    assert result["top_by_self_elapsed"][0]["module"] == "guard/context.py"


def test_builtin_and_frozen_names_are_bounded_and_top_output_is_limited():
    stats = {
        ("~", 0, "<method 'acquire' of '_thread.lock' objects>"): (1, 1, 0.1, 0.1, {}),
        ("~", 0, "<built-in method builtins.len>"): (1, 1, 0.2, 0.2, {}),
        ("<frozen os>", 1, "getenv"): (1, 1, 0.3, 0.3, {}),
    }
    result = summarize_profile(stats, ROOTS, limit=2)
    assert result["unmapped_functions"] == 0 and result["retained_functions"] == 2
    assert [value["function"] for value in result["top_by_self_elapsed"]] == ["getenv", "builtins.len"]


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -0.1])
def test_invalid_clock_measurements_refuse_instead_of_reporting_zero(value):
    with pytest.raises(ValueError, match="profile timing"):
        summarize_profile({("/qualified/a.py", 1, "compile"): (1, 1, value, 1.0, {})}, ROOTS)


def test_the_actual_standard_profiler_produces_accepted_nonnegative_measurements():
    profiler = cProfile.Profile()
    profiler.runcall(json.dumps, {"kind": "synthetic", "values": list(range(100))})
    stats = pstats.Stats(profiler, stream=io.StringIO()).stats
    result = summarize_profile(stats, ROOTS)
    assert result["total_calls"] > 0 and result["total_self_elapsed_seconds"] > 0
