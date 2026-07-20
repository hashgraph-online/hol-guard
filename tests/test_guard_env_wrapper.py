"""P40 regressions for the shared Unix env wrapper state machine."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.env_wrapper import parse_env_wrapper
from codex_plugin_scanner.guard.runtime.secret_file_requests import extract_sensitive_tool_action_request
from codex_plugin_scanner.guard.runtime.shell_command_wrappers import normalize_transparent_shell_command


def test_option_operand_is_consumed_exactly_once() -> None:
    parsed = parse_env_wrapper(
        ["-u", "-i", "python", "-c", "pass"],
        inherited_environment={"P40_SENTINEL": "inherited", "PATH": "/bin"},
    )

    assert parsed.complete is True
    assert parsed.option_effects.ignore_environment is False
    assert parsed.option_effects.unset_names == ("-i",)
    assert parsed.executable_argv == ("python", "-c", "pass")
    assert parsed.environment_dict() == {"P40_SENTINEL": "inherited", "PATH": "/bin"}


def test_clear_unset_and_assignments_apply_in_operating_system_order() -> None:
    parsed = parse_env_wrapper(
        ["-u", "OLD", "-i", "OLD=restored", "PATH=/tool/bin", "command", "arg"],
        inherited_environment={"OLD": "before", "SECRET": "inherited"},
    )

    assert parsed.complete is True
    assert parsed.environment_delta.clear is True
    assert parsed.environment_delta.unset_names == ("OLD",)
    assert parsed.environment_delta.assignments == (("OLD", "restored"), ("PATH", "/tool/bin"))
    assert parsed.environment_dict() == {"OLD": "restored", "PATH": "/tool/bin"}
    assert parsed.executable_argv == ("command", "arg")


@pytest.mark.parametrize(
    ("tokens", "ignore_environment", "unset_names", "executable"),
    (
        (["-iu", "NAME", "cmd"], True, ("NAME",), ("cmd",)),
        (["-ui", "cmd"], False, ("i",), ("cmd",)),
        (["--unset=NAME", "--ignore-environment", "cmd"], True, ("NAME",), ("cmd",)),
        (["--unset", "-i", "cmd"], False, ("-i",), ("cmd",)),
        (["--", "-i", "arg"], False, (), ("-i", "arg")),
    ),
)
def test_short_clusters_long_forms_and_option_boundary(
    tokens: list[str],
    ignore_environment: bool,
    unset_names: tuple[str, ...],
    executable: tuple[str, ...],
) -> None:
    parsed = parse_env_wrapper(tokens)

    assert parsed.complete is True
    assert parsed.option_effects.ignore_environment is ignore_environment
    assert parsed.option_effects.unset_names == unset_names
    assert parsed.executable_argv == executable


def test_chdir_search_path_and_repeated_options_use_last_operand(tmp_path: Path) -> None:
    parsed = parse_env_wrapper(
        ["-C", "first", "--chdir=second", "-P/bin", "-P", "/usr/bin", "cmd"],
        cwd=tmp_path,
    )

    assert parsed.complete is True
    assert parsed.option_effects.chdir == "second"
    assert parsed.option_effects.search_path == "/usr/bin"
    assert parsed.effective_cwd == tmp_path / "second"
    assert parsed.executable_argv == ("cmd",)


def test_repeated_unset_and_empty_path_apply_in_order() -> None:
    parsed = parse_env_wrapper(
        ["-u", "OLD", "-uOLD", "PATH=", "cmd"],
        inherited_environment={"OLD": "value", "PATH": "/bin"},
    )

    assert parsed.complete is True
    assert parsed.option_effects.unset_names == ("OLD", "OLD")
    assert parsed.environment_dict() == {"PATH": ""}
    assert parsed.executable_argv == ("cmd",)


def test_split_string_expands_in_place_with_suffix_and_nested_options() -> None:
    parsed = parse_env_wrapper(["-iS", "'NAME=value' command 'two words'", "tail"])

    assert parsed.complete is True
    assert parsed.option_effects.ignore_environment is True
    assert parsed.environment_delta.assignments == (("NAME", "value"),)
    assert parsed.executable_argv == ("command", "two words", "tail")
    assert parsed.split_expansions[0].payload == "'NAME=value' command 'two words'"
    assert parsed.split_expansions[0].source_index == 1


def test_nested_split_string_env_wrappers_are_bounded_and_unwrapped() -> None:
    normalized = normalize_transparent_shell_command(
        "env -S 'env -u PYTHONPATH rg -n fixture src'",
    )

    assert normalized.wrapper_chain == ("env", "env")
    assert normalized.normalized_command == "rg -n fixture src"


@pytest.mark.parametrize(
    ("tokens", "error"),
    (
        (["-u"], "missing_unset_operand"),
        (["--chdir"], "missing_chdir_operand"),
        (["-S"], "missing_split_string_operand"),
        (["--unknown", "cmd"], "unsupported_option"),
        (["-x", "cmd"], "unsupported_option"),
        (["-S", "'unterminated"], "split_string_syntax_error"),
        (["NAME=value\x00", "cmd"], "nul_token"),
    ),
)
def test_malformed_or_unsupported_options_are_incomplete(tokens: list[str], error: str) -> None:
    parsed = parse_env_wrapper(tokens)

    assert parsed.complete is False
    assert parsed.error == error
    assert parsed.command_index is None
    assert parsed.executable_argv == ()


@pytest.mark.skipif(os.name != "posix", reason="requires a POSIX env executable")
def test_parser_matches_real_env_for_option_like_unset_operand() -> None:
    env_executable = shutil.which("env")
    if env_executable is None:
        pytest.skip("env executable is unavailable")
    inherited = {"PATH": os.environ.get("PATH", ""), "P40_SENTINEL": "still-inherited"}
    parsed = parse_env_wrapper(
        ["-u", "-i", sys.executable, "-c", "import os; print(os.environ.get('P40_SENTINEL', 'missing'))"],
        inherited_environment=inherited,
    )
    completed = subprocess.run(
        [
            env_executable,
            "-u",
            "-i",
            sys.executable,
            "-c",
            "import os; print(os.environ.get('P40_SENTINEL', 'missing'))",
        ],
        check=True,
        capture_output=True,
        text=True,
        env=inherited,
    )

    assert parsed.environment_dict() == inherited
    assert completed.stdout.strip() == parsed.environment_dict()["P40_SENTINEL"]


def test_option_like_unset_operand_does_not_hide_unsafe_pythonpath(tmp_path: Path) -> None:
    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "env -u -i PYTHONPATH=./malicious python3 -m pytest -q"},
        cwd=tmp_path,
    )

    assert match is not None
    assert match.action_class == "destructive shell command"


def test_option_like_unset_operand_does_not_hide_sensitive_docker_context(tmp_path: Path) -> None:
    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "env -u -i DOCKER_CONTEXT=prod docker compose ps"},
        cwd=tmp_path,
    )

    assert match is not None
    assert match.action_class == "docker-sensitive command"
