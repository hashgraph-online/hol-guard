"""Focused contracts for the optimized executable path-set matcher."""

from __future__ import annotations

from typing import Any

import pytest

from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from codex_plugin_scanner.guard.runtime.command_path_set_matcher import ExecutablePathSetMatcher


def _matcher(**overrides: Any) -> ExecutablePathSetMatcher:
    values: dict[str, Any] = {
        "executables": frozenset({"tool"}),
        "paths": frozenset({("resource", "delete")}),
    }
    values.update(overrides)
    return ExecutablePathSetMatcher(**values)


def test_path_set_matcher_normalizes_every_option_contract_field() -> None:
    matcher = ExecutablePathSetMatcher(
        executables=frozenset({" Tool.EXE "}),
        paths=frozenset({(" Group ", " Delete ")}),
        required_flags=frozenset({" --FORCE "}),
        forbidden_flags=frozenset({" --SAFE "}),
        allow_leading_options=True,
        leading_options_with_values=frozenset({" --PROFILE "}),
        interspersed_options_with_values=frozenset({" --REGION "}),
        interspersed_flags=frozenset({" --DEBUG "}),
        options_with_values=frozenset({" --MODE "}),
        inverse_flag_pairs=frozenset({(" --FORCE ", " --NO-FORCE ")}),
        required_option_values=((" --MODE ", frozenset({" FAST "})),),
    )

    assert matcher.executables == frozenset({"tool.exe"})
    assert matcher.paths == frozenset({("group", "delete")})
    assert matcher.required_flags == frozenset({"--force"})
    assert matcher.forbidden_flags == frozenset({"--safe"})
    assert matcher.leading_options_with_values == frozenset({"--profile"})
    assert matcher.interspersed_options_with_values == frozenset({"--region"})
    assert matcher.interspersed_flags == frozenset({"--debug"})
    assert matcher.options_with_values == frozenset({"--mode"})
    assert matcher.inverse_flag_pairs == frozenset({("--force", "--no-force")})
    assert matcher.required_option_values == (("--mode", frozenset({"fast"})),)
    assert matcher.match(
        parse_shell_command(
            "tool.exe --profile prod group --region us-east-1 delete --force --mode FAST"
        )
    )


def test_path_set_matcher_rejects_required_and_forbidden_flag_overlap() -> None:
    with pytest.raises(ValueError, match="both required and forbidden"):
        _matcher(
            required_flags=frozenset({" --FORCE "}),
            forbidden_flags=frozenset({"--force"}),
        )


def test_path_set_matcher_rejects_reused_inverse_flag_names() -> None:
    with pytest.raises(ValueError, match="cannot reuse"):
        _matcher(
            inverse_flag_pairs=frozenset(
                {
                    ("--force", "--no-force"),
                    (" --FORCE ", "--disable-force"),
                }
            )
        )


def test_path_set_matcher_rejects_duplicate_required_option_names() -> None:
    with pytest.raises(ValueError, match="cannot declare an option more than once"):
        _matcher(
            required_option_values=(
                ("--mode", frozenset({"fast"})),
                (" --MODE ", frozenset({"slow"})),
            )
        )


def test_path_set_matcher_rejects_empty_required_option_names_and_values() -> None:
    with pytest.raises(ValueError, match="names cannot be blank"):
        _matcher(required_option_values=((" ", frozenset({"value"})),))
    with pytest.raises(ValueError, match="values cannot be empty or blank"):
        _matcher(required_option_values=(("--mode", frozenset()),))
    with pytest.raises(ValueError, match="values cannot be empty or blank"):
        _matcher(required_option_values=(("--mode", frozenset({" "})),))


def test_path_set_matcher_rejects_empty_path_tokens_instead_of_collapsing_them() -> None:
    with pytest.raises(ValueError, match="non-empty path tokens"):
        _matcher(paths=frozenset({("resource", " ")}))


def test_path_set_matcher_prefers_the_longest_exact_path() -> None:
    matcher = _matcher(
        paths=frozenset(
            {
                ("resource",),
                ("resource", "child", "delete"),
            }
        )
    )

    assert matcher._exact_path(("resource", "child", "delete", "target")) == (
        "resource",
        "child",
        "delete",
    )


def test_path_set_matcher_prefers_the_longest_conservative_path() -> None:
    matcher = _matcher(
        paths=frozenset(
            {
                ("resource",),
                ("resource", "child", "delete"),
            }
        ),
        fail_secure_unknown_options=True,
    )

    assert matcher._conservative_path(
        ("--future-option", "value", "resource", "child", "delete")
    ) == ("resource", "child", "delete")
