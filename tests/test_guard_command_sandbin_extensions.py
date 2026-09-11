"""Structured sandbin command extension tests."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from tests.command_extension_contracts import assert_safe_command_cases

SANDBIN_REVIEW_CASES: tuple[tuple[str, str], ...] = (
    ("sandbin run script.py --server sandbin.example.com", "command.sandbin.run-server"),
    ("sandbin run script.py -s sandbin.example.com", "command.sandbin.run-server"),
    ("sandbin run -l python -e 'print(1)' --server localhost:8080 --json", "command.sandbin.run-server"),
    ("sandbin keys create --server sandbin.example.com", "command.sandbin.keys-create"),
    ("sandbin keys create", "command.sandbin.keys-create"),
)

SANDBIN_SAFE_COMMANDS: tuple[str, ...] = (
    # --reconnect attaches to a run the server already accepted instead of
    # submitting a new one, so it carries none of the risk --server review.
    "sandbin run script.py --server sandbin.example.com --reconnect 7e2b1c4a-91fd-4c2b-8a3e-1234567890ab",
    "sandbin run --server localhost:8080 --reconnect abc123",
    # Read-only: reports an existing key's quota, mints nothing.
    "sandbin keys status sb_abcdef1234567890",
    # Reads this host's local IMAGES; never makes a network request.
    "sandbin languages",
    # No --server at all: sandbin executes the guest in-process, locally.
    "sandbin run script.py",
)


def test_sandbin_run_server_and_keys_create_reach_review_while_reconnect_and_reads_stay_quiet(
    tmp_path: Path,
) -> None:
    """Fresh --server submissions and key issuance are reviewed; reconnect, status, and languages are not."""
    for command, expected_rule in SANDBIN_REVIEW_CASES:
        observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(
            parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)
        )
        matched = {item.rule.rule_id for item in observations if item.extension.extension_id == "command.sandbin"}
        assert expected_rule in matched, command

        # command.sandbin ships external/opt-in, so a default evaluation must
        # not enforce it until a caller explicitly enables the extension.
        evaluation = evaluate_command(command, cwd=tmp_path, home_dir=tmp_path)
        assert evaluation.controlling_rule_id != expected_rule
        assert all(item.extension.extension_id != "command.sandbin" for item in evaluation.extension_observations)

    assert_safe_command_cases(SANDBIN_SAFE_COMMANDS, tmp_path)
