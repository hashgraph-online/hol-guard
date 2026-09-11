"""Structured sandbin command extension tests."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.command_extension_observations import CommandExtensionObservation
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from tests.command_extension_contracts import assert_safe_command_cases

SANDBIN_REVIEW_CASES: tuple[tuple[str, str], ...] = (
    ("sandbin run script.py --server sandbin.example.com", "command.sandbin.run-server"),
    ("sandbin run script.py -s sandbin.example.com", "command.sandbin.run-server"),
    ("sandbin run -l python -e 'print(1)' --server localhost:8080 --json", "command.sandbin.run-server"),
    ("sandbin keys create --server sandbin.example.com", "command.sandbin.keys-create"),
    ("sandbin keys create", "command.sandbin.keys-create"),
    # sandbin's argv parser is a plain switch on exact tokens with no
    # --flag=value support (bin/sandbin.mjs); `--reconnect=<id>` never
    # matches its literal `--reconnect` case and aborts before any network
    # call. The safe variant must not credit that spelling, so this stays a
    # genuine, unresolved review case rather than a silent exemption.
    ("sandbin run script.py --server sandbin.example.com --reconnect=abc123", "command.sandbin.run-server"),
)

SANDBIN_SAFE_COMMANDS: tuple[str, ...] = (
    # --reconnect (space-separated, sandbin's only recognized spelling)
    # attaches to a run the server already accepted instead of submitting a
    # new one, so it carries none of the risk --server review targets.
    "sandbin run script.py --server sandbin.example.com --reconnect 7e2b1c4a-91fd-4c2b-8a3e-1234567890ab",
    "sandbin run --server localhost:8080 --reconnect abc123",
    # Read-only: reports an existing key's quota, mints nothing.
    "sandbin keys status sb_abcdef1234567890",
    # Reads this host's local IMAGES; never makes a network request.
    "sandbin languages",
    # No --server at all: sandbin executes the guest in-process, locally.
    "sandbin run script.py",
)


def _sandbin_observation(command: str, rule_id: str, tmp_path: Path) -> CommandExtensionObservation:
    observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(
        parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)
    )
    matches = [
        item
        for item in observations
        if item.extension.extension_id == "command.sandbin" and item.rule.rule_id == rule_id
    ]
    assert matches, f"{command!r} did not reach rule {rule_id!r}"
    return matches[0]


def test_sandbin_run_server_and_keys_create_reach_review_while_reconnect_and_reads_stay_quiet(
    tmp_path: Path,
) -> None:
    """Fresh --server submissions and key issuance are reviewed; reconnect, status, and languages are not."""
    for command, expected_rule in SANDBIN_REVIEW_CASES:
        _sandbin_observation(command, expected_rule, tmp_path)

        # command.sandbin ships external/opt-in, so a default evaluation must
        # not enforce it until a caller explicitly enables the extension.
        evaluation = evaluate_command(command, cwd=tmp_path, home_dir=tmp_path)
        assert evaluation.controlling_rule_id != expected_rule
        assert all(item.extension.extension_id != "command.sandbin" for item in evaluation.extension_observations)

    assert_safe_command_cases(SANDBIN_SAFE_COMMANDS, tmp_path)


def test_sandbin_reconnect_equals_spelling_does_not_earn_the_safe_variant(tmp_path: Path) -> None:
    """`--reconnect=<id>` is not sandbin's real syntax, so it must not suppress review."""
    joined = _sandbin_observation(
        "sandbin run script.py --server sandbin.example.com --reconnect=abc123",
        "command.sandbin.run-server",
        tmp_path,
    )
    assert "reconnect" not in {variant.variant_id for variant in joined.safe_variants}

    space_separated = _sandbin_observation(
        "sandbin run script.py --server sandbin.example.com --reconnect abc123",
        "command.sandbin.run-server",
        tmp_path,
    )
    assert "reconnect" in {variant.variant_id for variant in space_separated.safe_variants}
