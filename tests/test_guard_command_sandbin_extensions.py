"""Structured sandbin command extension tests."""

from __future__ import annotations

from pathlib import Path

from tests.command_extension_contracts import assert_reviewed_command_cases, assert_safe_command_cases

SANDBIN_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    (
        "sandbin run script.py --server sandbin.example.com",
        "sandbin remote run submission command",
        "command.sandbin.run-server",
    ),
    (
        "sandbin run script.py -s sandbin.example.com",
        "sandbin remote run submission command",
        "command.sandbin.run-server",
    ),
    (
        "sandbin run -l python -e 'print(1)' --server localhost:8080 --json",
        "sandbin remote run submission command",
        "command.sandbin.run-server",
    ),
    (
        "sandbin keys create --server sandbin.example.com",
        "sandbin API key issuance command",
        "command.sandbin.keys-create",
    ),
    (
        "sandbin keys create",
        "sandbin API key issuance command",
        "command.sandbin.keys-create",
    ),
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
    assert_reviewed_command_cases(SANDBIN_REVIEW_CASES, tmp_path)
    assert_safe_command_cases(SANDBIN_SAFE_COMMANDS, tmp_path)
