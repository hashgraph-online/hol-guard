"""Approval reuse must never reinterpret compound shell syntax as direct argv."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.daemon.hook_native_review_approval import _command_reuse_is_payload_bound


@pytest.mark.parametrize(
    "command",
    (
        "cat mutable.sh |& sh",
        "cat .env <<< ignored",
        "cat .env <> scratch/out",
        "cat .env >| scratch/out",
        "cat .env && sh check.sh",
        "cat .env || sh check.sh",
        "cat .env; sh check.sh",
        "cat .env & sh check.sh",
        "cat .env | sh",
        "cat .env > scratch/out",
        "cat .env < scratch/in",
    ),
)
def test_compound_shell_operators_are_never_reusable(command: str) -> None:
    assert _command_reuse_is_payload_bound(command) is False


@pytest.mark.parametrize(
    "command",
    (
        "PATH=/tmp/tools cat .env",
        "LC_ALL=C cat .env",
        "./cat .env",
        "/bin/cat .env",
        "bash check.sh",
        "python3.12 check.py",
        "bunx vitest run tests/example.test.ts --reporter=dot",
    ),
)
def test_mutable_resolution_or_execution_is_never_reusable(command: str) -> None:
    assert _command_reuse_is_payload_bound(command) is False


def test_exact_direct_reader_remains_eligible_for_one_use_native_binding() -> None:
    assert _command_reuse_is_payload_bound("cat .env") is True
