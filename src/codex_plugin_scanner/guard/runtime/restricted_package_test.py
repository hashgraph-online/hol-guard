"""Resolve package test scripts without executing a package manager or shell."""

from __future__ import annotations

import shlex
from collections.abc import Sequence
from pathlib import Path

from .package_evidence_common import read_json_with_integrity
from .restricted_pytest_model import RestrictedPytestError
from .restricted_pytest_validation import _normalized_command

PACKAGE_TEST_REASON = "native_package_test_readonly_containment_required"
PACKAGE_TEST_PROFILE = "package-test-readonly-v1"


def is_package_test(command: Sequence[str]) -> bool:
    return (
        bool(command)
        and Path(command[0]).name in {"npm", "pnpm", "bun"}
        and (
            (len(command) >= 2 and command[1] == "test")
            or (len(command) >= 3 and tuple(command[1:3]) == ("run", "test"))
        )
    )


def resolve_package_test(command: Sequence[str], *, workspace: Path) -> tuple[str, ...]:
    argv = _normalized_command(command)
    if not is_package_test(argv):
        raise RestrictedPytestError("package_test_invalid_command", "Only local package test scripts are supported.")
    trailing = argv[2:] if argv[1] == "test" else argv[3:]
    if trailing and trailing[0] != "--":
        raise RestrictedPytestError("package_test_invalid_command", "Test arguments must follow an explicit --.")
    manifest, _digest = read_json_with_integrity(workspace / "package.json")
    scripts = manifest.get("scripts") if isinstance(manifest, dict) else None
    if not isinstance(scripts, dict) or not isinstance(scripts.get("test"), str):
        raise RestrictedPytestError("package_test_invalid_command", "The local test script is unavailable.")
    if any(scripts.get(phase) for phase in ("pretest", "posttest")):
        raise RestrictedPytestError(
            "package_test_invalid_command", "Test lifecycle actions need separate evaluation; none were skipped."
        )
    script = scripts["test"]
    # No shell expansion may silently disappear when replacing a package script.
    if any(character in script for character in ("$", "`", "\n", "\r")):
        raise RestrictedPytestError("package_test_invalid_command", "Test shell expansion needs separate evaluation.")
    lexer = shlex.shlex(script, posix=True, punctuation_chars=";&|<>")
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        tokens = tuple(lexer)
    except ValueError as error:
        raise RestrictedPytestError(
            "package_test_invalid_command", "The local test script could not be parsed."
        ) from error
    if not tokens or any(token and all(char in ";&|<>" for char in token) for token in tokens):
        raise RestrictedPytestError("package_test_invalid_command", "Test shell effects need separate evaluation.")
    node = Path(tokens[0]).name in {"node", "nodejs"} and len(tokens) > 1 and tokens[1] == "--test"
    vitest = tokens[0] == "vitest" and len(tokens) > 1 and tokens[1] == "run"
    if not node and not vitest:
        raise RestrictedPytestError("package_test_invalid_command", "The test script is not a supported local runner.")
    return (*tokens, *trailing[1:])
