"""Resolve package test scripts without executing a package manager or shell."""

from __future__ import annotations

import shlex
from collections.abc import Sequence
from pathlib import Path

from .package_evidence_common import read_json_with_integrity
from .restricted_node_test import nearest_project_root
from .restricted_pytest_model import RestrictedPytestError
from .restricted_pytest_validation import _normalized_command

PACKAGE_TEST_REASON = "native_package_test_readonly_containment_required"
PACKAGE_TEST_PROFILE = "package-test-readonly-v1"


def _option_name(argument: str) -> str:
    """The option an argument names, lowercased and without separators or value."""
    if not argument.startswith("--"):
        return ""
    return argument[2:].partition("=")[0].replace("-", "").replace("_", "").lower()


def _watches(arguments: Sequence[str]) -> bool:
    """A watching Jest run never finishes inside the sink.

    Jest reads its options through yargs, which takes a kebab spelling of every
    camelCase name, so the name is read with its separators removed. Watch mode
    has no short spelling: ``-w`` is Jest's ``--maxWorkers`` and ``--watchman``
    names the file crawler.
    """
    return any(_option_name(argument) in {"watch", "watchall"} for argument in arguments)


_PIECE_DELIMITERS = "\"',:;=[]{}"


def _leaves_the_workspace(argument: str) -> bool:
    """Whether any part of an argument names a path outside the workspace.

    yargs-parser takes a value joined with ``=``, attached straight to a short
    alias (``-c/etc/jest.config.js``), or spelled as inline JSON
    (``--config '{"setupFiles":["/tmp/x.js"]}'``), so the argument is screened
    whole and in pieces rather than as one path. Short aliases also group, and
    yargs-parser hands the rest of a group to whichever letter a non-word
    character follows, so ``-ic/etc/jest.config.js`` is ``--runInBand --config
    /etc/jest.config.js``. Every tail of the group is screened, since which
    letter takes the value is yargs-parser's to decide.

    Jest reads inline JSON with ``JSON.parse``, which turns a ``\\u`` escape
    into its character after this screen has looked at the raw text, so a
    quoted argument carrying such an escape goes to review instead.
    """
    if '"' in argument and "\\u" in argument:
        return True
    group = argument[1:] if argument.startswith("-") and not argument.startswith("--") else ""
    pieces = [argument, *(group[index:] for index in range(1, len(group)))]
    piece = ""
    for character in argument:
        if character.isspace() or character in _PIECE_DELIMITERS:
            pieces.append(piece)
            piece = ""
        else:
            piece += character
    pieces.append(piece)
    return any(_path_leaves_the_workspace(piece) for piece in pieces)


def _path_leaves_the_workspace(value: str) -> bool:
    """True when a value names a path this workspace does not hold."""
    value = value.replace("\\", "/")
    windows_root = len(value) >= 3 and value[0].isascii() and value[0].isalpha() and value[1:3] == ":/"
    return (
        value.startswith("/")
        or value.startswith("~/")
        or value == "~"
        or windows_root
        or any(segment == ".." for segment in value.split("/"))
    )


def _reads_its_own_workspace(arguments: Sequence[str]) -> bool:
    """Jest loads its config, transforms, reporters, environment and test runner
    from option values, so any of them can name a module outside the read-only
    admission. Every argument is read, not a list of the options that take one.
    """
    return not any(_leaves_the_workspace(argument) for argument in arguments)


def is_package_test(command: Sequence[str]) -> bool:
    return (
        bool(command)
        and Path(command[0]).name in {"npm", "pnpm", "bun", "yarn"}
        and (
            (len(command) >= 2 and command[1] == "test" and Path(command[0]).name != "bun")
            or (len(command) >= 3 and tuple(command[1:3]) == ("run", "test"))
        )
    )


def resolve_package_test(command: Sequence[str], *, workspace: Path, cwd: Path | None = None) -> tuple[str, ...]:
    argv = _normalized_command(command)
    if not is_package_test(argv):
        raise RestrictedPytestError("package_test_invalid_command", "Only local package test scripts are supported.")
    trailing = argv[2:] if argv[1] == "test" else argv[3:]
    if trailing and trailing[0] != "--":
        raise RestrictedPytestError("package_test_invalid_command", "Test arguments must follow an explicit --.")
    package = nearest_project_root(cwd or workspace, workspace, "package.json")
    manifest, _digest = read_json_with_integrity(package / "package.json")
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
        tokens = list(lexer)
    except ValueError as error:
        raise RestrictedPytestError(
            "package_test_invalid_command", "The local test script could not be parsed."
        ) from error
    if not tokens:
        raise RestrictedPytestError("package_test_invalid_command", "The test script is empty.")
    if any(token and all(char in ";&|<>" for char in token) for token in tokens):
        raise RestrictedPytestError("package_test_invalid_command", "Test shell effects need separate evaluation.")
    node = Path(tokens[0]).name in {"node", "nodejs"} and len(tokens) > 1 and tokens[1] == "--test"
    vitest = tokens[0] == "vitest" and len(tokens) > 1 and tokens[1] == "run"
    # The manager appends what follows `--` to the script, so the sink runs both
    # halves and both are read as one Jest call.
    jest_arguments = (*tokens[1:], *trailing[1:])
    jest = tokens[0] == "jest" and not _watches(jest_arguments) and _reads_its_own_workspace(jest_arguments)
    if not node and not vitest and not jest:
        raise RestrictedPytestError("package_test_invalid_command", "The test script is not a supported local runner.")
    return (*tokens, *trailing[1:])
