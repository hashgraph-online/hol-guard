"""Read grants of the workspace sandbox plan: scratch scripts outside the workspace.

Whether a plan's grant fields match the grant the resident decided is native
authority's reading too, through `workspace_grant_script_roots`. What is left
here is the filesystem check over the roots that reading returns.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

PLAN_FIELDS = frozenset(
    {
        "profile_version",
        "backend",
        "backend_executable",
        "workspace",
        "cwd",
        "executable",
        "command",
        "command_sha256",
        "allowed_executables",
        "read_only_roots",
        "exec_roots",
        "write_denials",
        "linked_git",
        "sandbox_path",
        "bootstrap_git",
        "prefix_command",
        "native_suffix",
        "denied_capabilities",
        "grant_identity_hash",
        "capabilities",
    }
)
_SCRIPT_SUFFIXES = frozenset({".py", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx"})


def _absolute_words(command: str) -> list[str]:
    """Ask native authority for the absolute words the command spells.

    Native authority read this text when it admitted the run and drew the plan
    whose grant is being checked here. Reading it again in Python is a second
    grammar deciding the same thing: whether `;`, `>` or `|` ends the word that
    names the script, and whether `#` starts a comment or spells a directory.
    A plan a grant is admitted against has to be read by the reading that drew
    it.

    An answer that is not a list of words is no reading at all, so it raises
    rather than passing for a command that names nothing.
    """
    from ..native_restricted_pytest import restricted_native
    from .restricted_pytest_model import PYTEST_INVALID_COMMAND_REASON_CODE, RestrictedPytestError

    words = restricted_native("command_absolute_words", {"command_text": command}, list)
    if type(words) is not list or not all(type(word) is str for word in words):
        raise RestrictedPytestError(PYTEST_INVALID_COMMAND_REASON_CODE, "Invalid restricted execution request.")
    return list(words)


def _launched(path: Path, command: str) -> bool:
    """The command carries an absolute word that names exactly this file."""
    return any(os.path.realpath(word) == str(path) for word in _absolute_words(command))


def read_grants_valid(value: object, command: str) -> bool:
    """At most one script outside the workspace, which the command launches.

    The grant is one absolute, canonical, regular file; the native plan derived
    it from the command, so a file the command does not name is not one the plan
    can have earned. A second grant could let one script read another.
    """
    if not isinstance(value, list) or len(value) > 1:
        return False
    for item in value:
        if not isinstance(item, str) or not item.startswith("/") or "\0" in item:
            return False
        path = Path(item)
        if (
            path.is_symlink()
            or not path.is_file()
            or path.resolve() != path
            or path.suffix.lower() not in _SCRIPT_SUFFIXES
            or not _launched(path, command)
        ):
            return False
    return True


@dataclass(frozen=True)
class ExpectedGrant:
    """The grant the resident decided for the command a plan runs."""

    identity_hash: str
    capabilities: tuple[str, ...]
    state_dir: str | None


def grant_script_roots(plan: Mapping[str, object], expected: ExpectedGrant | None) -> list[object] | None:
    """The plan's script read roots once native authority admits its grant; `None` refuses.

    The resident decided this grant and drew this plan; whether the two agree —
    the profile the plan claims, the identity it carries, that its capabilities
    are a canonical subset of the decided ones, and where the state directory
    sits among the read roots — is that decision read back, not a judgement made
    here a second time.

    An answer that is not a list of roots is no reading at all, so the plan is
    refused rather than run with the roots it asked for.
    """
    from ..native_restricted_pytest import restricted_native
    from .restricted_pytest_model import RestrictedPytestError

    grant = (
        None
        if expected is None
        else {
            "identity_hash": expected.identity_hash,
            "capabilities": list(expected.capabilities),
            "state_dir": expected.state_dir,
        }
    )
    try:
        roots = restricted_native("workspace_grant_script_roots", {"plan": dict(plan), "expected": grant}, list)
    except RestrictedPytestError:
        return None
    return list(roots) if type(roots) is list else None
