"""Read grants of the workspace sandbox plan: scratch scripts outside the workspace.

`grant_script_roots` mirrors Rust `contained_workspace_grant_plan` exactly; both
are pinned by `tests/fixtures/workspace_grant_plan/parity_vectors.json`.
"""

from __future__ import annotations

import os
import shlex
from collections.abc import Mapping
from dataclasses import dataclass
from itertools import pairwise
from pathlib import Path

_BASE_PROFILE = "workspace-contained-v1"
_GRANT_PROFILE = "workspace-contained-grant-v1"
_GRANT_CAPABILITIES = ("loopback-network", "state-dir-read", "state-dir-write")
_STATE_CAPABILITIES = frozenset({"state-dir-read", "state-dir-write"})
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


def _launched(path: Path, command: str) -> bool:
    """The command carries an absolute word that names exactly this file."""
    lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        words = list(lexer)
    except ValueError:
        return False
    return any(word.startswith("/") and os.path.realpath(word) == str(path) for word in words)


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


def _canonical(items: list[object]) -> list[str] | None:
    names: list[str] = []
    for item in items:
        if not isinstance(item, str) or item not in _GRANT_CAPABILITIES:
            return None
        names.append(item)
    if any(left >= right for left, right in pairwise(names)):
        return None
    return names


def grant_script_roots(plan: Mapping[str, object], expected: ExpectedGrant | None) -> list[object] | None:
    """The plan's script read roots once its grant fields check out; `None` refuses.

    A base plan carries no grant. A grant plan must match the decided grant: same
    identity, a canonical subset of its capabilities and, with a state
    capability, the CLI state directory as the last read root.
    """
    roots = plan.get("read_only_roots")
    raw = plan.get("capabilities")
    if not isinstance(roots, list) or not isinstance(raw, list):
        return None
    capabilities = _canonical(raw)
    profile = plan.get("profile_version")
    if capabilities is None or not isinstance(profile, str) or "grant_identity_hash" not in plan:
        return None
    identity = plan["grant_identity_hash"]
    if expected is None:
        if profile == _BASE_PROFILE and identity is None and not capabilities:
            return list(roots)
        return None
    if (
        profile != _GRANT_PROFILE
        or not isinstance(identity, str)
        or identity != expected.identity_hash
        or any(name not in expected.capabilities for name in capabilities)
    ):
        return None
    if not _STATE_CAPABILITIES.intersection(capabilities):
        return list(roots)
    if not roots or expected.state_dir is None:
        return None
    last = roots[-1]
    return list(roots[:-1]) if isinstance(last, str) and last == expected.state_dir else None
