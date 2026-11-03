"""Local CLI grant identity from the native runtime.

Grants for unlisted CLIs match on ``cli_id`` and ``identity_hash``. The
resident derives both from verified launch material, so Python never hashes
grant identity itself.

A failed or malformed answer yields no identity, which on its own would look
like "not a local CLI" and let a stored block silently stop applying. Callers
that apply grants or record observations therefore run inside
``track_local_cli_identity_failures`` and fail closed when it reports one.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Any, TypeGuard

from .native_context import _is_sha256_digest, _resolve_digest_home, native_context_digest

_CLI_ID_PATTERN = re.compile(r"^local-cli\.[a-z0-9]+(?:-[a-z0-9]+){0,8}$")
_IDENTITY_KEYS = frozenset({"cli_id", "name", "kind", "identity_hash"})
_KINDS = frozenset({"script", "executable"})
_UNLISTED_KEYS = frozenset(
    {
        "cli_id",
        "name",
        "kind",
        "identity_hash",
        "example_label",
        "interpreter_name",
        "source_path",
        "path_class",
        "runner",
        "identity_source",
    }
)
_UNLISTED_OPTIONAL_KEYS = ("interpreter_name", "source_path", "path_class", "runner")
# The resident gets one budget for parsing, launch derivation and hashing.
_IDENTIFY_BUDGET_MS = 2000
_IDENTIFY_TIMEOUT_SECONDS = 2.5
# Recognition may identify the paste and then the file it names.
_RECOGNIZE_BUDGET_MS = 4000
_RECOGNIZE_TIMEOUT_SECONDS = 4.5
_FAILURES: ContextVar[list[str] | None] = ContextVar("local_cli_identity_failures", default=None)


@contextmanager
def track_local_cli_identity_failures() -> Iterator[list[str]]:
    """Collect native identity failures raised while the block runs."""

    failures: list[str] = []
    token = _FAILURES.set(failures)
    try:
        yield failures
    finally:
        _FAILURES.reset(token)


def record_local_cli_identity_failure(reason: str) -> None:
    """Report a native failure to the enclosing ``track_local_cli_identity_failures``."""

    failures = _FAILURES.get()
    if failures is not None:
        failures.append(reason)


def valid_local_cli_identity(identity: object) -> TypeGuard[dict[str, str]]:
    """Whether ``identity`` is a well-formed ``LocalCliIdentityV1`` answer."""

    return (
        isinstance(identity, dict)
        and set(identity) == _IDENTITY_KEYS
        and all(isinstance(identity[key], str) for key in _IDENTITY_KEYS)
        and identity["kind"] in _KINDS
        and _is_sha256_digest(identity["identity_hash"])
        and _CLI_ID_PATTERN.fullmatch(identity["cli_id"]) is not None
    )


def _valid_unlisted_cli(record: object) -> TypeGuard[dict[str, Any]]:
    if not isinstance(record, dict) or set(record) != _UNLISTED_KEYS:
        return False
    core = {key: record[key] for key in _IDENTITY_KEYS}
    return (
        valid_local_cli_identity(core)
        and isinstance(record["example_label"], str)
        and all(record[key] is None or isinstance(record[key], str) for key in _UNLISTED_OPTIONAL_KEYS)
        and isinstance(record["identity_source"], dict)
        and isinstance(record["identity_source"].get("source"), str)
    )


def native_unlisted_cli_identities(
    command_text: str,
    *,
    cwd: Path,
    home_dir: Path | None,
    compound: bool,
) -> list[dict[str, Any]]:
    """Return the resident's unlisted-CLI identities for ``command_text``.

    The resident owns the whole derivation: parsing, runner unwrapping,
    launch identity, catalog ownership and the grant hash. ``compound`` also
    covers scripts sourced or launched inside a compound shell command. A
    native failure records one for ``track_local_cli_identity_failures`` and
    yields no identities, so tracked callers fail closed.
    """

    result = native_context_digest(
        "local_cli_identify",
        {
            "command_text": command_text,
            "cwd": str(cwd),
            "home_dir": None if home_dir is None else str(home_dir),
            "user_home": str(Path.home()),
            "compound": compound,
            "env": dict(os.environ),
            "budget_ms": _IDENTIFY_BUDGET_MS,
        },
        guard_home=_resolve_digest_home(None),
        timeout_seconds=_IDENTIFY_TIMEOUT_SECONDS,
    )
    if not isinstance(result, dict) or result.get("status") != "ok":
        record_local_cli_identity_failure("native_local_cli_identity_unavailable")
        return []
    records = result.get("local_cli_identities")
    if not isinstance(records, list) or not all(_valid_unlisted_cli(record) for record in records):
        record_local_cli_identity_failure("native_local_cli_identity_malformed")
        return []
    return records


def _valid_recognition(result: dict[str, Any], answer: str) -> bool:
    if answer == "candidates":
        found = result.get("candidates")
        return isinstance(found, list) and all(isinstance(item, str) for item in found)
    identity = result.get("identity")
    return (
        (identity is None or _valid_unlisted_cli(identity))
        and isinstance(result.get("error_code"), str)
        and isinstance(result.get("message"), str)
    )


def native_local_cli_recognition(
    command_text: str,
    *,
    cwd: Path,
    home_dir: Path,
    answer: str = "recognition",
    guard_home: Path | None = None,
) -> dict[str, Any] | None:
    """Return the resident's ``local_cli_recognize`` answer for a pasted command.

    ``answer="recognition"`` names the one unlisted CLI, or the reason there
    is none; ``answer="candidates"`` returns only the spellings it would try.
    A failed or malformed answer records a failure and yields ``None``.
    """

    from .native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    request = {
        "command_text": command_text,
        "cwd": str(cwd),
        "home_dir": str(home_dir),
        "user_home": str(Path.home()),
        "env": dict(os.environ),
        "budget_ms": _RECOGNIZE_BUDGET_MS,
        "answer": answer,
    }
    try:
        result = native_runner_authority(
            "local_cli_recognize",
            request,
            guard_home=_resolve_digest_home(guard_home),
            timeout_seconds=_RECOGNIZE_TIMEOUT_SECONDS,
        )
    except NativeRunnerAuthorityError:
        record_local_cli_identity_failure("native_local_cli_identity_unavailable")
        return None
    if not _valid_recognition(result, answer):
        record_local_cli_identity_failure("native_local_cli_identity_malformed")
        return None
    return result


__all__ = [
    "native_local_cli_recognition",
    "native_unlisted_cli_identities",
    "record_local_cli_identity_failure",
    "track_local_cli_identity_failures",
    "valid_local_cli_identity",
]
