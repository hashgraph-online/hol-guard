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
_FAILURES: ContextVar[list[str] | None] = ContextVar("local_cli_identity_failures", default=None)


class LocalCliIdentityUnavailableError(RuntimeError):
    """The resident could not derive an identity the command may need."""


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


def native_local_cli_identity(source: dict[str, Any], *, guard_home: Path | None = None) -> dict[str, str] | None:
    """Return ``{cli_id, name, kind, identity_hash}`` or ``None``.

    ``source`` is one ``LocalCliIdentitySourceV1`` variant, tagged by
    ``source``. ``None`` covers both "not a grantable identity" and native
    failure; a failure is also recorded for ``track_local_cli_identity_failures``.
    """

    result = native_context_digest(
        "local_cli_identity",
        {"source": source},
        guard_home=_resolve_digest_home(guard_home),
    )
    if not isinstance(result, dict) or result.get("status") != "ok":
        return record_local_cli_identity_failure("native_local_cli_identity_unavailable")
    if "local_cli_identity" not in result:
        return None
    identity = result.get("local_cli_identity")
    if not valid_local_cli_identity(identity):
        return record_local_cli_identity_failure("native_local_cli_identity_malformed")
    return identity


__all__ = [
    "LocalCliIdentityUnavailableError",
    "native_local_cli_identity",
    "record_local_cli_identity_failure",
    "track_local_cli_identity_failures",
    "valid_local_cli_identity",
]
