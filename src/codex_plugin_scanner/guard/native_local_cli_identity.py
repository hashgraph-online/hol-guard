"""Local CLI grant identity from the native runtime.

Grants for unlisted CLIs match on ``cli_id`` and ``identity_hash``. The
resident derives both from verified launch material, so Python never hashes
grant identity itself. A missing or malformed answer yields no identity, and
no grant can match a command without one.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .native_context import _is_sha256_digest, _resolve_digest_home, native_context_digest

_CLI_ID_PATTERN = re.compile(r"^local-cli\.[a-z0-9]+(?:-[a-z0-9]+){0,8}$")
_IDENTITY_KEYS = frozenset({"cli_id", "name", "kind", "identity_hash"})
_KINDS = frozenset({"script", "executable"})


def native_local_cli_identity(source: dict[str, Any], *, guard_home: Path | None = None) -> dict[str, str] | None:
    """Return ``{cli_id, name, kind, identity_hash}`` or ``None``.

    ``source`` is one ``LocalCliIdentitySourceV1`` variant, tagged by
    ``source``. ``None`` covers both "not a grantable identity" and native
    unavailability; either way no grant applies.
    """

    result = native_context_digest(
        "local_cli_identity",
        {"source": source},
        guard_home=_resolve_digest_home(guard_home),
    )
    if not isinstance(result, dict) or result.get("status") != "ok":
        return None
    identity = result.get("local_cli_identity")
    if (
        not isinstance(identity, dict)
        or set(identity) != _IDENTITY_KEYS
        or any(not isinstance(identity[key], str) for key in _IDENTITY_KEYS)
        or identity["kind"] not in _KINDS
        or not _is_sha256_digest(identity["identity_hash"])
        or _CLI_ID_PATTERN.fullmatch(identity["cli_id"]) is None
    ):
        return None
    return identity


__all__ = ["native_local_cli_identity"]
