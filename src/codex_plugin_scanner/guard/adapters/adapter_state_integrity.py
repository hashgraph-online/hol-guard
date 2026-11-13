"""Authentication for adapter lifecycle state containing filesystem paths.

An adapter's manifest records the configuration file Guard took over and the
backup it will restore, so a manifest an attacker can edit names a file Guard
overwrites during install, repair or uninstall. The MAC that stops that is
computed and compared in the native runtime, which also reads and creates the
key it signs with under ``<guard_home>/managed``; this module names that Guard
home and applies the verdict. Without the runtime there is no verdict, so
nothing authenticates.
"""

from __future__ import annotations

import os
from pathlib import Path

from ..native_adapter_state_integrity import (
    AdapterStateIntegrityUnavailableError,
    adapter_state_runtime_available,
    native_adapter_state_integrity,
)

_KEY_FILENAME = "adapter-state.key"


def require_adapter_state_runtime(guard_home: Path) -> None:
    """Refuse a lifecycle change nothing will be able to authenticate.

    An install writes the harness configuration first and stamps its manifest
    last, so a resident that cannot answer turns the whole install into a
    half-applied one: the user's configuration is changed and no authenticated
    state records what to put back. Asking first keeps that failure before the
    first write.
    """

    if not adapter_state_runtime_available(guard_home):
        raise AdapterStateIntegrityUnavailableError


def authenticate_adapter_state(
    guard_home: Path,
    *,
    harness: str,
    payload: dict[str, object],
    create_key: bool = True,
) -> dict[str, object]:
    """Return ``payload`` with the authentication block the runtime computed.

    The runtime signs with the key under ``guard_home``, creating it when
    ``create_key`` allows. Without ``create_key`` a missing key raises
    ``FileNotFoundError`` and an unusable one ``ValueError``.
    """

    if not create_key and not os.path.lexists(_key_path(guard_home)):
        raise FileNotFoundError("adapter state key is missing")
    return native_adapter_state_integrity(
        action="authenticate",
        harness=harness,
        payload=payload,
        key_home=guard_home,
        create_key=create_key,
        guard_home=guard_home,
    )


def adapter_state_is_authenticated(
    guard_home: Path,
    *,
    harness: str,
    payload: dict[str, object],
) -> bool:
    """Whether the runtime recomputes the manifest's own authentication block."""

    return _answer(guard_home, action="verify", harness=harness, payload=payload) is not None


def authenticated_adapter_path(
    guard_home: Path,
    *,
    harness: str,
    payload: dict[str, object],
    field: str,
) -> Path | None:
    """Return a canonical path only when its complete state payload authenticates."""

    answer = _answer(guard_home, action="authenticated_field", harness=harness, payload=payload, field=field)
    if answer is None:
        return None
    value = answer.get("value")
    if not isinstance(value, str):
        return None
    stored = Path(value)
    if not stored.is_absolute():
        # The runtime accepts either family's spelling, because a manifest can
        # be carried between machines. Resolution happens here, against this
        # host, where a foreign spelling such as ``C:\\Users\\dev\\x`` is a
        # relative path and would resolve against the working directory.
        return None
    # The runtime authenticated this complete payload, and rejected a relative
    # path or one carrying a NUL, before the stored path is resolved here.
    # Sonar cannot model that application-level sanitizer.
    return stored.resolve()  # NOSONAR


def _answer(
    guard_home: Path,
    *,
    action: str,
    harness: str,
    payload: dict[str, object],
    field: str | None = None,
) -> dict[str, object] | None:
    """The runtime's answer, or ``None`` when it did not authenticate the state.

    A missing key file and an unusable one are the same answer here: the
    stored state is not Guard's own. An unavailable runtime is not. It is no
    answer at all, and callers act on "not Guard's own" by discarding the
    state — Hermes falls back to legacy cleanup and deletes the saved previous
    section, Copilot skips the backup it would have restored — so the error
    travels instead of being read as a verdict nothing produced.
    """

    if not os.path.lexists(_key_path(guard_home)):
        return None
    answer = native_adapter_state_integrity(
        action=action,
        harness=harness,
        payload=payload,
        field=field,
        key_home=guard_home,
        guard_home=guard_home,
    )
    return answer if answer.get("authenticated") is True else None


def _key_path(guard_home: Path) -> Path:
    return guard_home / "managed" / _KEY_FILENAME
