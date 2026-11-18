"""Authenticated local identity records for Guard-managed Codex hooks.

The Codex configuration is user-editable and therefore cannot establish Guard
ownership by itself.  Ownership rests on a private, Guard-owned key file that only the native
runtime creates, reads, signs with and removes; canonical manifests are
authenticated with HMAC-SHA256 under it. Python sees only the key's public
identity, and the key is never copied into Codex configuration or returned
by status APIs.
"""

from __future__ import annotations

import base64
import os
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from .codex_hook_file_integrity import CodexHookIntegrityError, check_hook_validation_deadline
from .local_authority_integrity import LOCAL_AUTHORITY_INTEGRITY_MAC_ALGORITHM

HOOK_MANIFEST_SCHEMA_VERSION = 2
HOOK_MANIFEST_MAC_ALGORITHM = LOCAL_AUTHORITY_INTEGRITY_MAC_ALGORITHM
_PRIVATE_FILE_MODE = 0o600


@dataclass(frozen=True, slots=True)
class HookSecretMaterial:
    """The Codex hook key's public identity; the native runtime alone holds the key."""

    installation_id: str
    key_id: str
    fingerprint: str
    guard_home: Path = field(compare=False)


_KEY_MISSING_MESSAGE = (
    "The private Codex hook authentication key is missing; run `hol-guard install codex` to repair it."
)
_KEY_UNAVAILABLE_REASONS = frozenset({"runtime_unavailable", "invalid"})


_PATHS_FEATURE = "native-codex-hook-paths-v1"
_PATHS_COMMAND = "codex-hook-paths"
_PATHS_TIMEOUT_SECONDS = 10.0


@dataclass(frozen=True, slots=True)
class HookPaths:
    """The hook identity files one config target owns in a Guard home, as the runtime names them."""

    manifest: Path
    receipt: Path
    key: Path


def _paths_answer(guard_home: Path, config_path: Path | None) -> dict[str, object]:
    """The runtime's ``codex-hook-paths`` answer; a runtime that does not answer is
    a refused operation the caller repairs, never a guessed path."""

    from .mdm.runtime_request import runtime_answer

    request: dict[str, object] = {"guard_home": str(guard_home)}
    if config_path is not None:
        target = config_path.expanduser()
        request["config_path"] = str(target if target.is_absolute() else Path(os.getcwd()) / target)
    check_hook_validation_deadline()
    answer = runtime_answer(
        _PATHS_FEATURE,
        _PATHS_COMMAND,
        request,
        output_limit=64 * 1024,
        timeout_seconds=_PATHS_TIMEOUT_SECONDS,
    )
    check_hook_validation_deadline()
    if answer is None:
        raise hook_key_refusal("runtime_unavailable")
    return answer


def _named(answer: Mapping[str, object], key: str) -> Path:
    value = answer.get(key)
    if not isinstance(value, str) or not value:
        raise hook_key_refusal("runtime_unavailable")
    return Path(value)


def hook_paths(guard_home: Path, config_path: Path) -> HookPaths:
    """The manifest, receipt and key files ``config_path`` owns in ``guard_home``."""
    answer = _paths_answer(guard_home, config_path)
    return HookPaths(_named(answer, "manifest_path"), _named(answer, "receipt_path"), _named(answer, "key_path"))


def hook_manifest_file(guard_home: Path, config_path: Path) -> Path:
    """The manifest ``config_path`` owns in ``guard_home``, as the runtime names it."""
    return hook_paths(guard_home, config_path).manifest


def hook_secret_file(guard_home: Path) -> Path:
    """The Guard home's hook key file, as the runtime names it."""
    return _named(_paths_answer(guard_home, None), "key_path")


@contextmanager
def _ordinary_hook_writer(guard_home: Path, target: Path, *, actor: str) -> Iterator[None]:
    from .native_owned import codex_install_transaction
    from .runtime_transition import assert_transition_mutation_allowed

    assert_transition_mutation_allowed(guard_home)
    with codex_install_transaction(guard_home, target, actor=actor):
        assert_transition_mutation_allowed(guard_home)
        yield


def load_hook_secret(guard_home: Path) -> HookSecretMaterial:
    return _hook_key("key_identity", guard_home)


def _home_text(guard_home: Path) -> str:
    return os.path.abspath(guard_home)


_KeyOp = Literal["key_identity", "key_ensure", "key_remove_if_unused"]


def _hook_key_answer(op: _KeyOp, guard_home: Path) -> dict[str, object]:
    from .codex_hook_authority_record import AuthorityRecordRefusedError, hook_key_answer

    try:
        return hook_key_answer(op, _home_text(guard_home))
    except AuthorityRecordRefusedError as exc:
        raise hook_key_refusal(exc.reason) from exc


def hook_key_refusal(reason: str) -> CodexHookIntegrityError:
    """The error a refused hook key operation raises."""
    if reason in _KEY_UNAVAILABLE_REASONS:
        return CodexHookIntegrityError(
            "codex_hook_manifest_verification_unavailable",
            "Guard's native runtime did not answer for the Codex hook key; run `hol-guard repair`.",
        )
    message = (
        _KEY_MISSING_MESSAGE
        if reason == "codex_hook_manifest_secret_missing"
        else "The private Codex hook authentication key is not usable; repair the Codex installation."
    )
    return CodexHookIntegrityError(reason, message)


def _hook_key(op: _KeyOp, guard_home: Path) -> HookSecretMaterial:
    answer = _hook_key_answer(op, guard_home)
    fields = (answer.get("installation_id"), answer.get("key_id"), answer.get("fingerprint"))
    if not all(isinstance(value, str) and value for value in fields):
        raise CodexHookIntegrityError(
            "codex_hook_manifest_verification_unavailable",
            "Guard's native runtime did not answer for the Codex hook key; run `hol-guard repair`.",
        )
    installation_id, key_id, fingerprint = (str(value) for value in fields)
    return HookSecretMaterial(installation_id, key_id, fingerprint, guard_home)


def load_authenticated_hook_manifest_path(
    guard_home: Path,
    path: Path,
) -> dict[str, object]:
    """Authenticate an explicit private manifest path without creating state."""

    return _authenticated(guard_home, path=os.path.abspath(path))


def authenticate_hook_manifest_text(
    guard_home: Path,
    raw: str,
    *,
    _secret: HookSecretMaterial | None = None,
) -> dict[str, object]:
    """Authenticate captured text; the runtime refuses more than 1 MiB. This does not validate its file or package."""

    if _secret is None:
        return _authenticated(guard_home, text=raw)
    return _authenticated(_secret.guard_home, text=raw, key_id=_secret.key_id, installation_id=_secret.installation_id)


_REPAIR = "run `hol-guard install codex` to repair it."
_MANIFEST_MESSAGES = {
    "codex_hook_manifest_missing": f"The authenticated Codex hook manifest is missing; {_REPAIR}",
    "codex_hook_manifest_not_regular": "The Codex hook manifest must be a private regular file, not a symlink.",
    "codex_hook_manifest_owner_mismatch": "The Codex hook manifest has an unexpected owner.",
    "codex_hook_manifest_permissions_unsafe": "The Codex hook manifest permissions are not owner-only.",
    "codex_hook_manifest_invalid": f"The authenticated Codex hook manifest is unreadable; {_REPAIR}",
    "codex_hook_manifest_authentication_missing": f"The Codex hook manifest is not authenticated; {_REPAIR}",
    "codex_hook_manifest_authentication_invalid": (
        "The Codex hook manifest authentication metadata is invalid; repair the Codex installation."
    ),
    "codex_hook_manifest_key_mismatch": (
        "The Codex hook manifest belongs to another Guard installation; run `hol-guard install codex`."
    ),
    "codex_hook_manifest_installation_mismatch": (
        "The Codex hook manifest belongs to another Guard installation; run `hol-guard install codex`."
    ),
    "codex_hook_manifest_mac_invalid": f"The Codex hook manifest authentication failed; {_REPAIR}",
    "codex_hook_manifest_secret_missing": _KEY_MISSING_MESSAGE,
}


def _authenticated(guard_home: Path, **request: str | None) -> dict[str, object]:
    from .codex_hook_authority_record import AuthorityRecordRefusedError, authenticated_manifest

    check_hook_validation_deadline()
    try:
        manifest = authenticated_manifest(_home_text(guard_home), **request)
    except AuthorityRecordRefusedError as exc:
        check_hook_validation_deadline()
        raise manifest_refusal(exc.reason) from exc
    check_hook_validation_deadline()
    return manifest


def manifest_refusal(reason: str) -> CodexHookIntegrityError:
    """The status-safe refusal for a native manifest-authentication reason."""

    if reason in _KEY_UNAVAILABLE_REASONS:
        return CodexHookIntegrityError(
            "codex_hook_manifest_verification_unavailable",
            "Guard could not verify the Codex hook installation; run repair and retry.",
        )
    message = _MANIFEST_MESSAGES.get(
        reason, "The private Codex hook authentication key is not usable; repair the Codex installation."
    )
    return CodexHookIntegrityError(reason, message)


def atomic_write_text(
    path: Path,
    text: str,
    *,
    mode: int = _PRIVATE_FILE_MODE,
    on_publish: Callable[[tuple[int, int, int, int, int]], None] | None = None,
) -> None:
    atomic_write_bytes(path, text.encode("utf-8"), mode=mode, private=False, on_publish=on_publish)


def atomic_write_bytes(
    path: Path,
    payload: bytes,
    *,
    mode: int,
    private: bool,
    on_publish: Callable[[tuple[int, int, int, int, int]], None] | None = None,
    before_publish: Callable[[], None] | None = None,
) -> None:
    """Publish ``payload`` through the resident; it journals the write."""

    if before_publish is not None:
        before_publish()
    identity = _native(
        "write", path.parent, path=_path_text(path), payload=_encode(payload), mode=mode, private=private
    )
    if on_publish is not None:
        if not isinstance(identity, list) or len(identity) != 5 or not all(isinstance(part, int) for part in identity):
            raise CodexHookIntegrityError(
                "codex_hook_transaction_target_changed", "Codex configuration changed during publication."
            )
        on_publish((identity[0], identity[1], identity[2], identity[3], identity[4]))


def _path_text(path: Path) -> str:
    return os.path.abspath(path.expanduser())


def _encode(payload: bytes | None) -> str | None:
    return None if payload is None else base64.b64encode(payload).decode("ascii")


def _native(op: str, home: Path, **fields: Any) -> object:
    from .native_transition_files import publication

    return publication(op, home, **fields)


__all__ = [
    "HOOK_MANIFEST_MAC_ALGORITHM",
    "HOOK_MANIFEST_SCHEMA_VERSION",
    "CodexHookIntegrityError",
    "HookSecretMaterial",
    "atomic_write_text",
    "hook_manifest_file",
    "hook_secret_file",
    "load_authenticated_hook_manifest_path",
]
