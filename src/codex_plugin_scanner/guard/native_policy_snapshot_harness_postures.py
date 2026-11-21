"""Carry per-harness posture beside, not inside, the native policy snapshot.

The Rust resident validates a strict snapshot schema and never decides
recording-only delivery; Python converts verdicts after native evaluation. So
per-harness Watch cannot be (and need not be) a snapshot field. It rides the
same publish/ACK path instead:

* the publisher captures the overrides at the ACK commit and serves them in
  its in-memory binding, and
* a verifier-key MAC'd sidecar bound to the ACKed generation and policy digest
  serves workers that read the signed snapshot file.

A missing, stale, or unauthenticated sidecar yields no overrides, so hooks fall
back to the ACKed snapshot mode. A local config edit therefore cannot weaken an
enforcing ACKed snapshot until the publisher has re-ACKed with the edit.

The sidecar also signs when each Watch reverts, so a hook bridge whose daemon
is down stops treating a harness as in Watch at the deadline the daemon would
have reverted it. A publish that changes what the sidecar signs takes a new
generation, so stopping before the sidecar is written leaves the old sidecar
bound to a generation that is no longer ACKed.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
from collections.abc import Mapping
from pathlib import Path

from .native_policy_snapshot_codec import derive_native_policy_verifier_key
from .native_policy_snapshot_constants import NativePolicySnapshotError
from .protection_posture import VALID_PROTECTION_POSTURES

logger = logging.getLogger(__name__)

HARNESS_POSTURES_BINDING_KEY = "harness_postures"
HARNESS_POSTURES_SIDECAR_NAME = "harness-postures-v1.json"
_SIDECAR_SCHEMA = "guard-harness-postures.v2"
_SIDECAR_DOMAIN = b"hol-guard/harness-postures/v2\0"
_MAX_SIDECAR_BYTES = 16 * 1024


def valid_harness_postures(value: object) -> dict[str, str]:
    """Keep only well-formed ``harness -> posture`` pairs."""

    if not isinstance(value, Mapping):
        return {}
    return {
        key: posture
        for key, posture in value.items()
        if isinstance(key, str) and key and isinstance(posture, str) and posture in VALID_PROTECTION_POSTURES
    }


def _verifier_key_for_store(store: object) -> bytes | None:
    material_getter = getattr(store, "_policy_integrity_secret_material", None)
    if not callable(material_getter):
        return None
    try:
        material = material_getter(create=False)
    except Exception:
        logger.debug("Native policy integrity material is unavailable", exc_info=True)
        return None
    if not isinstance(material, tuple) or len(material) != 2 or not isinstance(material[0], bytes):
        return None
    try:
        return derive_native_policy_verifier_key(material[0])
    except NativePolicySnapshotError:
        return None


WatchEnds = tuple[int | None, dict[str, int]]
"""When the machine-wide Watch and each harness Watch override revert, in epoch microseconds."""


def signed_watch_ends(postures: Mapping[str, str], deadlines: WatchEnds | None) -> WatchEnds:
    """The Watch deadlines to sign beside ``postures``.

    Only Watch overrides keep a harness deadline. Unknown deadlines (``None``)
    sign every Watch as already over, so a bridge whose daemon is down never
    continues a call on a Watch whose end it cannot prove is still ahead.
    """

    watched = sorted(harness for harness, posture in valid_harness_postures(postures).items() if posture == "watch")
    if deadlines is None:
        return 0, dict.fromkeys(watched, 0)
    posture_at, harness_at = deadlines
    return posture_at, {harness: harness_at[harness] for harness in watched if harness in harness_at}


def _sidecar_fields(
    generation: int, policy_digest: str, postures: Mapping[str, str], watch_ends: WatchEnds
) -> dict[str, object]:
    return {
        "generation": generation,
        "policy_digest": policy_digest,
        "harness_postures": dict(sorted(postures.items())),
        "harness_watch_ends_at_us": dict(sorted(watch_ends[1].items())),
        "watch_ends_at_us": watch_ends[0],
    }


def _sidecar_mac(verifier_key: bytes, fields: Mapping[str, object]) -> str:
    body = json.dumps(dict(fields), separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hmac.new(verifier_key, _SIDECAR_DOMAIN + body, hashlib.sha256).hexdigest()


def _read_sidecar_document(guard_home: object) -> dict[str, object] | None:
    try:
        path = _sidecar_path(guard_home)
        if path.stat().st_size > _MAX_SIDECAR_BYTES:
            return None
        document = json.loads(path.read_bytes())
    except (OSError, ValueError, NativePolicySnapshotError):
        return None
    if not isinstance(document, dict) or document.get("schema") != _SIDECAR_SCHEMA:
        return None
    return document


def sidecar_generation_to_retire(store: object, *, postures: Mapping[str, str], watch_ends: WatchEnds) -> int | None:
    """The generation a publish must move past before it rewrites the sidecar.

    The materializer keeps the generation when only postures change, because
    they ride beside the snapshot. If that publish then stopped before the new
    sidecar was written, the old sidecar would still match the ACKed
    generation and keep proving the old posture to a bridge whose daemon is
    down. When the sidecar on disk signs something else, its generation is
    returned so the publisher renews past it. The file is read without
    authentication: it only decides whether to spend a new generation.
    """

    guard_home = getattr(store, "guard_home", None)
    if guard_home is None:
        return None
    document = _read_sidecar_document(guard_home)
    if document is None:
        return None
    generation = document.get("generation")
    if isinstance(generation, bool) or not isinstance(generation, int) or generation <= 0:
        return None
    expected = _sidecar_fields(generation, "", valid_harness_postures(postures), watch_ends)
    if all(
        document.get(key) == expected[key]
        for key in ("harness_postures", "harness_watch_ends_at_us", "watch_ends_at_us")
    ):
        return None
    return generation


def _sidecar_path(guard_home: object) -> Path:
    """Path inside the validated private runtime-state directory."""

    from .native_policy_snapshot_windows_support import _runtime_state_directory

    return _runtime_state_directory(Path(str(guard_home))) / HARNESS_POSTURES_SIDECAR_NAME


def _write_private_file(path: Path, payload: bytes) -> None:
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(16)}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, 0o600)
    try:
        written = 0
        while written < len(payload):
            written += os.write(descriptor, payload[written:])
        os.fsync(descriptor)
    except OSError:
        os.close(descriptor)
        with_suppressed_unlink(temporary)
        raise
    os.close(descriptor)
    try:
        os.replace(temporary, path)
    except OSError:
        with_suppressed_unlink(temporary)
        raise


def write_harness_postures_sidecar(
    store: object,
    *,
    generation: int,
    policy_digest: str,
    postures: Mapping[str, str],
    watch_ends: WatchEnds | None = None,
) -> dict[str, str]:
    """Persist overrides for the ACKed snapshot and return what readers will see.

    ``watch_ends`` are the revert deadlines from the configuration the
    overrides were compiled from; ``None`` signs every Watch as already over.

    Failure only means no overrides. The publisher binds the returned value, so
    its in-memory binding and readers of the signed file always agree. The
    file is written even when there are no overrides: it is the signed proof
    that there are none, which the native hook bridge needs before it trusts a
    Watch snapshot, because the snapshot is saved first and a publish can stop
    between the two writes.
    """

    guard_home = getattr(store, "guard_home", None)
    if guard_home is None:
        return {}
    verified = valid_harness_postures(postures)
    path: Path | None = None
    try:
        path = _sidecar_path(guard_home)
        verifier_key = _verifier_key_for_store(store)
        if verifier_key is None:
            path.unlink(missing_ok=True)
            return {}
        fields = _sidecar_fields(generation, policy_digest, verified, signed_watch_ends(verified, watch_ends))
        document = {"schema": _SIDECAR_SCHEMA, **fields, "mac": _sidecar_mac(verifier_key, fields)}
        _write_private_file(path, json.dumps(document, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    except (OSError, NativePolicySnapshotError):
        logger.warning("Could not persist per-harness posture sidecar; apps follow the global posture", exc_info=True)
        if path is not None:
            with_suppressed_unlink(path)
        return {}
    return verified


def with_suppressed_unlink(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:
        logger.debug("Could not remove per-harness posture sidecar", exc_info=True)


def read_harness_postures_sidecar(
    store: object,
    *,
    generation: int,
    policy_digest: str,
) -> dict[str, str]:
    """Return overrides only when authenticated and bound to this exact ACK."""

    guard_home = getattr(store, "guard_home", None)
    if guard_home is None:
        return {}
    verifier_key = _verifier_key_for_store(store)
    if verifier_key is None:
        return {}
    document = _read_sidecar_document(guard_home)
    if document is None:
        return {}
    raw_postures = document.get("harness_postures")
    postures = valid_harness_postures(raw_postures)
    harness_ends = document.get("harness_watch_ends_at_us")
    posture_end = document.get("watch_ends_at_us")
    mac = document.get("mac")
    if (
        document.get("generation") != generation
        or document.get("policy_digest") != policy_digest
        or not postures
        or not isinstance(raw_postures, dict)
        or len(postures) != len(raw_postures)
        or not isinstance(harness_ends, dict)
        or not all(isinstance(key, str) and type(at) is int for key, at in harness_ends.items())
        or not (posture_end is None or type(posture_end) is int)
        or not isinstance(mac, str)
    ):
        return {}
    fields = _sidecar_fields(generation, policy_digest, postures, (posture_end, harness_ends))
    if not hmac.compare_digest(mac, _sidecar_mac(verifier_key, fields)):
        return {}
    return postures


def binding_with_harness_postures(binding: dict[str, object], postures: Mapping[str, str]) -> dict[str, object]:
    verified = valid_harness_postures(postures)
    if verified:
        binding[HARNESS_POSTURES_BINDING_KEY] = dict(verified)
    return binding
