#!/usr/bin/env python3
"""Issue a root-signed native workspace-review authority record.

This is an offline custodian tool.  It accepts only a public, unsigned
authority request and emits the corresponding public signed record.  The
resident runtime remains the source of truth for installed-state transitions.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import stat
import sys
import tempfile
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from pathlib import Path
from typing import Final, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

MAX_AUTHORITY_BYTES: Final = 16 * 1024
MAX_TTL_MS: Final = 365 * 24 * 60 * 60 * 1000
MAX_SAFE_INTEGER: Final = (1 << 53) - 1
ED25519_PUBLIC_KEY_BYTES: Final = 32
ED25519_SIGNATURE_BYTES: Final = 64
SHA256_DIGEST_BYTES: Final = 32

SCHEMA: Final = "guard-native-workspace-review-authority.v1"
VERSION: Final = 1
PURPOSE: Final = "cloud_review_team_delegation"
KEY_ALGORITHM: Final = "ed25519"
SCOPE_CONTRACT_VERSION: Final = "guard-native-workspace-review-scope.v1"
ENROLLMENT_DOMAIN: Final = b"guard-native-workspace-review-enrollment-v1\0"

ROOT_SEED_ENV: Final = "HOL_GUARD_APPROVAL_ENROLLMENT_ROOT_SEED_HEX"
ROOT_PUBLIC_ENV: Final = "HOL_GUARD_APPROVAL_ENROLLMENT_ROOT_HEX"
ROOT_FINGERPRINT_ENV: Final = "HOL_GUARD_APPROVAL_ENROLLMENT_ROOT_FINGERPRINT_HEX"

UNSIGNED_FIELDS: Final = frozenset(
    {
        "schema",
        "version",
        "purpose",
        "key_algorithm",
        "key_id",
        "public_key",
        "workspace_binding",
        "device_binding",
        "installation_binding",
        "enrollment_generation",
        "previous_key_id",
        "scope_contract_version",
        "scope_binding",
        "issued_at_ms",
        "expires_at_ms",
        "status",
    }
)
SIGNED_FIELDS: Final = UNSIGNED_FIELDS | {"enrollment_signature"}


class AuthorityIssuerError(ValueError):
    """Expected request, configuration, cryptographic, or filesystem error."""


class _DuplicateKeyError(ValueError):
    pass


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> object:
    raise ValueError


def _parse_json(data: bytes) -> object:
    try:
        parsed: object = cast(
            object,
            json.loads(
                data.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_json_constant,
            ),
        )
        return parsed
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise AuthorityIssuerError("invalid workspace review request") from error


def _is_lower_hex(value: object, byte_count: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == byte_count * 2
        and all(character in "0123456789abcdef" for character in value)
    )


def _require_lower_hex(value: object, byte_count: int) -> str:
    if not _is_lower_hex(value, byte_count):
        raise AuthorityIssuerError("invalid workspace review request")
    return cast(str, value)


def _require_safe_u64(value: object, *, positive: bool = False) -> int:
    if type(value) is not int or value < 0 or value > MAX_SAFE_INTEGER:
        raise AuthorityIssuerError("invalid workspace review request")
    if positive and value == 0:
        raise AuthorityIssuerError("invalid workspace review request")
    return value


def _now_ms() -> int:
    return time.time_ns() // 1_000_000


def canonical_json_bytes(value: Mapping[str, object]) -> bytes:
    """Return the compact, sorted JSON bytes emitted by the Rust contract."""

    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, UnicodeEncodeError, ValueError) as error:
        raise AuthorityIssuerError("invalid workspace review request") from error


def validate_request(value: object, *, now_ms: int | None = None) -> dict[str, object]:
    """Validate and return an unsigned workspace-review authority request.

    Validation is deliberately independent of root configuration so callers
    can validate a public request before a separate custodian signing step.
    """

    if not isinstance(value, dict):
        raise AuthorityIssuerError("invalid workspace review request")
    raw_value = cast(dict[object, object], value)
    request: dict[str, object] = {}
    for key, item in raw_value.items():
        if not isinstance(key, str):
            raise AuthorityIssuerError("invalid workspace review request")
        request[key] = item
    if frozenset(request) != UNSIGNED_FIELDS:
        raise AuthorityIssuerError("invalid workspace review request")

    schema = request.get("schema")
    purpose = request.get("purpose")
    key_algorithm = request.get("key_algorithm")
    scope_contract_version = request.get("scope_contract_version")
    status = request.get("status")
    if (
        schema != SCHEMA
        or purpose != PURPOSE
        or key_algorithm != KEY_ALGORITHM
        or scope_contract_version != SCOPE_CONTRACT_VERSION
        or not all(isinstance(item, str) for item in (schema, purpose, key_algorithm, scope_contract_version, status))
    ):
        raise AuthorityIssuerError("invalid workspace review request")
    if status not in {"active", "revoked"}:
        raise AuthorityIssuerError("invalid workspace review request")

    version = _require_safe_u64(request.get("version"))
    if version != VERSION:
        raise AuthorityIssuerError("invalid workspace review request")

    public_key_hex = _require_lower_hex(request.get("public_key"), ED25519_PUBLIC_KEY_BYTES)
    key_id = _require_lower_hex(request.get("key_id"), SHA256_DIGEST_BYTES)
    workspace_binding = _require_lower_hex(request.get("workspace_binding"), SHA256_DIGEST_BYTES)
    device_binding = _require_lower_hex(request.get("device_binding"), SHA256_DIGEST_BYTES)
    installation_binding = _require_lower_hex(request.get("installation_binding"), SHA256_DIGEST_BYTES)
    scope_binding = _require_lower_hex(request.get("scope_binding"), SHA256_DIGEST_BYTES)
    if device_binding == installation_binding:
        raise AuthorityIssuerError("invalid workspace review request")

    try:
        public_key = bytes.fromhex(public_key_hex)
    except ValueError as error:
        raise AuthorityIssuerError("invalid workspace review request") from error
    expected_key_id = hashlib.sha256(public_key).hexdigest()
    if not hmac.compare_digest(key_id, expected_key_id):
        raise AuthorityIssuerError("invalid workspace review request")

    generation = _require_safe_u64(request.get("enrollment_generation"), positive=True)
    previous_value = request.get("previous_key_id")
    if previous_value is not None:
        previous_key_id = _require_lower_hex(previous_value, SHA256_DIGEST_BYTES)
        if hmac.compare_digest(previous_key_id, key_id) or status == "revoked":
            raise AuthorityIssuerError("invalid workspace review request")
    elif generation > 1 and status == "active":
        raise AuthorityIssuerError("invalid workspace review request")
    if generation == 1 and (previous_value is not None or status != "active"):
        raise AuthorityIssuerError("invalid workspace review request")

    issued_at_ms = _require_safe_u64(request.get("issued_at_ms"), positive=True)
    expires_at_ms = _require_safe_u64(request.get("expires_at_ms"), positive=True)
    if expires_at_ms <= issued_at_ms or expires_at_ms - issued_at_ms > MAX_TTL_MS:
        raise AuthorityIssuerError("invalid workspace review request")
    effective_now_ms = _now_ms() if now_ms is None else _require_safe_u64(now_ms)
    if issued_at_ms > effective_now_ms or effective_now_ms >= expires_at_ms:
        raise AuthorityIssuerError("invalid workspace review request")

    request["workspace_binding"] = workspace_binding
    request["scope_binding"] = scope_binding

    # Return a fresh object so signing cannot mutate a caller-owned mapping.
    return {key: request[key] for key in UNSIGNED_FIELDS}


def _read_request(path: Path, expected_sha256: str | None = None) -> dict[str, object]:
    try:
        before = os.lstat(path)
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise AuthorityIssuerError("invalid workspace review request")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
    except (OSError, TypeError) as error:
        raise AuthorityIssuerError("invalid workspace review request") from error
    try:
        opened = os.fstat(fd)
        if (
            stat.S_ISLNK(opened.st_mode)
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
            or opened.st_size > MAX_AUTHORITY_BYTES
        ):
            raise AuthorityIssuerError("invalid workspace review request")
        data = os.read(fd, MAX_AUTHORITY_BYTES + 1)
        after = os.fstat(fd)
        if (
            after.st_dev != opened.st_dev
            or after.st_ino != opened.st_ino
            or after.st_size != opened.st_size
            or len(data) != after.st_size
            or len(data) > MAX_AUTHORITY_BYTES
        ):
            raise AuthorityIssuerError("invalid workspace review request")
    except OSError as error:
        raise AuthorityIssuerError("invalid workspace review request") from error
    finally:
        os.close(fd)
    if expected_sha256 is not None and (
        not _is_lower_hex(expected_sha256, SHA256_DIGEST_BYTES)
        or not hmac.compare_digest(hashlib.sha256(data).hexdigest(), expected_sha256)
    ):
        raise AuthorityIssuerError("invalid workspace review request")
    parsed = _parse_json(data)
    return validate_request(parsed)


def _decode_env_hex(environment: Mapping[str, str], name: str, byte_count: int) -> bytes:
    value = environment.get(name)
    if not _is_lower_hex(value, byte_count):
        raise AuthorityIssuerError("root enrollment configuration is invalid")
    try:
        return bytes.fromhex(cast(str, value))
    except ValueError as error:
        raise AuthorityIssuerError("root enrollment configuration is invalid") from error


def _root_signing_key(environment: Mapping[str, str]) -> tuple[Ed25519PrivateKey, bytes]:
    seed = _decode_env_hex(environment, ROOT_SEED_ENV, ED25519_PUBLIC_KEY_BYTES)
    pinned_public = _decode_env_hex(environment, ROOT_PUBLIC_ENV, ED25519_PUBLIC_KEY_BYTES)
    pinned_fingerprint = _decode_env_hex(environment, ROOT_FINGERPRINT_ENV, SHA256_DIGEST_BYTES)
    try:
        private_key = Ed25519PrivateKey.from_private_bytes(seed)
        derived_public = private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    except ValueError as error:
        raise AuthorityIssuerError("root enrollment configuration is invalid") from error
    pin_matches = hmac.compare_digest(derived_public, pinned_public)
    fingerprint_matches = hmac.compare_digest(hashlib.sha256(derived_public).digest(), pinned_fingerprint)
    if not (pin_matches and fingerprint_matches):
        raise AuthorityIssuerError("root enrollment configuration is invalid")
    return private_key, derived_public


def _unsigned_signing_bytes(request: Mapping[str, object]) -> bytes:
    return ENROLLMENT_DOMAIN + canonical_json_bytes(request)


def sign_request(
    value: object,
    *,
    now_ms: int | None = None,
    environment: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Validate and sign one unsigned request using the configured root seed."""

    request = validate_request(value, now_ms=now_ms)
    private_key, root_public = _root_signing_key(os.environ if environment is None else environment)
    signature = private_key.sign(_unsigned_signing_bytes(request)).hex()
    signed = dict(request)
    signed["enrollment_signature"] = signature
    if frozenset(signed) != SIGNED_FIELDS:
        raise AuthorityIssuerError("invalid workspace review authority")
    signed_bytes = canonical_json_bytes(signed)
    if len(signed_bytes) > MAX_AUTHORITY_BYTES:
        raise AuthorityIssuerError("invalid workspace review authority")
    try:
        Ed25519PublicKey.from_public_bytes(root_public).verify(
            bytes.fromhex(signature), _unsigned_signing_bytes(request)
        )
    except (InvalidSignature, ValueError) as error:
        raise AuthorityIssuerError("invalid workspace review authority") from error
    return signed


def _same_file(path: Path, identity: tuple[int, int]) -> bool:
    try:
        metadata = os.lstat(path)
    except OSError:
        return False
    return (metadata.st_dev, metadata.st_ino) == identity


def _file_identity(path: Path) -> tuple[int, int]:
    metadata = os.lstat(path)
    return metadata.st_dev, metadata.st_ino


def _unlink_owned(path: Path, identity: tuple[int, int]) -> None:
    if _same_file(path, identity):
        with suppress(OSError):
            os.unlink(path)


def _fsync_parent(path: Path) -> None:
    if os.name == "nt" or not hasattr(os, "O_DIRECTORY"):
        return
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    directory_fd = os.open(path.parent, flags)
    try:
        _ = os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _assert_private_output_parent(path: Path) -> None:
    try:
        metadata = os.lstat(path.parent)
    except OSError as error:
        raise AuthorityIssuerError("workspace review authority output is unavailable") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise AuthorityIssuerError("workspace review authority output is unavailable")
    if os.name == "nt":
        return
    getuid = cast(Callable[[], int] | None, getattr(os, "getuid", None))
    if getuid is None or metadata.st_uid != getuid() or stat.S_IMODE(metadata.st_mode) & 0o022:
        raise AuthorityIssuerError("workspace review authority output is unavailable")


def _link_without_following(source: Path, destination: Path) -> None:
    try:
        os.link(source, destination, follow_symlinks=False)
    except (NotImplementedError, TypeError, ValueError) as error:
        raise OSError("safe hard-link publication is unavailable") from error


def _assert_published_file(path: Path, identity: tuple[int, int]) -> None:
    try:
        metadata = os.lstat(path)
    except OSError as error:
        raise OSError("published authority output is unavailable") from error
    if not stat.S_ISREG(metadata.st_mode) or (metadata.st_dev, metadata.st_ino) != identity:
        raise OSError("published authority output identity changed")


def _write_new_private(path: Path, data: bytes) -> None:
    if len(data) > MAX_AUTHORITY_BYTES:
        raise AuthorityIssuerError("workspace review authority output is unavailable")
    _assert_private_output_parent(path)
    try:
        existing = os.lstat(path)
    except FileNotFoundError:
        existing = None
    except OSError as error:
        raise AuthorityIssuerError("workspace review authority output is unavailable") from error
    if existing is not None:
        if stat.S_ISLNK(existing.st_mode) or not stat.S_ISREG(existing.st_mode):
            raise AuthorityIssuerError("workspace review authority output is unavailable")
        raise AuthorityIssuerError("workspace review authority output is unavailable")

    descriptor: int | None = None
    temporary: Path | None = None
    temporary_identity: tuple[int, int] | None = None
    published = False
    published_identity: tuple[int, int] | None = None
    try:
        descriptor_value, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
        )
        descriptor = descriptor_value
        temporary = Path(temporary_name)
        metadata = os.fstat(descriptor)
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise OSError("temporary authority output is not regular")
        temporary_identity = (metadata.st_dev, metadata.st_ino)
        fchmod = cast(Callable[[int, int], None] | None, getattr(os, "fchmod", None))
        if fchmod is not None:
            _ = fchmod(descriptor, 0o600)
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("authority output write made no progress")
            view = view[written:]
        _ = os.fsync(descriptor)

        _link_without_following(temporary, path)
        published = True
        published_identity = _file_identity(path)
        _assert_published_file(path, temporary_identity)
        os.close(descriptor)
        descriptor = None
        _fsync_parent(path)
        os.unlink(temporary)
        temporary = None
        _fsync_parent(path)
    except Exception as error:
        if descriptor is not None:
            with suppress(OSError):
                os.close(descriptor)
        if temporary_identity is not None:
            if published and published_identity is not None:
                _unlink_owned(path, published_identity)
            if temporary is not None:
                _unlink_owned(temporary, temporary_identity)
        if isinstance(error, AuthorityIssuerError):
            raise
        raise AuthorityIssuerError("workspace review authority output is unavailable") from error


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Issue a native workspace-review authority record.")
    _ = parser.add_argument("--request", required=True, type=Path)
    _ = parser.add_argument("--expected-request-sha256")
    mode = parser.add_mutually_exclusive_group()
    _ = mode.add_argument("--output", type=Path)
    _ = mode.add_argument("--validate-only", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    validate_only = cast(bool, args.validate_only)
    expected_sha256 = cast(str | None, args.expected_request_sha256)
    if validate_only:
        output = None
    else:
        output = cast(Path | None, args.output)
        if output is None:
            parser.error("--output is required unless --validate-only is used")
        if expected_sha256 is None:
            parser.error("--expected-request-sha256 is required for signing")
    stage = "request validation"
    try:
        request = _read_request(cast(Path, args.request), expected_sha256)
        if validate_only:
            return 0
        stage = "root signing"
        signed = sign_request(request)
        assert output is not None
        stage = "output publication"
        _write_new_private(output, canonical_json_bytes(signed))
        return 0
    except Exception:
        print(f"workspace review authority operation rejected during {stage}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
