"""Local TOTP helpers for HOL Guard approval gate."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import urllib.parse
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

_TOTP_PERIOD_SECONDS = 30
_TOTP_DIGITS = 6
_TOTP_ALGORITHM = "SHA1"
_TOTP_ISSUER = "HOL Guard"


class TotpSecretStore:
    """Encrypted secret store for local TOTP enrollment secrets."""

    def __init__(self, guard_home: Path) -> None:
        self.base_dir = guard_home / "totp-secrets"
        self.key_path = self.base_dir / "key.bin"
        self._fernet: Fernet | None = None

    def _ensure_ready(self) -> None:
        if self._fernet is not None:
            return
        self.base_dir.mkdir(parents=True, exist_ok=True)
        # Owner-only directory access is required for encrypted TOTP seed storage.
        os.chmod(self.base_dir, 0o700)  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions  # noqa: E501
        if not self.key_path.exists():
            self._atomic_write_bytes(self.key_path, Fernet.generate_key(), 0o600)
        key = self.key_path.read_bytes()
        self._fernet = Fernet(key)

    def set_secret(self, secret_id: str, value: str) -> None:
        self._ensure_ready()
        fernet = self._fernet
        if fernet is None:
            return
        payload = fernet.encrypt(value.encode("utf-8")).decode("ascii")
        self._atomic_write_text(self._path_for(secret_id), payload, 0o600)

    def get_secret(self, secret_id: str) -> str | None:
        self._ensure_ready()
        fernet = self._fernet
        if fernet is None:
            return None
        path = self._path_for(secret_id)
        if not path.exists():
            return None
        try:
            ciphertext = path.read_text(encoding="utf-8")
            plaintext = fernet.decrypt(ciphertext.encode("ascii"))
        except (OSError, InvalidToken, ValueError):
            return None
        try:
            return plaintext.decode("utf-8")
        except UnicodeDecodeError:
            return None

    def delete_secret(self, secret_id: str) -> None:
        path = self._path_for(secret_id)
        if path.exists():
            path.unlink()

    def _path_for(self, secret_id: str) -> Path:
        safe = "".join(ch for ch in secret_id if ch.isalnum() or ch in {"-", "_"})
        return self.base_dir / f"{safe}.secret"

    @staticmethod
    def _atomic_write_bytes(path: Path, payload: bytes, mode: int) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = path.with_suffix(path.suffix + ".tmp")
        tmp_path.write_bytes(payload)
        os.chmod(tmp_path, mode)
        tmp_path.replace(path)
        os.chmod(path, mode)

    @staticmethod
    def _atomic_write_text(path: Path, payload: str, mode: int) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = path.with_suffix(path.suffix + ".tmp")
        tmp_path.write_text(payload, encoding="utf-8")
        os.chmod(tmp_path, mode)
        tmp_path.replace(path)
        os.chmod(path, mode)


def generate_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def build_otpauth_uri(*, secret: str, device_label: str) -> str:
    safe_label = urllib.parse.quote(f"{_TOTP_ISSUER}:{device_label}", safe=":")
    params = urllib.parse.urlencode(
        {
            "secret": secret,
            "issuer": _TOTP_ISSUER,
            "algorithm": _TOTP_ALGORITHM,
            "digits": str(_TOTP_DIGITS),
            "period": str(_TOTP_PERIOD_SECONDS),
        },
        quote_via=urllib.parse.quote,
    )
    return f"otpauth://totp/{safe_label}?{params}"


def totp_counter(now_epoch: float) -> int:
    return int(now_epoch // _TOTP_PERIOD_SECONDS)


def verify_totp_code(
    *,
    secret: str,
    code: str,
    now_epoch: float,
    skew_steps: int,
    last_accepted_counter: int | None,
) -> int | None:
    normalized = code.strip()
    if len(normalized) != _TOTP_DIGITS or not normalized.isdigit():
        return None
    current = totp_counter(now_epoch)
    for offset in range(-skew_steps, skew_steps + 1):
        counter = current + offset
        if counter < 0:
            continue
        if last_accepted_counter is not None and counter <= last_accepted_counter:
            continue
        if hmac.compare_digest(totp_code_at_counter(secret=secret, counter=counter), normalized):
            return counter
    return None


def totp_code_at_counter(*, secret: str, counter: int) -> str:
    secret_bytes = base64.b32decode(_normalize_base32(secret), casefold=True)
    message = counter.to_bytes(8, byteorder="big", signed=False)
    digest = hmac.new(secret_bytes, message, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = (
        ((digest[offset] & 0x7F) << 24) | (digest[offset + 1] << 16) | (digest[offset + 2] << 8) | digest[offset + 3]
    )
    return f"{binary % (10**_TOTP_DIGITS):0{_TOTP_DIGITS}d}"


def _normalize_base32(value: str) -> str:
    normalized = value.strip().replace(" ", "").replace("-", "").upper()
    padding = "=" * ((8 - len(normalized) % 8) % 8)
    return normalized + padding
