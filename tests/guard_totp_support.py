"""TOTP helpers for tests that drive the native approval gate.

The approval gate enrolls, stores and verifies TOTP seeds natively. Tests only
need to read back a seed the runtime stored and compute the code a device would
show for it.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
from pathlib import Path

from cryptography.fernet import Fernet

_TOTP_DIGITS = 6


def read_totp_secret(guard_home: Path, secret_id: str) -> str | None:
    """Decrypt a seed the native secret store wrote under ``guard_home``."""

    base_dir = guard_home / "totp-secrets"
    safe = "".join(ch for ch in secret_id if ch.isalnum() or ch in {"-", "_"})
    path = base_dir / f"{safe}.secret"
    if not path.exists():
        return None
    fernet = Fernet((base_dir / "key.bin").read_bytes())
    return fernet.decrypt(path.read_text(encoding="utf-8").encode("ascii")).decode("utf-8")


def totp_code_at_counter(*, secret: str, counter: int) -> str:
    normalized = secret.strip().replace(" ", "").replace("-", "").upper()
    secret_bytes = base64.b32decode(normalized + "=" * ((8 - len(normalized) % 8) % 8), casefold=True)
    message = counter.to_bytes(8, byteorder="big", signed=False)
    digest = hmac.new(secret_bytes, message, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = (
        ((digest[offset] & 0x7F) << 24) | (digest[offset + 1] << 16) | (digest[offset + 2] << 8) | digest[offset + 3]
    )
    return f"{binary % (10**_TOTP_DIGITS):0{_TOTP_DIGITS}d}"
