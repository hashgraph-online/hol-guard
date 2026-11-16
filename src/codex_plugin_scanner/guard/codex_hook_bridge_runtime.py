"""Decode the config argument a managed Codex hook registration carries."""

from __future__ import annotations

import base64
import binascii
import re

_BASE64URL_ARGUMENT = re.compile(r"[A-Za-z0-9_-]+")


def decode_bridge_config_argument(argument: str) -> str:
    """Return the JSON text of a bridge config argument.

    POSIX installs pass the JSON itself. Windows installs pass unpadded
    base64url text because the Windows shells cannot carry JSON quotes intact.
    """

    if argument.startswith("{"):
        return argument
    if not _BASE64URL_ARGUMENT.fullmatch(argument):
        raise ValueError("bridge config argument is neither JSON nor base64url")
    try:
        text = base64.urlsafe_b64decode(argument + "=" * (-len(argument) % 4)).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError) as exc:
        raise ValueError("bridge config argument is not valid base64url") from exc
    if not text.startswith("{"):
        raise ValueError("bridge config argument does not encode a JSON object")
    return text


__all__ = ["decode_bridge_config_argument"]
