"""JSON transport hardening shared by Guard HTTP surfaces."""

from __future__ import annotations


def escape_json_for_html(payload: bytes) -> bytes:
    """Escape markup-significant bytes without changing decoded JSON values."""

    return payload.replace(b"&", b"\\u0026").replace(b"<", b"\\u003c").replace(b">", b"\\u003e")


__all__ = ["escape_json_for_html"]
