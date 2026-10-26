"""The origin Guard records for a remote MCP server it finds in a harness config."""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

MASKED_PATH_SEGMENT = "[masked]"


def remote_mcp_origin(url: str) -> str | None:
    """Return ``scheme://host/path``: query, fragment and credentials never persist.

    Some hosted servers carry the account key in the path, so a path segment
    that looks like a key is masked before the origin is stored or shown.
    """

    try:
        parts = urlsplit(url.strip())
        hostname = parts.hostname
        port = parts.port
    except ValueError:
        return None
    if parts.scheme.lower() not in {"http", "https"} or not hostname:
        return None
    host = f"[{hostname}]" if ":" in hostname else hostname
    netloc = f"{host}:{port}" if port is not None else host
    path = "/".join(_masked_segment(segment) for segment in parts.path.split("/"))
    origin = urlunsplit((parts.scheme.lower(), netloc.lower(), path, "", ""))
    if len(origin) > 512 or any(character in origin for character in "?#@ ") or not origin.isprintable():
        return None
    return origin


def _masked_segment(segment: str) -> str:
    """A path segment, or a mask when it is long or mixes letters and digits."""

    looks_like_key = len(segment) >= 16 or (
        len(segment) >= 8 and any(c.isdigit() for c in segment) and any(c.isalpha() for c in segment)
    )
    return MASKED_PATH_SEGMENT if looks_like_key else segment
