"""Detection of the MCP Skills extension declaration."""

from __future__ import annotations

import re
from datetime import date

_EXTENSION = "io.modelcontextprotocol/skills"
_PROTOCOL_VERSION = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}\Z")
_MIN_SKILLS_VERSION = date(2026, 7, 28)


def mcp_skills_declared(capabilities: object, *, protocol_version: str) -> bool:
    if not isinstance(protocol_version, str) or not _PROTOCOL_VERSION.fullmatch(protocol_version):
        return False
    try:
        if date.fromisoformat(protocol_version) < _MIN_SKILLS_VERSION:
            return False
    except ValueError:
        return False
    if not isinstance(capabilities, dict):
        return False
    extensions = capabilities.get("extensions")
    declaration = extensions.get(_EXTENSION) if isinstance(extensions, dict) else None
    return isinstance(capabilities.get("resources"), dict) and isinstance(declaration, dict)
