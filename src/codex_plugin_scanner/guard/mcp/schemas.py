"""Contract constants and schema definitions for guard-mcp.v1."""

from __future__ import annotations

import re
from enum import Enum

CONTRACT_VERSION = "guard-mcp.v1"
SOURCE_LOCAL = "local"

DEFAULT_SEARCH_LIMIT = 10
MAX_SEARCH_LIMIT = 20
MAX_FETCH_TEXT_BYTES = 32768  # 32 KiB

ID_NAMESPACES = ("receipt:", "artifact:", "inventory:", "device:")


class ResultKind(str, Enum):
    RECEIPT = "receipt"
    ARTIFACT = "artifact"
    INVENTORY = "inventory"
    DEVICE = "device"


class DecisionCategory(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    WARN = "warn"
    BLOCK = "block"
    UNKNOWN = "unknown"


class HarnessName(str, Enum):
    CODEX = "codex"
    CLAUDE = "claude"
    CURSOR = "cursor"
    COPILOT = "copilot"
    OPENCODE = "opencode"
    GEMINI = "gemini"
    HERMES = "hermes"
    OPENCLAW = "openclaw"
    ANTIGRAVITY = "antigravity"
    PI = "pi"


VALID_HARNESSES = frozenset(h.value for h in HarnessName)
VALID_DECISIONS = frozenset(d.value for d in DecisionCategory)
VALID_KINDS = frozenset(k.value for k in ResultKind)

_ID_PATTERN = re.compile(r"^(receipt|artifact|inventory|device):[a-zA-Z0-9_-]+$")


def is_valid_id(raw: str) -> bool:
    if not raw or len(raw) > 256:
        return False
    return bool(_ID_PATTERN.match(raw))


def make_opaque_id(kind: str, internal_id: str) -> str:
    import hashlib

    digest = hashlib.sha256(f"{kind}:{internal_id}".encode()).hexdigest()[:24]
    return f"{kind}:{digest}"
