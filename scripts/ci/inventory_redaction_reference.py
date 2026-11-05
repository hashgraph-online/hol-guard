r"""The CPython oracle the inventory serializer-redaction corpus is recorded from.

These functions were `inventory_contract_redaction`'s serializer half until the
resident took the walk over. The corpus in
`rust/crates/guard-command/testdata/inventory_redaction_parity.json` exists to
prove the Rust port reproduces CPython's `re` and `json.dumps`, so it has to be
recorded from CPython. Asking the runtime that the corpus pins would pin that
runtime against itself and prove nothing.

This is generator tooling, not runtime code: nothing under `src/` imports it,
and a Guard install never runs it. Keep it what the module did on the
interpreter named in the fixture's `python_version`, and change it only to
track a deliberate change in the redaction contract, alongside the Rust owner
and a regenerated fixture.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

#: The constants as `inventory_contract_constants` spelled them while the
#: module owned these bodies.
_SENSITIVE_KEY_RE = re.compile(
    r"(auth|authorization|bearer|token|secret|password|credential|api[^a-z0-9]?key)",
    re.IGNORECASE,
)
_NON_SECRET_KEY = "evidenceauthority"
_SENSITIVE_VALUE_RE = re.compile(r"(?i)(gh[pousr]_[a-z0-9_]+|sk-[a-z0-9_-]+|guard_live_[a-z0-9_-]+|bearer\s+\S+)")
_UNSAFE_PATH_MARKERS = (
    "".join(("/", "Users", "/")),
    "".join(("/", "home", "/")),
    "".join(("/", "root", "/")),
    "".join(("\\", "Users", "\\")),
    "".join(("/", "var", "/", "folders", "/")),
    "".join(("/", "workspace", "/")),
    "".join(("/", "tmp", "/")),
    "".join(("/", "etc", "/")),
    "".join(("/", "mnt", "/")),
)
_SERIALIZER_UNSAFE_PATH_PATTERN = (
    r"(?:^|[\s\"'=:({])(?:" + "|".join(re.escape(marker) for marker in _UNSAFE_PATH_MARKERS) + ")"
)
_SERIALIZER_UNSAFE_PATH_RE = re.compile(_SERIALIZER_UNSAFE_PATH_PATTERN, re.IGNORECASE)
_SERIALIZER_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(?:api[_-]?key|authorization|password|secret|token|access[_-]?token|refresh[_-]?token)\b\s*[:=]\s*(?!redacted\b)\S+",
)
_SERIALIZER_REDACTED_VALUE = "[REDACTED]"
_SAFE_SERIALIZED_MARKERS = frozenset(
    {
        _SERIALIZER_REDACTED_VALUE,
        "present_redacted",
        "present",
        "redacted",
        "malformed_url_redacted",
    }
)


def _is_sensitive_key(key: str) -> bool:
    """Whether a metadata key names a credential and its value must be masked."""
    if key.isascii() and key.lower() == _NON_SECRET_KEY:
        return False
    return _SENSITIVE_KEY_RE.search(key) is not None


def _sanitize_serializer_string(
    value: str,
    *,
    parent_key: str = "",
    parent_sensitive: bool = False,
) -> str:
    """Apply final string redaction before inventory serialization."""
    if value in _SAFE_SERIALIZED_MARKERS:
        return value
    if parent_sensitive or (parent_key and _is_sensitive_key(parent_key)):
        return _SERIALIZER_REDACTED_VALUE
    if _SERIALIZER_UNSAFE_PATH_RE.search(value):
        return _SERIALIZER_REDACTED_VALUE
    if _SENSITIVE_VALUE_RE.search(value):
        return _SERIALIZER_REDACTED_VALUE
    if _SERIALIZER_SECRET_ASSIGNMENT_RE.search(value):
        return _SERIALIZER_REDACTED_VALUE
    return value


def _assert_serialized_inventory_payload_safe(payload: object) -> None:
    """Reject serialized inventory that still violates the export safety contract."""
    encoded = json.dumps(payload, sort_keys=True)
    if (
        _SERIALIZER_UNSAFE_PATH_RE.search(encoded)
        or _SENSITIVE_VALUE_RE.search(encoded)
        or _SERIALIZER_SECRET_ASSIGNMENT_RE.search(encoded)
    ):
        raise ValueError("Inventory snapshot serialization produced unsafe payload.")


def _safe_json(
    value: object,
    *,
    parent_key: str = "",
    parent_sensitive: bool = False,
) -> object:
    """Normalize metadata into bounded JSON-compatible evidence."""
    key_sensitive = parent_sensitive or bool(parent_key and _is_sensitive_key(parent_key))
    if isinstance(value, dict):
        return {
            _sanitize_serializer_string(str(key)): _safe_json(
                item,
                parent_key=str(key),
                parent_sensitive=key_sensitive,
            )
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_safe_json(item, parent_key=parent_key, parent_sensitive=parent_sensitive) for item in value]
    if isinstance(value, Path):
        return value.name
    if isinstance(value, str):
        return _sanitize_serializer_string(
            value,
            parent_key=parent_key,
            parent_sensitive=parent_sensitive,
        )
    return value
