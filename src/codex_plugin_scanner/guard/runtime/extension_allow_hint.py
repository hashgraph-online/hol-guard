"""Queue-time hint: which configurable extension permissions would allow a reviewed command.

The hint is advisory. The native resident decides it (``extension_review_hint``,
``extension_allow_hint``): it re-evaluates the command against its own admitted
controls with hypothetical enabled permissions, so nothing is mutated and the
answer carries only catalog identifiers (no command text). This module
shape-checks a stored or answered hint and builds the connector setup hint.
Enabling a permission still requires the normal proof-bound extension-control
mutation.
"""

from __future__ import annotations

import re
from typing import cast
from urllib.parse import quote

from .extension_control_runtime import ExtensionControlRuntimeSnapshot

EXTENSION_ALLOW_HINT_SCHEMA = "guard.extension-allow-hint.v1"
# Bounds a stored hint's id lists. The resident names at most three permissions
# (the client enforces that on its reply) and reports at most twelve relied-on
# ones; a stored hint keeps the wider bound it has always had.
_MAX_HINT_IDS = 12


def _valid_hint_ids(items: object, *, allow_empty: bool) -> list[str] | None:
    if not isinstance(items, list) or (not items and not allow_empty) or len(items) > _MAX_HINT_IDS:
        return None
    ids = [item for item in items if isinstance(item, str) and item.startswith("command.") and len(item) <= 256]
    return ids if len(ids) == len(items) else None


def hint_authority_admitted(snapshot: ExtensionControlRuntimeSnapshot) -> bool:
    """Whether an allow hint can be offered under this authority.

    A protected authority can apply the Allow now. A device that never enrolled
    can once it enrolls, so it gets the hint with the setup step in front of it.
    Any other failure (degraded, tampered, recovery) needs repair first.
    """

    return snapshot.authority_failure is None or snapshot.awaiting_enrollment


def validated_extension_allow_hint(value: object) -> dict[str, object] | None:
    """Return a shape-checked copy of a stored hint, or None."""

    if not isinstance(value, dict) or value.get("schema") != EXTENSION_ALLOW_HINT_SCHEMA:
        return None
    result: dict[str, object] = {"schema": EXTENSION_ALLOW_HINT_SCHEMA}
    for key in ("permission_ids", "rule_ids", "extension_ids"):
        items = _valid_hint_ids(value.get(key), allow_empty=False)
        if items is None:
            return None
        result[key] = items
    # Optional: hints queued before this key existed carry no relied permissions.
    relied = _valid_hint_ids(value.get("relied_permission_ids", []), allow_empty=True)
    if relied is None:
        return None
    result["relied_permission_ids"] = relied
    digest = value.get("catalog_digest")
    if not isinstance(digest, str) or len(digest) != 64:
        return None
    result["catalog_digest"] = digest
    return result


CONNECTOR_SETUP_HINT_SCHEMA = "guard.connector-setup-hint.v1"
CONNECTOR_SETUP_SURFACES = frozenset({"cli", "package-scripts", "mcp"})
_MAX_CONNECTOR_TEXT = 128
_MAX_RISK_CLASSES = 16


def _connector_text(value: object, *, pattern: re.Pattern[str]) -> str | None:
    return value if isinstance(value, str) and len(value) <= _MAX_CONNECTOR_TEXT and pattern.fullmatch(value) else None


_IDENTITY_HASH = re.compile(r"[0-9a-f]{64}")
_CLI_ID = re.compile(r"local-cli\.[A-Za-z0-9._@+-]{1,118}")
_DISPLAY_NAME = re.compile(r"[A-Za-z0-9@][A-Za-z0-9._@+/ -]{0,63}")
_RISK_CLASS = re.compile(r"[a-z][a-z0-9_]{0,63}")
_CAPABILITY = re.compile(r"[a-z][a-z0-9-]{0,63}")


def _matching_strings(value: object, pattern: re.Pattern[str]) -> list[str] | None:
    """The list when every entry is a short string matching ``pattern``, else None."""

    if not isinstance(value, list) or len(cast("list[object]", value)) > _MAX_RISK_CLASSES:
        return None
    items = [item for item in cast("list[object]", value) if isinstance(item, str) and pattern.fullmatch(item)]
    return items if len(items) == len(cast("list[object]", value)) else None


def connector_setup_deep_link(cli_id: str) -> str:
    """Dashboard-relative Protect path for one connector; never carries a host."""

    return f"/extensions/local-cli/{quote(cli_id, safe='')}"


def connector_setup_hint(
    *,
    cli_id: str,
    identity_hash: str,
    display_name: str,
    surface: str,
    risk_classes: object = None,
) -> dict[str, object] | None:
    """The connector analogue of the allow hint, recorded when a review is a setup decision.

    It names only the connector and the advisory card recommendation. Setting
    the connector up still goes through the proof-bound local-CLI write.
    """

    candidates = cast("list[object]", list(risk_classes)) if isinstance(risk_classes, list | tuple) else []
    classes = sorted({item for item in candidates if isinstance(item, str) and _RISK_CLASS.fullmatch(item)})
    return validated_connector_setup_hint(
        {
            "schema": CONNECTOR_SETUP_HINT_SCHEMA,
            "identity_hash": identity_hash,
            "cli_id": cli_id,
            "surface": surface,
            "display_name": display_name,
            "deep_link": connector_setup_deep_link(cli_id),
            # Advisory only: the live recommendation is recomputed on every read.
            "card_recommendation": {"state": "allowed", "capabilities": []},
            "risk_classes": classes[:_MAX_RISK_CLASSES],
        }
    )


def validated_connector_setup_hint(value: object) -> dict[str, object] | None:
    """Return a shape-checked copy of a stored connector hint, or None."""

    if not isinstance(value, dict) or value.get("schema") != CONNECTOR_SETUP_HINT_SCHEMA:
        return None
    fields = cast("dict[str, object]", value)
    identity_hash = _connector_text(fields.get("identity_hash"), pattern=_IDENTITY_HASH)
    cli_id = _connector_text(fields.get("cli_id"), pattern=_CLI_ID)
    display_name = _connector_text(fields.get("display_name"), pattern=_DISPLAY_NAME)
    surface = fields.get("surface")
    if identity_hash is None or cli_id is None or display_name is None or surface not in CONNECTOR_SETUP_SURFACES:
        return None
    if fields.get("deep_link") != connector_setup_deep_link(cli_id):
        return None
    recommendation = fields.get("card_recommendation")
    if not isinstance(recommendation, dict):
        return None
    recommended = cast("dict[str, object]", recommendation)
    capabilities = _matching_strings(recommended.get("capabilities"), _CAPABILITY)
    risk_classes = _matching_strings(fields.get("risk_classes", []), _RISK_CLASS)
    if recommended.get("state") != "allowed" or capabilities is None or risk_classes is None:
        return None
    return {
        "schema": CONNECTOR_SETUP_HINT_SCHEMA,
        "identity_hash": identity_hash,
        "cli_id": cli_id,
        "surface": surface,
        "display_name": display_name,
        "deep_link": connector_setup_deep_link(cli_id),
        "card_recommendation": {"state": "allowed", "capabilities": capabilities},
        "risk_classes": risk_classes,
    }
