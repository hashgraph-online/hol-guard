"""Queue-time hint: which configurable extension permissions would allow a reviewed command.

The hint is advisory. It is computed by re-running the pure policy resolver
against the same native evidence with a hypothetical local-admin layer, so it
never triggers a native call, never mutates authority, and carries only catalog
identifiers (no command text). Enabling a permission still requires the normal
proof-bound extension-control mutation.
"""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import cast
from urllib.parse import quote

from .command_evaluation import evaluate_command
from .command_evaluation_types import CompositeCommandEvaluation
from .command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY, CommandSafetyExtensionRegistry
from .extension_control_runtime import ExtensionControlRuntimeSnapshot
from .native_command_extension_evidence import NativeCommandExtensionEvidenceError

EXTENSION_ALLOW_HINT_SCHEMA = "guard.extension-allow-hint.v1"
MAX_HINT_PERMISSIONS = 3
_MAX_HINT_IDS = MAX_HINT_PERMISSIONS * 4


def _valid_hint_ids(items: object, *, allow_empty: bool) -> list[str] | None:
    if not isinstance(items, list) or (not items and not allow_empty) or len(items) > _MAX_HINT_IDS:
        return None
    ids = [item for item in items if isinstance(item, str) and item.startswith("command.") and len(item) <= 256]
    return ids if len(ids) == len(items) else None


def compute_extension_allow_hint(
    evaluation: CompositeCommandEvaluation,
    *,
    command_text: str,
    snapshot: ExtensionControlRuntimeSnapshot,
    native_evidence: object,
    cwd: Path | None = None,
    home_dir: Path | None = None,
    registry: CommandSafetyExtensionRegistry = BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    deadline: float | None = None,
) -> dict[str, object] | None:
    """Return permission ids whose Allow state would let this command run, or None.

    ``deadline`` (``time.monotonic()``) bounds the optional reduction pass: once
    it passes, the already verified full permission set is returned as-is.
    """

    if snapshot.authority_failure is not None or evaluation.decision_plane.action not in (
        "review",
        "require-reapproval",
    ):
        return None
    if isinstance(native_evidence, dict) and (
        native_evidence.get("minimum_action") == "block"
        # A fixed PreTool floor (sensitive access, Guard self-protection,
        # ...) reviews whatever the extensions say, so no extension Allow
        # can settle it and no hint may promise otherwise. Real native
        # results always carry the reason; its absence is not the
        # extension review either.
        or native_evidence.get("reason_code") != "native_command_review_required"
    ):
        return None
    already_enabled = set(evaluation.control_resolution.explicitly_enabled_permission_ids)
    owners: dict[str, tuple[str, str]] = {}
    relied_permission_ids: list[str] = []
    for owned in evaluation.matches:
        rule_id = owned.match.rule.rule_id
        permission = registry.permission_for_rule_id(rule_id)
        if permission is None or not permission.configurable:
            continue
        if permission.permission_id in already_enabled:
            # The counterfactual only holds while this permission stays enabled.
            if permission.permission_id not in relied_permission_ids:
                relied_permission_ids.append(permission.permission_id)
            continue
        owners.setdefault(permission.permission_id, (rule_id, permission.extension_id))
    if not owners or len(owners) > MAX_HINT_PERMISSIONS or len(relied_permission_ids) > _MAX_HINT_IDS:
        return None

    def allows(permission_ids: tuple[str, ...]) -> bool:
        try:
            counterfactual = evaluate_command(
                command_text,
                canonical_command=evaluation.command,
                cwd=cwd,
                home_dir=home_dir,
                native_extension_evidence=native_evidence,
                extension_control_snapshot=snapshot,
                counterfactual_enabled_permission_ids=permission_ids,
            )
        except (NativeCommandExtensionEvidenceError, RuntimeError, ValueError):
            return False
        return counterfactual.decision_plane.action == "allow" and counterfactual.minimum_action == "allow"

    permission_ids = list(owners)
    if not allows(tuple(permission_ids)):
        return None
    # A matched rule that does not gate (for example a disabled-by-default one)
    # must not be named: keep only the permissions the Allow actually needs.
    for permission_id in tuple(permission_ids):
        if deadline is not None and time.monotonic() >= deadline:
            break
        remaining = tuple(item for item in permission_ids if item != permission_id)
        if remaining and allows(remaining):
            permission_ids = list(remaining)
    rule_ids: list[str] = []
    extension_ids: list[str] = []
    for permission_id in permission_ids:
        rule_id, extension_id = owners[permission_id]
        if rule_id not in rule_ids:
            rule_ids.append(rule_id)
        if extension_id not in extension_ids:
            extension_ids.append(extension_id)
    return {
        "schema": EXTENSION_ALLOW_HINT_SCHEMA,
        "permission_ids": permission_ids,
        "rule_ids": rule_ids,
        "extension_ids": extension_ids,
        "relied_permission_ids": relied_permission_ids,
        "catalog_digest": registry.catalog_digest,
    }


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
