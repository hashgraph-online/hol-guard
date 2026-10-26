"""Proposed extension packs. Never imported by runtime enforcement.

A pack groups existing catalog extensions and permissions for presentation and
setup. It cannot enable an extension, change a trust class, lower a baseline
floor, or grant an allow; native contributions remain the only source of
runtime behavior.
"""

from __future__ import annotations

import json
from collections.abc import Collection
from functools import lru_cache
from importlib.resources import files
from pathlib import Path
from typing import Literal, Protocol, cast

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError

from ..action_lattice import guard_action_severity, most_restrictive_guard_action
from .errors import BuilderError
from .io import canonical_json, checked_path, parse_json, read_bytes
from .validation import text, token

PACK_SCHEMA = "guard.extension-pack.v1"
MAX_PACK_BYTES = 32_768
PackRole = Literal["personal", "managed-team"]
_PACK_ID = r"[a-z][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)+"
_LOCAL_ID = r"[a-z][a-z0-9-]*"
_VERSION = r"[0-9]+\.[0-9]+\.[0-9]+"
_DOCUMENT = r"docs/guard/[A-Za-z0-9._/-]+\.md"


class _Extension(Protocol):
    @property
    def version(self) -> str: ...

    @property
    def enabled(self) -> bool: ...

    @property
    def permissions(self) -> tuple[_Permission, ...]: ...


class _Permission(Protocol):
    @property
    def permission_id(self) -> str: ...

    @property
    def extension_id(self) -> str: ...

    @property
    def baseline_floor(self) -> str: ...


class PackCatalog(Protocol):
    def get(self, extension_id: str) -> _Extension | None: ...

    def permission(self, permission_id: str) -> _Permission | None: ...


@lru_cache(maxsize=1)
def pack_schema() -> dict[str, object]:
    payload = files("codex_plugin_scanner.guard.extension_builder").joinpath("pack.v1.schema.json")
    return cast(dict[str, object], json.loads(payload.read_text(encoding="utf-8")))


def _plain(value: object) -> None:
    try:
        text(value, maximum=400)
    except BuilderError as exc:
        raise BuilderError("pack_text", "Pack text must be trimmed, single-line plain text.") from exc


def _identifiers(values: list[tuple[object, str, int]]) -> None:
    """Full-match identifiers; JSON Schema ``$`` also accepts a trailing newline."""

    try:
        for value, pattern, maximum in values:
            token(value, pattern=pattern, maximum=maximum)
    except BuilderError as exc:
        raise BuilderError("pack_identity", "Pack identifiers must match their full pattern.") from exc


def _unique(values: list[str], code: str, message: str) -> None:
    if len(set(values)) != len(values):
        raise BuilderError(code, message)


def validate_pack(payload: object, *, catalog: PackCatalog, repository: Path) -> dict[str, object]:
    """Validate a proposed pack against the catalog without changing any extension state."""

    try:
        Draft202012Validator(pack_schema(), format_checker=FormatChecker()).validate(payload)
    except (ValidationError, RecursionError) as exc:
        raise BuilderError("pack_schema", "Pack does not match the bounded pack contract.") from exc
    row = cast(dict[str, object], payload)
    extensions = cast(list[dict[str, str]], row["extensions"])
    families = cast(list[dict[str, object]], row["operationFamilies"])
    recipes = cast(list[dict[str, object]], row["setupRecipes"])
    not_covered = cast(list[dict[str, str]], row["notCovered"])
    texts: list[object] = [row["title"], row["summary"], *cast(list[str], row["limitations"])]
    texts += [item["title"] for item in families] + [item["title"] for item in recipes]
    texts += [value for item in not_covered for value in (item["title"], item["reason"])]
    for value in texts:
        _plain(value)
    identifiers: list[tuple[object, str, int]] = [(row["packId"], _PACK_ID, 96)]
    identifiers += [(item["extensionId"], _PACK_ID, 160) for item in extensions]
    identifiers += [(item["version"], _VERSION, 32) for item in extensions]
    for family in families:
        identifiers.append((family["familyId"], _LOCAL_ID, 64))
        identifiers += [(value, _PACK_ID, 160) for value in cast(list[str], family["permissionIds"])]
    for recipe in recipes:
        identifiers += [(recipe["recipeId"], _LOCAL_ID, 64), (recipe["documentationPath"], _DOCUMENT, 200)]
        identifiers += [(value, _PACK_ID, 160) for value in cast(list[str], recipe["extensionIds"])]
    _identifiers(identifiers)
    extension_ids = [item["extensionId"] for item in extensions]
    _unique(extension_ids, "pack_identity", "Pack extensions must be unique.")
    _unique([cast(str, item["familyId"]) for item in families], "pack_identity", "Operation families must be unique.")
    _unique([cast(str, item["recipeId"]) for item in recipes], "pack_identity", "Setup recipes must be unique.")
    expected_permissions: set[str] = set()
    for item in extensions:
        extension = catalog.get(item["extensionId"])
        if extension is None:
            raise BuilderError("pack_reference", "Pack extensions must exist in the generated catalog.")
        if extension.version != item["version"]:
            raise BuilderError("pack_version", "Pack extension versions must match the generated catalog.")
        expected_permissions.update(permission.permission_id for permission in extension.permissions)
    covered: list[str] = []
    for family in families:
        suggestions = cast(dict[str, str], family["roleSuggestions"])
        for permission_id in cast(list[str], family["permissionIds"]):
            permission = catalog.permission(permission_id)
            if permission is None or permission.extension_id not in extension_ids:
                raise BuilderError("pack_reference", "Pack permissions must belong to a pack extension.")
            floor = guard_action_severity(permission.baseline_floor, unknown_action="block")
            if any(guard_action_severity(action) < floor for action in suggestions.values()):
                raise BuilderError("pack_floor", "Role suggestions cannot be weaker than a baseline floor.")
            covered.append(permission_id)
    _unique(covered, "pack_coverage", "Each permission belongs to exactly one operation family.")
    if set(covered) != expected_permissions:
        raise BuilderError("pack_coverage", "Operation families must cover every pack extension permission.")
    for recipe in recipes:
        if not set(cast(list[str], recipe["extensionIds"])) <= set(extension_ids):
            raise BuilderError("pack_reference", "Setup recipes may reference only pack extensions.")
        document = checked_path(repository / cast(str, recipe["documentationPath"]))
        if not document.is_file():
            raise BuilderError("pack_reference", "Setup recipe documentation must exist in the repository.")
    if len(canonical_json(row).encode("utf-8")) > MAX_PACK_BYTES:
        raise BuilderError("pack_limit", "Pack exceeds its byte budget.")
    return row


def load_pack(path: Path, *, catalog: PackCatalog, repository: Path) -> dict[str, object]:
    path = checked_path(path)
    row = validate_pack(parse_json(read_bytes(path, limit=MAX_PACK_BYTES)), catalog=catalog, repository=repository)
    if path.name != f"{row['packId']}.json":
        raise BuilderError("pack_identity", "Pack filename must match its pack ID.")
    return row


def plan_pack_selection(
    pack: dict[str, object],
    *,
    catalog: PackCatalog,
    enabled_extension_ids: Collection[str],
    role: PackRole,
) -> dict[str, object]:
    """Describe what selecting a pack would show. The plan grants nothing.

    An extension is active only when local extension control already enabled
    it; selecting the pack does not. Suggestions are composed with the
    baseline floor so a suggestion can only keep or tighten it.
    """

    rows: list[dict[str, object]] = []
    active: set[str] = set()
    for item in cast(list[dict[str, str]], pack["extensions"]):
        enabled = item["extensionId"] in enabled_extension_ids
        if enabled:
            active.add(item["extensionId"])
        rows.append({"extensionId": item["extensionId"], "state": "active" if enabled else "inert"})
    suggestions: list[dict[str, object]] = []
    for family in cast(list[dict[str, object]], pack["operationFamilies"]):
        suggested = cast(dict[str, str], family["roleSuggestions"])[role]
        for permission_id in cast(list[str], family["permissionIds"]):
            permission = catalog.permission(permission_id)
            if permission is None:
                raise BuilderError("pack_reference", "Pack permissions must belong to a pack extension.")
            suggestions.append(
                {
                    "permissionId": permission_id,
                    "familyId": family["familyId"],
                    "baselineFloor": permission.baseline_floor,
                    "suggestedAction": most_restrictive_guard_action(
                        suggested, permission.baseline_floor, unknown_action="block"
                    ),
                    "applies": permission.extension_id in active,
                }
            )
    return {
        "packId": pack["packId"],
        "role": role,
        "grants": [],
        "activatesExtensions": False,
        "extensions": rows,
        "suggestions": suggestions,
    }
