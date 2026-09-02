"""Presentation-only explanation metadata for command safety extensions.

The metadata can add names, intent IDs, target kinds, consequences, synonyms,
and safer-step IDs. It cannot choose, weaken, suppress, or otherwise emit an
enforcement action. Enforcement remains owned by the existing command extension
and policy runtime.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
import hashlib
import json
import re

from codex_plugin_scanner.guard.redaction import redact_text

EXTENSION_EXPLANATION_SCHEMA_VERSION = 1
_MAX_NAME = 120
_MAX_PURPOSE = 500
_MAX_METADATA_ITEMS = 64
_ID_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
_VALID_CONFIDENCE = frozenset({"exact", "derived", "limited"})
_VALID_DIALECTS = frozenset({"posix", "powershell", "cmd", "argv", "unknown"})
_FORBIDDEN_KEYS = frozenset(
    {
        "action",
        "enforcement",
        "enforcement_action",
        "policy_action",
        "decision",
        "verdict",
        "allow",
        "deny",
        "block",
    }
)


@dataclass(frozen=True, slots=True)
class ExtensionEverydayMetadata:
    extension_id: str
    everyday_name: str
    everyday_purpose: str
    search_synonyms: tuple[str, ...] = ()
    technical_synonyms: tuple[str, ...] = ()
    dialects: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "extension_id": self.extension_id,
            "everyday_name": self.everyday_name,
            "everyday_purpose": self.everyday_purpose,
            "search_synonyms": list(self.search_synonyms),
            "technical_synonyms": list(self.technical_synonyms),
            "dialects": list(self.dialects),
        }


@dataclass(frozen=True, slots=True)
class RuleEverydayMetadata:
    rule_id: str
    action_intent_id: str
    target_kind: str
    consequence_ids: tuple[str, ...]
    safer_step_ids: tuple[str, ...]
    safe_variant_id: str | None = None
    minimum_confidence: str = "derived"

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "action_intent_id": self.action_intent_id,
            "target_kind": self.target_kind,
            "consequence_ids": list(self.consequence_ids),
            "safer_step_ids": list(self.safer_step_ids),
            "safe_variant_id": self.safe_variant_id,
            "minimum_confidence": self.minimum_confidence,
        }


@dataclass(frozen=True, slots=True)
class CommandExtensionExplanationCatalog:
    revision: int
    extensions: tuple[ExtensionEverydayMetadata, ...]
    rules: tuple[RuleEverydayMetadata, ...]

    @property
    def digest(self) -> str:
        payload = {
            "schema_version": EXTENSION_EXPLANATION_SCHEMA_VERSION,
            "revision": self.revision,
            "extensions": [item.to_dict() for item in sorted(self.extensions, key=lambda item: item.extension_id)],
            "rules": [item.to_dict() for item in sorted(self.rules, key=lambda item: item.rule_id)],
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def rule(self, rule_id: str) -> RuleEverydayMetadata | None:
        normalized = rule_id.strip().lower()
        return next((item for item in self.rules if item.rule_id == normalized), None)


def parse_extension_explanation_catalog(
    payload: Mapping[str, object],
    *,
    minimum_revision: int = 0,
) -> CommandExtensionExplanationCatalog:
    """Parse a signed/verified payload after signature verification by its caller."""

    _reject_forbidden_keys(payload)
    if payload.get("schema_version") != EXTENSION_EXPLANATION_SCHEMA_VERSION:
        raise ValueError("unsupported extension explanation schema version")
    revision = payload.get("revision")
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < minimum_revision:
        raise ValueError("extension explanation metadata rollback rejected")
    raw_extensions = payload.get("extensions")
    raw_rules = payload.get("rules")
    if not isinstance(raw_extensions, list) or not isinstance(raw_rules, list):
        raise ValueError("extension explanation catalog arrays are required")
    if len(raw_extensions) > _MAX_METADATA_ITEMS or len(raw_rules) > _MAX_METADATA_ITEMS * 32:
        raise ValueError("extension explanation catalog exceeds bounded metadata limits")
    extensions = tuple(_parse_extension(item) for item in raw_extensions)
    rules = tuple(_parse_rule(item) for item in raw_rules)
    _assert_unique((item.extension_id for item in extensions), "extension explanation ID")
    _assert_unique((item.rule_id for item in rules), "rule explanation ID")
    return CommandExtensionExplanationCatalog(revision=revision, extensions=extensions, rules=rules)


def validate_builtin_explanation_coverage(
    *,
    rule_ids: Sequence[str],
    catalog: CommandExtensionExplanationCatalog,
    explicit_generic_fallbacks: Sequence[str] = (),
) -> None:
    metadata = {item.rule_id for item in catalog.rules}
    fallback = {item.strip().lower() for item in explicit_generic_fallbacks}
    missing = sorted({item.strip().lower() for item in rule_ids} - metadata - fallback)
    if missing:
        raise ValueError("built-in command rules lack explanation metadata or explicit fallback: " + ", ".join(missing))


def explanation_catalog_digest(*, command_catalog_digest: str, metadata_catalog: CommandExtensionExplanationCatalog) -> str:
    """Bind presentation metadata to the deterministic command catalog digest."""

    encoded = json.dumps(
        {
            "command_catalog_digest": command_catalog_digest,
            "explanation_metadata_digest": metadata_catalog.digest,
            "schema_version": EXTENSION_EXPLANATION_SCHEMA_VERSION,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def sanitize_external_explanation_value(value: str, *, limit: int) -> str:
    """Redact secret-like material and bound external display values."""

    cleaned = redact_text(value).text.strip()
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[: max(0, limit - 1)] + "…"


def _parse_extension(value: object) -> ExtensionEverydayMetadata:
    item = _mapping(value, "extension explanation metadata")
    _reject_forbidden_keys(item)
    extension_id = _identifier(item.get("extension_id"), "extension_id")
    everyday_name = sanitize_external_explanation_value(_required_text(item.get("everyday_name"), "everyday_name"), limit=_MAX_NAME)
    everyday_purpose = sanitize_external_explanation_value(
        _required_text(item.get("everyday_purpose"), "everyday_purpose"), limit=_MAX_PURPOSE
    )
    dialects = _strings(item.get("dialects"), 8, 32)
    if any(item not in _VALID_DIALECTS for item in dialects):
        raise ValueError("unsupported extension explanation dialect")
    return ExtensionEverydayMetadata(
        extension_id=extension_id,
        everyday_name=everyday_name,
        everyday_purpose=everyday_purpose,
        search_synonyms=_strings(item.get("search_synonyms"), 32, 80),
        technical_synonyms=_strings(item.get("technical_synonyms"), 32, 80),
        dialects=dialects,
    )


def _parse_rule(value: object) -> RuleEverydayMetadata:
    item = _mapping(value, "rule explanation metadata")
    _reject_forbidden_keys(item)
    rule_id = _identifier(item.get("rule_id"), "rule_id")
    action_intent_id = _identifier(item.get("action_intent_id"), "action_intent_id")
    target_kind = _identifier(item.get("target_kind"), "target_kind")
    consequence_ids = tuple(_identifier(value, "consequence_id") for value in _strings(item.get("consequence_ids"), 16, 128))
    safer_step_ids = tuple(_identifier(value, "safer_step_id") for value in _strings(item.get("safer_step_ids"), 16, 128))
    if not consequence_ids:
        raise ValueError("rule explanation metadata cannot suppress every consequence")
    confidence = _required_text(item.get("minimum_confidence", "derived"), "minimum_confidence")
    if confidence not in _VALID_CONFIDENCE:
        raise ValueError("invalid rule explanation minimum confidence")
    raw_safe_variant = item.get("safe_variant_id")
    safe_variant_id = None if raw_safe_variant is None else _identifier(raw_safe_variant, "safe_variant_id")
    return RuleEverydayMetadata(
        rule_id=rule_id,
        action_intent_id=action_intent_id,
        target_kind=target_kind,
        consequence_ids=consequence_ids,
        safer_step_ids=safer_step_ids,
        safe_variant_id=safe_variant_id,
        minimum_confidence=confidence,
    )


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be an object")
    return value


def _reject_forbidden_keys(value: object) -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if isinstance(key, str) and key.casefold() in _FORBIDDEN_KEYS:
                raise ValueError(f"extension explanation metadata cannot set enforcement field {key}")
            _reject_forbidden_keys(nested)
    elif isinstance(value, list | tuple):
        for nested in value:
            _reject_forbidden_keys(nested)


def _identifier(value: object, label: str) -> str:
    text = _required_text(value, label).strip().lower()
    if _ID_RE.fullmatch(text) is None:
        raise ValueError(f"invalid {label}")
    return text


def _required_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} is required")
    return value.strip()


def _strings(value: object, max_items: int, max_length: int) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list | tuple) or len(value) > max_items:
        raise ValueError("extension explanation metadata array exceeds limit")
    result = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ValueError("extension explanation metadata arrays require strings")
        result.append(sanitize_external_explanation_value(item, limit=max_length))
    return tuple(result)


def _assert_unique(values: Iterable[str], label: str) -> None:
    sequence = list(values)
    if len(sequence) != len(set(sequence)):
        raise ValueError(f"duplicate {label}")
