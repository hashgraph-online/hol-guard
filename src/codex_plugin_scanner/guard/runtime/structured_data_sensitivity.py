"""Bounded, declarative presence detection for synthetic sensitive data.

This module is inert until a caller explicitly uses it. A match says only that
the declared category was present; it does not block or rewrite host content.
It deliberately does not infer personal data from arbitrary contact-like text.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass
from functools import partial
from typing import Literal

from ..strict_json_pairs import unique_json_object
from .secret_sensitivity import SecretContentMatch, classify_secret_content, secret_content_rule_version

ScanStatus = Literal["matched", "no_declared_match", "unsupported"]
FieldRole = Literal["protected_personal", "ordinary"]
FieldType = Literal["string", "integer"]
PersonalCategory = Literal["person_name", "email_address", "employee_id"]

CLASSIFIER_VERSION = "structured-sensitive-v1"
MAX_INPUT_BYTES = 64 * 1024
MAX_DEPTH = 8
MAX_NODES = 128
MAX_FIELDS = 64
MAX_MATCHES = 16
MAX_DURATION_SECONDS = 0.2
_PATH_SEGMENT = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
_PERSONAL_CATEGORIES = frozenset({"person_name", "email_address", "employee_id"})


@dataclass(frozen=True, slots=True)
class DeclaredField:
    """One exact JSON object path and its application-declared role."""

    path: tuple[str, ...]
    role: FieldRole
    value_type: FieldType = "string"
    category: PersonalCategory | None = None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.path, tuple)
            or not self.path
            or len(self.path) > MAX_DEPTH
            or any(not isinstance(part, str) or not _PATH_SEGMENT.fullmatch(part) for part in self.path)
        ):
            raise ValueError("declared field path is invalid")
        if self.value_type not in ("string", "integer"):
            raise ValueError("declared field type is invalid")
        if self.role == "protected_personal":
            if self.category not in _PERSONAL_CATEGORIES:
                raise ValueError("protected personal category is invalid")
        elif self.role != "ordinary" or self.category is not None:
            raise ValueError("declared field role is invalid")


@dataclass(frozen=True, slots=True)
class DeclaredSchema:
    """Closed synthetic object schema; unknown leaves are unsupported."""

    fields: tuple[DeclaredField, ...]

    def __post_init__(self) -> None:
        if not self.fields or len(self.fields) > MAX_FIELDS:
            raise ValueError("declared schema size is invalid")
        if len({field.path for field in self.fields}) != len(self.fields):
            raise ValueError("declared schema contains duplicate paths")


@dataclass(frozen=True, slots=True)
class SensitiveMatch:
    """Value-free typed presence record."""

    category: str
    sensitivity: str
    field_path: tuple[str, ...]
    reason: str


@dataclass(frozen=True, slots=True)
class SensitiveScanResult:
    status: ScanStatus
    matches: tuple[SensitiveMatch, ...]
    complete: bool
    reason_code: str
    bytes_scanned: int
    fields_scanned: int
    rule_version: str


def classifier_rule_version(schema: DeclaredSchema | None = None) -> str:
    """Bind the existing credential rules and the declared schema, never data."""

    material = {
        "classifier": CLASSIFIER_VERSION,
        "credentialRules": secret_content_rule_version(),
        "fields": [
            {"path": field.path, "role": field.role, "type": field.value_type, "category": field.category}
            for field in (schema.fields if schema is not None else ())
        ],
    }
    return hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _reject_constant(_value: str) -> object:
    raise ValueError("nonstandard JSON constant")


_CREDENTIAL_CHUNK_CHARS = 4096
_CREDENTIAL_CONTEXT_CHARS = 8192
_EARLY_EXIT_SENSITIVITIES = frozenset({"high", "critical"})


@dataclass(frozen=True, slots=True)
class _CredentialScan:
    matches: tuple[SecretContentMatch, ...]
    bytes_scanned: int
    budget_exhausted: bool
    reason_code: str


def _scan_credential_window(
    window: str,
    matches_by_classifier: dict[str, SecretContentMatch],
) -> None:
    """Classify one rolling window and merge new matches."""
    suppressed = classify_secret_content(window, suppress_samples=True, documentation_sample_context=False)
    for match in suppressed:
        matches_by_classifier.setdefault(match.classifier, match)
    # Local content keeps the escalation of retrying with sample suppression
    # disabled so sample-looking assignments still count as present.
    if not suppressed:
        for match in classify_secret_content(window, suppress_samples=False):
            matches_by_classifier.setdefault(match.classifier, match)


def _scan_credential_content(
    text: str,
    *,
    deadline_monotonic: float | None,
) -> _CredentialScan:
    """Bounded chunked credential presence scan over declared local content.

    Input is already bounded to ``MAX_INPUT_BYTES`` by the caller; the rolling
    context window catches tokens split across chunk boundaries and the scan
    exits early on high/critical matches so ``bytes_scanned`` reports only the
    bytes actually consumed.
    """
    tail = ""
    matches_by_classifier: dict[str, SecretContentMatch] = {}
    bytes_scanned = 0
    for index in range(0, len(text), _CREDENTIAL_CHUNK_CHARS):
        if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
            return _CredentialScan(
                matches=tuple(matches_by_classifier.values())[:MAX_MATCHES],
                bytes_scanned=bytes_scanned,
                budget_exhausted=True,
                reason_code="deadline_exceeded",
            )
        chunk = text[index : index + _CREDENTIAL_CHUNK_CHARS]
        bytes_scanned += len(chunk.encode("utf-8"))
        window = tail + chunk
        _scan_credential_window(window, matches_by_classifier)
        if any(m.sensitivity in _EARLY_EXIT_SENSITIVITIES for m in matches_by_classifier.values()):
            return _CredentialScan(
                matches=tuple(matches_by_classifier.values())[:MAX_MATCHES],
                bytes_scanned=bytes_scanned,
                budget_exhausted=False,
                reason_code="secret_match_early_exit",
            )
        if len(matches_by_classifier) >= MAX_MATCHES:
            return _CredentialScan(
                matches=tuple(matches_by_classifier.values())[:MAX_MATCHES],
                bytes_scanned=bytes_scanned,
                budget_exhausted=False,
                reason_code="max_matches_reached",
            )
        tail = window[-_CREDENTIAL_CONTEXT_CHARS:] if len(window) > _CREDENTIAL_CONTEXT_CHARS else window
    return _CredentialScan(
        matches=tuple(matches_by_classifier.values())[:MAX_MATCHES],
        bytes_scanned=bytes_scanned,
        budget_exhausted=False,
        reason_code="matches" if matches_by_classifier else "clean",
    )


def _typed_value(value: object, expected: FieldType) -> bool:
    if expected == "string":
        return isinstance(value, str)
    return type(value) is int


def classify_declared_content(
    content: bytes | str,
    *,
    schema: DeclaredSchema | None = None,
    deadline_monotonic: float | None = None,
) -> SensitiveScanResult:
    """Detect existing credential patterns and exact declared personal fields.

    The result is a presence signal only. ``no_declared_match`` means no match
    under these rules, never a universal claim that the content is safe.
    Unsupported or incomplete input is never labeled ``no_declared_match``.
    """

    version = classifier_rule_version(schema)
    deadline = min(
        time.monotonic() + MAX_DURATION_SECONDS,
        deadline_monotonic if deadline_monotonic is not None else float("inf"),
    )
    matches: list[SensitiveMatch] = []
    scanned = 0
    fields_scanned = 0

    def finish(status: ScanStatus, reason: str, *, complete: bool = False) -> SensitiveScanResult:
        return SensitiveScanResult(
            status=status,
            matches=tuple(matches[:MAX_MATCHES]),
            complete=complete,
            reason_code=reason,
            bytes_scanned=scanned,
            fields_scanned=fields_scanned,
            rule_version=version,
        )

    if isinstance(content, bytes):
        if len(content) > MAX_INPUT_BYTES:
            return finish("unsupported", "input_too_large")
        try:
            text = content.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            return finish("unsupported", "invalid_utf8")
        byte_count = len(content)
    elif isinstance(content, str):
        if len(content) > MAX_INPUT_BYTES:
            return finish("unsupported", "input_too_large")
        try:
            byte_count = len(content.encode("utf-8", errors="strict"))
        except UnicodeEncodeError:
            return finish("unsupported", "invalid_unicode")
        if byte_count > MAX_INPUT_BYTES:
            return finish("unsupported", "input_too_large")
        text = content
    else:
        return finish("unsupported", "input_type_unsupported")

    credential_result = _scan_credential_content(
        text,
        deadline_monotonic=deadline,
    )
    matches.extend(
        SensitiveMatch(
            category=f"credential.{match.classifier}",
            sensitivity=match.sensitivity,
            field_path=(),
            reason="declared_credential_pattern_present",
        )
        for match in credential_result.matches
    )
    scanned = credential_result.bytes_scanned
    if credential_result.budget_exhausted or time.monotonic() >= deadline:
        return finish("unsupported", "scan_budget_exhausted")
    if "\\" in text:
        return finish("unsupported", "encoded_or_escaped_content")
    if schema is None:
        complete = credential_result.reason_code in ("clean", "matches")
        status: ScanStatus = "matched" if matches else "no_declared_match"
        return finish(status, "credential_scan", complete=complete)

    try:
        document = json.loads(
            text,
            object_pairs_hook=partial(unique_json_object, duplicate_error="duplicate JSON field"),
            parse_constant=_reject_constant,
        )
    except (ValueError, RecursionError, TypeError):
        return finish("unsupported", "invalid_or_duplicate_json")
    if not isinstance(document, dict):
        return finish("unsupported", "root_object_required")

    declared = {field.path: field for field in schema.fields}
    object_paths = {field.path[:depth] for field in schema.fields for depth in range(1, len(field.path))}
    nodes_scanned = 0
    stack: list[tuple[tuple[str, ...], object]] = [((), document)]
    while stack:
        if time.monotonic() >= deadline:
            return finish("unsupported", "scan_budget_exhausted")
        path, value = stack.pop()
        nodes_scanned += 1
        if nodes_scanned > MAX_NODES or len(path) > MAX_DEPTH:
            return finish("unsupported", "structure_limit_exceeded")
        if isinstance(value, dict):
            if path in declared:
                return finish("unsupported", "field_type_invalid")
            if path and path not in object_paths:
                return finish("unsupported", "unknown_field")
            stack.extend(((*path, key), child) for key, child in value.items())
            continue
        if isinstance(value, list):
            return finish("unsupported", "array_unsupported")
        fields_scanned += 1
        if fields_scanned > MAX_FIELDS:
            return finish("unsupported", "field_limit_exceeded")
        field = declared.get(path)
        if field is None:
            return finish("unsupported", "unknown_field")
        if not _typed_value(value, field.value_type):
            return finish("unsupported", "field_type_invalid")
        present = (isinstance(value, str) and bool(value.strip())) or type(value) is int
        if field.role == "protected_personal" and present:
            matches.append(
                SensitiveMatch(
                    category=f"personal.{field.category}",
                    sensitivity="high",
                    field_path=field.path,
                    reason="declared_protected_field_present",
                )
            )
            if len(matches) > MAX_MATCHES:
                return finish("unsupported", "match_limit_exceeded")

    complete = credential_result.reason_code in ("clean", "matches")
    status = "matched" if matches else "no_declared_match"
    return finish(status, "declared_schema_scan", complete=complete)
