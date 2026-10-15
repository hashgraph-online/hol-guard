"""Structured diagnostics for ``hol-guard policy validate``.

Every problem is reported as ``{code, path, line, col, message, expected?, suggestion?}`` with a
``category`` that separates a document the schema rejects (``schema_invalid``) from one that is
schema-valid but cannot be enforced (``not_enforceable``) and from a file Guard refuses to read
(``file_untrusted``). Messages never include policy values.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal, TypeAlias

import yaml

from .business_policy_document_import import compile_document_for_import
from .native_policy_snapshot_constants import NativePolicySnapshotError
from .policy_document import GuardPolicyDocument
from .policy_document_io import PolicyFileTrustError, read_trusted_policy_text
from .policy_document_types import CompiledPolicyRow, PolicyCompilationError
from .policy_document_yaml import (
    JsonPath,
    PolicyDiagnostic,
    PolicyDocumentError,
    _node_for_path,
    _PolicyLoader,
    parse_policy_document_yaml,
)

DiagnosticCategory: TypeAlias = Literal["schema_invalid", "not_enforceable", "file_untrusted"]
ValidationStatus: TypeAlias = Literal["valid", "schema_invalid", "not_enforceable", "file_untrusted"]

# The runtime older than 3.1 cannot compile typed command expressions into local rows. The document is still
# a valid policy, so this is reported as a warning and never fails validation.
COMMAND_EXPRESSION_CODE: Final = "command_expression_requires_guard_3_1_runtime"

_MESSAGES: Final[dict[str, str]] = {
    "yaml_syntax": "The file is not valid YAML.",
    "yaml_duplicate_key": "A mapping key appears twice.",
    "yaml_merge_key": "YAML merge keys (<<) are not allowed in policy files.",
    "yaml_unhashable_key": "A mapping key must be a plain string.",
    "yaml_anchor": "YAML anchors are not allowed in policy files.",
    "yaml_alias": "YAML aliases are not allowed in policy files.",
    "yaml_tag": "YAML tags are not allowed in policy files.",
    "yaml_document_count": "A policy file must contain exactly one YAML document.",
    "yaml_resource_limit": "The YAML nesting or size exceeds the policy limits.",
    "invalid_utf8": "The file is not valid UTF-8 text.",
    "limit_bytes": "The file is larger than the 1 MiB policy limit.",
    "limit_tokens": "The file contains more YAML tokens than the policy limit allows.",
    "limit_depth": "The document is nested deeper than the policy limit allows.",
    "limit_string": "A string is longer than the policy limit allows.",
    "limit_integer": "A number is outside the supported integer range.",
    "limit_collection": "A list or mapping has more items than the policy limit allows.",
    "limit_key": "A mapping key is longer than the policy limit allows.",
    "invalid_unicode": "A string contains characters that policy files do not allow.",
    "non_finite_number": "Numbers must be finite.",
    "unsupported_float": "Policy files use whole numbers only.",
    "mapping_key_type": "A mapping key must be a string.",
    "duplicate_rule_id": "Two rules share the same id.",
    "invalid_timestamp": "A timestamp is not a valid UTC time such as 2026-10-14T00:00:00Z.",
    "forbidden_sensitive_field": "A field name looks like it holds a secret. Policies must not store credentials.",
    "business_selector_limit_bytes": "A business selector is larger than the policy limit allows.",
    "schema_type": "The value has the wrong type.",
    "schema_enum": "The value is not one of the allowed choices.",
    "schema_required": "A required field is missing.",
    "schema_additionalProperties": "The field is not part of the policy schema.",
    "schema_minItems": "The list needs at least one item.",
    "schema_maxItems": "The list has too many items.",
    "schema_minLength": "The value is too short.",
    "schema_maxLength": "The value is too long.",
    "schema_pattern": "The value does not match the expected format.",
    "schema_const": "The value must be exactly the one the schema names.",
    "schema_anyOf": "The value does not match any allowed shape.",
    "schema_oneOf": "The value must match exactly one allowed shape.",
    "schema_not": "The value uses a combination the schema forbids.",
    "schema_uniqueItems": "The list repeats an item.",
    "invalid_policy_match_selector": "A match selector is empty or malformed.",
    "invalid_policy_enabled": "The enabled flag must be true or false.",
    "invalid_policy_rules": "The rules list is malformed.",
    "invalid_policy_spec": "The spec section is malformed.",
    "policy_compilation_limit": "The rules expand into more enforcement rows than one policy may hold.",
    "sensitive_local_policy_requires_provenance": "This rule needs provenance before Guard will enforce it.",
    "unsupported_local_policy_action": "Guard enforces only allow and block rules.",
    "unsupported_policy_budgets": "Budgets are not enforced by Guard.",
    "unsupported_policy_effect": "Guard enforces only allow and block rules.",
    "unsupported_policy_lifetime": "Guard enforces only permanent and until lifetimes.",
    "unsupported_policy_match": "This combination of match fields is not enforced by Guard.",
    COMMAND_EXPRESSION_CODE: "Command expressions need Guard 3.1 or newer to be enforced on this device.",
    "policy_file_insecure_mode": "The file can be written by other users, so Guard will not trust it.",
    "policy_file_not_owned": "The file is owned by another user, so Guard will not trust it.",
    "policy_file_link_count": "The file has more than one hard link, so Guard will not trust it.",
    "policy_file_not_regular": "The path is not a regular file.",
    "policy_file_unavailable": "The file could not be found or read.",
    "policy_file_open_failed": "The file could not be opened.",
    "policy_file_changed": "The file changed while it was being read.",
    "policy_file_too_large": "The file is larger than the 1 MiB policy limit.",
    "policy_file_not_utf8": "The file is not valid UTF-8 text.",
    "policy_parent_insecure_mode": "The folder can be written by other users, so Guard will not trust files in it.",
    "policy_parent_not_owned": "The folder is owned by another user, so Guard will not trust files in it.",
    "policy_parent_not_directory": "The parent path is not a folder.",
    "policy_parent_unavailable": "The folder could not be opened.",
}

_NOT_ENFORCEABLE_EXPECTED: Final[dict[str, object]] = {
    "unsupported_local_policy_action": ["allow", "block"],
    "unsupported_policy_effect": ["allow", "block"],
    "unsupported_policy_lifetime": ["permanent", "until"],
}

_NOT_ENFORCEABLE_SUGGESTIONS: Final[dict[str, str]] = {
    "unsupported_local_policy_action": "Set effect to allow or block.",
    "unsupported_policy_effect": "Set effect to allow or block.",
    "unsupported_policy_lifetime": "Use lifetime.mode permanent, or until with an expiresAt time.",
    "unsupported_policy_budgets": "Remove the budgets field; Guard does not enforce it.",
    "unsupported_policy_match": (
        "Match on tools, artifacts, harnesses, publishers or workspaces. Tools cannot be combined "
        "with artifacts or publishers."
    ),
    "invalid_policy_match_selector": "Give every match field at least one non-empty value.",
    "sensitive_local_policy_requires_provenance": "Add provenance.source and provenance.createdAt to the rule.",
    "policy_compilation_limit": "Split the policy, or list fewer tools, artifacts and harnesses per rule.",
    COMMAND_EXPRESSION_CODE: "Upgrade Guard to 3.1 or newer; until then the rule is validated but not enforced here.",
}

_TRUST_SUGGESTIONS: Final[dict[str, str]] = {
    "policy_file_not_owned": "Copy the file to one you own: cp {file} {file}.new && mv {file}.new {file}",
    "policy_file_link_count": "Replace it with a single-link copy: cp {file} {file}.new && mv {file}.new {file}",
    "policy_file_unavailable": "Check the path and that you can read the file.",
    "policy_file_too_large": "Split the policy into smaller rule sets; the limit is 1 MiB.",
    "policy_file_not_utf8": "Save the file as UTF-8.",
}


@dataclass(frozen=True, slots=True)
class StructuredDiagnostic:
    code: str
    path: str
    line: int | None
    col: int | None
    message: str
    category: DiagnosticCategory
    severity: Literal["error", "warning"] = "error"
    expected: object | None = None
    suggestion: str | None = None

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "code": self.code,
            "path": self.path,
            "line": self.line,
            "col": self.col,
            "message": self.message,
            "category": self.category,
            "severity": self.severity,
        }
        if self.expected is not None:
            payload["expected"] = self.expected
        if self.suggestion is not None:
            payload["suggestion"] = self.suggestion
        return payload


@dataclass(frozen=True, slots=True)
class PolicyValidationReport:
    status: ValidationStatus
    diagnostics: tuple[StructuredDiagnostic, ...]
    document: GuardPolicyDocument | None = None
    compiled: tuple[CompiledPolicyRow, ...] = ()
    local_store_reason: str | None = None

    @property
    def valid(self) -> bool:
        return self.status == "valid"

    @property
    def errors(self) -> tuple[StructuredDiagnostic, ...]:
        return tuple(item for item in self.diagnostics if item.severity == "error")


def format_json_path(path: JsonPath) -> str:
    """Render ``("spec", "rules", 0)`` as ``spec.rules[0]``; the root is ``$``."""

    if not path:
        return "$"
    rendered = ""
    for part in path:
        if isinstance(part, int):
            rendered += f"[{part}]"
        elif part.replace("_", "").replace("-", "").isalnum() and part:
            rendered += f".{part}" if rendered else part
        else:
            escaped = part[:80].replace('"', '\\"')
            rendered += f'["{escaped}"]'
    return rendered


def locate_policy_path(text: str, path: JsonPath) -> tuple[int | None, int | None]:
    """Return the 1-based line and column of ``path`` in ``text`` when it can be resolved."""

    try:
        node = _node_for_path(yaml.compose(text, Loader=_PolicyLoader), path)
    except yaml.YAMLError:
        return None, None
    if node is None:
        return None, None
    return node.start_mark.line + 1, node.start_mark.column + 1


def _schema_diagnostic(item: PolicyDiagnostic, text: str | None) -> StructuredDiagnostic:
    line, column = item.line, item.column
    if line is None and item.path and text is not None:
        line, column = locate_policy_path(text, item.path)
    return StructuredDiagnostic(
        code=item.code,
        path=format_json_path(item.path),
        line=line,
        col=column,
        message=_MESSAGES.get(item.code, "The document is not valid GuardPolicy v1alpha1."),
        category="schema_invalid",
        expected=item.expected,
        suggestion=item.suggestion,
    )


def file_trust_diagnostic(code: str, file: Path) -> StructuredDiagnostic:
    """A file Guard refuses to read, with the command that usually fixes it."""

    target = str(file)
    suggestion: str | None
    if code == "policy_file_insecure_mode":
        suggestion = f"chmod 600 {shlex.quote(target)}"
    elif code == "policy_parent_insecure_mode":
        suggestion = f"chmod go-w {shlex.quote(str(file.expanduser().absolute().parent))}"
    else:
        template = _TRUST_SUGGESTIONS.get(code)
        suggestion = template.format(file=shlex.quote(target)) if template is not None else None
    return StructuredDiagnostic(
        code=code,
        path="$",
        line=None,
        col=None,
        message=_MESSAGES.get(code, "Guard cannot trust this file."),
        category="file_untrusted",
        suggestion=suggestion,
    )


def compilation_diagnostic(
    error: PolicyCompilationError,
    document: GuardPolicyDocument | None,
    text: str | None,
) -> StructuredDiagnostic:
    """Map a compiler refusal onto the rule that caused it."""

    path: JsonPath = ()
    if document is not None:
        for index, rule in enumerate(document.rules):
            if rule.id == error.rule_id:
                path = ("spec", "rules", index)
                break
    line, column = locate_policy_path(text, path) if text is not None and path else (None, None)
    warning = error.code == COMMAND_EXPRESSION_CODE
    return StructuredDiagnostic(
        code=error.code,
        path=format_json_path(path),
        line=line,
        col=column,
        message=_MESSAGES.get(error.code, "Guard cannot enforce this rule."),
        category="not_enforceable",
        severity="warning" if warning else "error",
        expected=_NOT_ENFORCEABLE_EXPECTED.get(error.code),
        suggestion=_NOT_ENFORCEABLE_SUGGESTIONS.get(error.code),
    )


def schema_diagnostics_from_error(error: PolicyDocumentError, text: str | None) -> tuple[StructuredDiagnostic, ...]:
    return tuple(_schema_diagnostic(item, text) for item in error.diagnostics)


def parse_with_diagnostics(
    text: str,
) -> tuple[GuardPolicyDocument | None, tuple[StructuredDiagnostic, ...]]:
    """Parse ``text`` and report every schema problem, not only the first twenty."""

    try:
        return parse_policy_document_yaml(text, diagnostic_limit=None), ()
    except PolicyDocumentError as error:
        return None, schema_diagnostics_from_error(error, text)


def validate_policy_file(path: Path, *, diagnostic_limit: int | None = None) -> PolicyValidationReport:
    """Read, parse and compile one policy file and report every problem found.

    ``diagnostic_limit=None`` is the uncapped JSON mode; a number caps the text summary.
    """

    try:
        text = read_trusted_policy_text(path)
    except PolicyFileTrustError as error:
        return PolicyValidationReport("file_untrusted", (file_trust_diagnostic(error.code, path),))
    try:
        document = parse_policy_document_yaml(text, diagnostic_limit=diagnostic_limit)
    except PolicyDocumentError as error:
        return PolicyValidationReport("schema_invalid", schema_diagnostics_from_error(error, text))
    try:
        compiled = compile_document_for_import(document)
    except PolicyCompilationError as error:
        diagnostic = compilation_diagnostic(error, document, text)
        if diagnostic.severity == "warning":
            return PolicyValidationReport("valid", (diagnostic,), document=document, local_store_reason=error.code)
        return PolicyValidationReport("not_enforceable", (diagnostic,), document=document)
    except NativePolicySnapshotError as error:
        code = str(error) if re.fullmatch(r"[a-z0-9_]{1,80}", str(error)) else "unsupported_policy_match"
        diagnostic = StructuredDiagnostic(
            code=code,
            path="spec",
            line=None,
            col=None,
            message=_MESSAGES.get(code, "Guard cannot enforce this policy."),
            category="not_enforceable",
            suggestion=_NOT_ENFORCEABLE_SUGGESTIONS.get(code),
        )
        return PolicyValidationReport("not_enforceable", (diagnostic,), document=document)
    return PolicyValidationReport("valid", (), document=document, compiled=tuple(compiled))


__all__ = [
    "COMMAND_EXPRESSION_CODE",
    "DiagnosticCategory",
    "PolicyValidationReport",
    "StructuredDiagnostic",
    "ValidationStatus",
    "compilation_diagnostic",
    "file_trust_diagnostic",
    "format_json_path",
    "locate_policy_path",
    "parse_with_diagnostics",
    "schema_diagnostics_from_error",
    "validate_policy_file",
]
