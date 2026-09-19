"""Lossless bounded projections of canonical command-expression rules.

This is compilation output, not signature verification, runtime negotiation, or
application evidence. A caller must authenticate the original complete bundle
and bind both target identity and local installation before using this output.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Literal
from uuid import UUID

from .models import PolicyDecision
from .policy_document import GuardPolicyDocument, PolicyMatch, PolicyRule, policy_document_digest
from .policy_document_compile import compile_policy_document
from .policy_document_types import PolicyCompilationError
from .policy_publication_binding import PolicyPublicationBinding
from .policy_rule_identity import PolicyRuleIdentity
from .runtime.command_expression import CommandExpression, validate_command_expression

MAX_PROJECTED_COMMAND_ROWS = 256
_SUPPORTED_SELECTORS = frozenset({"artifacts", "harnesses", "publishers", "tools", "workspaces", "devices"})
_MANAGED_EXTENSIONS = frozenset({"x-hol-extension-controls", "x-hol-custom-extension-continuity"})


@dataclass(frozen=True, slots=True)
class CanonicalCommandSource:
    """Retain source identities without confusing delivery and document versions."""

    workspace_id: str
    target_device_id: str
    publication: PolicyPublicationBinding
    policy_id: str
    policy_version: str
    payload_hash: str


@dataclass(frozen=True, slots=True)
class CanonicalCommandRow:
    """The expression AND every existing selector, with unchanged expiry."""

    selector: PolicyDecision
    identity: PolicyRuleIdentity
    expression: CommandExpression | None
    device_selectors: tuple[str, ...]
    applicable_to_target: bool
    provenance_json: str


@dataclass(frozen=True, slots=True)
class CanonicalRuleDisposition:
    identity: PolicyRuleIdentity
    kind: Literal["inert", "generic", "expression"]
    device_selectors: tuple[str, ...]
    applicable_to_target: bool
    row_count: int


@dataclass(frozen=True, slots=True)
class CanonicalCommandProjection:
    source: CanonicalCommandSource
    rows: tuple[CanonicalCommandRow, ...]
    rule_dispositions: tuple[CanonicalRuleDisposition, ...]


def _reject(code: str, rule_id: str) -> None:
    raise PolicyCompilationError(code, rule_id)


def _document_boundary(document: GuardPolicyDocument) -> None:
    for key, _ in document.spec_extensions:
        code = (
            "network_policy_requires_separate_runtime"
            if key == "networkPolicy"
            else "command_source_extension_unsupported"
        )
        _reject(code, document.metadata.id)
    for key, _ in document.extensions:
        code = (
            "managed_policy_requires_separate_runtime"
            if key in _MANAGED_EXTENSIONS
            else "command_source_extension_unsupported"
        )
        _reject(code, document.metadata.id)
    if document.defaults.extensions:
        _reject("command_default_extension_unsupported", document.metadata.id)


def _selector_projection(rule: PolicyRule) -> tuple[PolicyMatch, tuple[str, ...]]:
    """Only remove fields retained explicitly by this projection's typed row."""
    if rule.match.extensions or any(key not in _SUPPORTED_SELECTORS for key, _ in rule.match.fields):
        _reject("command_selector_unsupported", rule.id)
    if rule.lifetime.extensions:
        _reject("command_lifetime_extension_unsupported", rule.id)
    if rule.extensions:
        code = (
            "managed_rule_requires_separate_runtime"
            if any(key == "x-hol-extension-targets" for key, _ in rule.extensions)
            else "command_rule_extension_unsupported"
        )
        _reject(code, rule.id)
    devices = next((values for key, values in rule.match.fields if key == "devices"), ())
    if any(not values for _, values in rule.match.fields):
        _reject("invalid_policy_match_selector", rule.id)
    return replace(
        rule.match,
        command_expression=None,
        fields=tuple((key, values) for key, values in rule.match.fields if key != "devices"),
    ), devices


def project_canonical_command_policy(
    document: GuardPolicyDocument,
    *,
    publication: PolicyPublicationBinding,
    workspace_id: str,
    target_device_id: str,
) -> CanonicalCommandProjection:
    """Account for every rule, refusing the whole projection on any active gap.

    target_device_id is the delivery target identity resolved by the authenticated
    caller. publication.installation_id is a separate local source identity; it
    is deliberately never used as an alias for a devices selector.
    """
    if type(publication) is not PolicyPublicationBinding:
        raise TypeError("command_publication_binding_required")
    try:
        if str(UUID(workspace_id)) != workspace_id:
            raise ValueError
    except (ValueError, AttributeError, TypeError) as error:
        raise ValueError("command_workspace_identity_invalid") from error
    if (
        not isinstance(target_device_id, str)
        or not 1 <= len(target_device_id) <= 256
        or any(not 0x21 <= ord(character) <= 0x7E for character in target_device_id)
    ):
        raise ValueError("command_target_identity_invalid")
    _document_boundary(document)
    rows: list[CanonicalCommandRow] = []
    dispositions: list[CanonicalRuleDisposition] = []
    seen: set[str] = set()
    for rule in document.rules:
        if rule.id in seen:
            _reject("duplicate_policy_rule_id", rule.id)
        seen.add(rule.id)
        identity = PolicyRuleIdentity(document.metadata.id, rule.id, str(document.metadata.revision), publication)
        devices = next((values for key, values in rule.match.fields if key == "devices"), ())
        applicable = not devices or target_device_id in devices
        if not rule.enabled or rule.effect == "ignore":
            dispositions.append(CanonicalRuleDisposition(identity, "inert", devices, applicable, 0))
            continue
        stripped_match, devices = _selector_projection(rule)
        expression = rule.match.command_expression
        if expression is not None:
            validate_command_expression(expression)
        compiled = compile_policy_document(replace(document, rules=(replace(rule, match=stripped_match),)))
        if len(rows) + len(compiled) > MAX_PROJECTED_COMMAND_ROWS:
            _reject("command_projection_row_limit", rule.id)
        for row in compiled:
            rows.append(
                CanonicalCommandRow(
                    selector=replace(row.decision, owner=rule.id, source="policy-bundle-canonical"),
                    identity=identity,
                    expression=expression,
                    device_selectors=devices,
                    applicable_to_target=applicable,
                    provenance_json=row.provenance_json,
                )
            )
        dispositions.append(
            CanonicalRuleDisposition(
                identity,
                "expression" if expression is not None else "generic",
                devices,
                applicable,
                len(compiled),
            )
        )
    return CanonicalCommandProjection(
        source=CanonicalCommandSource(
            workspace_id,
            target_device_id,
            publication,
            document.metadata.id,
            str(document.metadata.revision),
            "sha256:" + policy_document_digest(document),
        ),
        rows=tuple(rows),
        rule_dispositions=tuple(dispositions),
    )
