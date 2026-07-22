"""Strict input validation for MCP policy authoring tools.

Every field is bounded, type-checked, and rejected if unknown.  No caller-
supplied path, URL, origin, environment override, or credential is accepted.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from dataclasses import dataclass

from ..policy_document_yaml import MAX_POLICY_BYTES
from ..store_policy_document import PolicyImportMode
from .policy_errors import PolicyToolError

_MAX_IDEMPOTENCY_KEY_LENGTH = 128
_MIN_IDEMPOTENCY_KEY_LENGTH = 8
_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_IDEMPOTENCY_KEY_PATTERN = re.compile(r"^[A-Za-z0-9._~-]{8,128}$")
_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9]{16,64}$")
_VALID_MODES = frozenset({"merge", "replace"})


def validate_policy_yaml(raw: object) -> str:
    if not isinstance(raw, str):
        raise PolicyToolError("invalid_arguments", "policyYaml must be a string.")
    if not raw.strip():
        raise PolicyToolError("invalid_arguments", "policyYaml must not be empty.")
    if len(raw.encode("utf-8")) > MAX_POLICY_BYTES:
        raise PolicyToolError("policy_too_large", "policyYaml exceeds the maximum document size.")
    return raw


def validate_mode(raw: object) -> PolicyImportMode:
    if raw is None:
        return "merge"
    if not isinstance(raw, str) or raw not in _VALID_MODES:
        raise PolicyToolError("invalid_arguments", "mode must be 'merge' or 'replace'.")
    if raw == "merge":
        return "merge"
    return "replace"


def validate_required_mode(raw: object) -> PolicyImportMode:
    if not isinstance(raw, str) or raw not in _VALID_MODES:
        raise PolicyToolError("invalid_arguments", "mode must be 'merge' or 'replace'.")
    if raw == "merge":
        return "merge"
    return "replace"


def validate_digest(raw: object, *, field: str) -> str:
    if not isinstance(raw, str) or not _DIGEST_PATTERN.match(raw):
        raise PolicyToolError("invalid_arguments", f"{field} must be 64 lowercase hex characters.")
    return raw


def validate_optional_digest(raw: object, *, field: str) -> str | None:
    if raw is None:
        return None
    return validate_digest(raw, field=field)


def validate_idempotency_key(raw: object) -> str:
    if not isinstance(raw, str) or not _IDEMPOTENCY_KEY_PATTERN.match(raw):
        raise PolicyToolError(
            "invalid_arguments",
            "idempotencyKey must be 8-128 URL-safe characters [A-Za-z0-9._~-].",
        )
    return raw


def validate_request_id(raw: object) -> str:
    if not isinstance(raw, str) or not _REQUEST_ID_PATTERN.match(raw):
        raise PolicyToolError("invalid_arguments", "requestId must be 16-64 alphanumeric characters.")
    return raw


def hash_idempotency_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def generate_request_id() -> str:
    return secrets.token_urlsafe(32).replace("-", "").replace("_", "")[:32]


def reject_unknown_keys(arguments: dict[str, object], allowed: frozenset[str]) -> None:
    unknown = set(arguments.keys()) - allowed
    if unknown:
        raise PolicyToolError("invalid_arguments", f"Unknown arguments: {sorted(unknown)}")


@dataclass(frozen=True, slots=True)
class ValidatePolicyInput:
    policy_yaml: str
    mode: PolicyImportMode


@dataclass(frozen=True, slots=True)
class CreatePolicyInput:
    policy_yaml: str
    mode: PolicyImportMode
    candidate_digest: str
    expected_current_digest: str | None
    idempotency_key: str


@dataclass(frozen=True, slots=True)
class GetPolicyCreationInput:
    request_id: str


def parse_validate_policy_input(arguments: dict[str, object]) -> ValidatePolicyInput:
    reject_unknown_keys(arguments, frozenset({"policyYaml", "mode"}))
    return ValidatePolicyInput(
        policy_yaml=validate_policy_yaml(arguments.get("policyYaml")),
        mode=validate_mode(arguments.get("mode")),
    )


def parse_create_policy_input(arguments: dict[str, object]) -> CreatePolicyInput:
    reject_unknown_keys(
        arguments,
        frozenset({"policyYaml", "mode", "candidateDigest", "expectedCurrentDigest", "idempotencyKey"}),
    )
    return CreatePolicyInput(
        policy_yaml=validate_policy_yaml(arguments.get("policyYaml")),
        mode=validate_required_mode(arguments.get("mode")),
        candidate_digest=validate_digest(arguments.get("candidateDigest"), field="candidateDigest"),
        expected_current_digest=validate_optional_digest(
            arguments.get("expectedCurrentDigest"), field="expectedCurrentDigest"
        ),
        idempotency_key=validate_idempotency_key(arguments.get("idempotencyKey")),
    )


def parse_get_policy_creation_input(arguments: dict[str, object]) -> GetPolicyCreationInput:
    reject_unknown_keys(arguments, frozenset({"requestId"}))
    return GetPolicyCreationInput(
        request_id=validate_request_id(arguments.get("requestId")),
    )


__all__ = [
    "CreatePolicyInput",
    "GetPolicyCreationInput",
    "PolicyImportMode",
    "ValidatePolicyInput",
    "generate_request_id",
    "hash_idempotency_key",
    "parse_create_policy_input",
    "parse_get_policy_creation_input",
    "parse_validate_policy_input",
    "validate_idempotency_key",
    "validate_mode",
    "validate_optional_digest",
    "validate_policy_yaml",
    "validate_request_id",
    "validate_required_mode",
]
