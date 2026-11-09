"""Strict input validation for MCP policy authoring tools.

The native runtime owns the checks (``mcp_policy_input``): every field is
bounded, type-checked, and rejected if unknown. No caller-supplied path, URL,
origin, environment override, or credential is accepted. A runtime that cannot
answer fails the call as retryable; it never lets an unchecked argument through.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from typing import Any

from ..native_policy_document import NativePolicyDocumentError
from ..policy_document_yaml import MAX_POLICY_BYTES
from ..store_policy_document import PolicyImportMode
from .policy_errors import INVALID_ARGUMENTS, POLICY_TOO_LARGE, PolicyToolError

_KIND = "mcp_policy_input"
_REFUSALS = frozenset({INVALID_ARGUMENTS, POLICY_TOO_LARGE})
_MODES: dict[object, PolicyImportMode] = {"merge": "merge", "replace": "replace"}


def hash_idempotency_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def generate_request_id() -> str:
    return secrets.token_urlsafe(32).replace("-", "").replace("_", "")[:32]


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


def _checked(tool: str, arguments: dict[str, object]) -> dict[str, Any]:
    policy_yaml = arguments.get("policyYaml")
    # Oversize text stays out of the bounded request. An ASCII stand-in just
    # past the limit, blank exactly when the policy is, keeps every earlier
    # refusal (unknown keys, type, blank text) ahead of the size one.
    if isinstance(policy_yaml, str) and len(policy_yaml.encode("utf-8", "surrogatepass")) > MAX_POLICY_BYTES:
        stand_in = ("x" if policy_yaml.strip() else " ") * (MAX_POLICY_BYTES + 1)
        arguments = {**arguments, "policyYaml": stand_in}
    from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    try:
        answer = native_runner_authority(_KIND, {"tool": tool, "arguments": arguments})
    except NativeRunnerAuthorityError as error:
        raise NativePolicyDocumentError(_KIND) from error
    refusal = answer.get("error")
    if isinstance(refusal, dict) and refusal.get("code") in _REFUSALS and isinstance(refusal.get("message"), str):
        raise PolicyToolError(refusal["code"], refusal["message"])
    value = answer.get("value")
    if not isinstance(value, dict):
        raise NativePolicyDocumentError(_KIND)
    return value


def _text(value: dict[str, Any], key: str) -> str:
    text = value.get(key)
    if not isinstance(text, str):
        raise NativePolicyDocumentError(_KIND)
    return text


def _mode(value: dict[str, Any]) -> PolicyImportMode:
    mode = _MODES.get(value.get("mode"))
    if mode is None:
        raise NativePolicyDocumentError(_KIND)
    return mode


def _policy_yaml(arguments: dict[str, object]) -> str:
    policy_yaml = arguments.get("policyYaml")
    if not isinstance(policy_yaml, str):
        raise NativePolicyDocumentError(_KIND)
    return policy_yaml


def parse_validate_policy_input(arguments: dict[str, object]) -> ValidatePolicyInput:
    value = _checked("validate_policy", arguments)
    return ValidatePolicyInput(policy_yaml=_policy_yaml(arguments), mode=_mode(value))


def parse_create_policy_input(arguments: dict[str, object]) -> CreatePolicyInput:
    value = _checked("create_policy", arguments)
    expected = value.get("expected_current_digest")
    return CreatePolicyInput(
        policy_yaml=_policy_yaml(arguments),
        mode=_mode(value),
        candidate_digest=_text(value, "candidate_digest"),
        expected_current_digest=None if expected is None else _text(value, "expected_current_digest"),
        idempotency_key=_text(value, "idempotency_key"),
    )


def parse_get_policy_creation_input(arguments: dict[str, object]) -> GetPolicyCreationInput:
    return GetPolicyCreationInput(request_id=_text(_checked("get_policy_creation", arguments), "request_id"))


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
]
