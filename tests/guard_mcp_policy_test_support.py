"""Shared fixtures and leakage assertions for the MCP policy test modules."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.policy_document import policy_document_digest
from codex_plugin_scanner.guard.policy_document_yaml import parse_policy_document_yaml
from codex_plugin_scanner.guard.store import GuardStore

_BASIC_POLICY_YAML = """
apiVersion: guard.hashgraphonline.com/v1alpha1
kind: GuardPolicy
metadata:
  id: policy.test-defaults
  name: Test defaults
  revision: 1
spec:
  defaults:
    mode: prompt
    defaultAction: warn
  rolloutState: draft
  rules:
    - id: rule.block-bad-package
      description: Block bad package installs
      enabled: true
      effect: block
      match:
        artifacts:
          - npm:bad-package
        harnesses:
          - claude-code
      lifetime:
        mode: permanent
        expiresAt: null
      provenance:
        source: suggested-memory
        createdAt: 2026-07-15T12:00:00Z
        createdBy: user-001
"""


_BASIC_POLICY_YAML_2 = """\
apiVersion: guard.hashgraphonline.com/v1alpha1
kind: GuardPolicy
metadata:
  id: policy.test-defaults
  name: Test defaults
  revision: 2
spec:
  defaults:
    mode: prompt
    defaultAction: warn
  rolloutState: draft
  rules:
    - id: rule.block-bad-package
      description: Block bad package installs
      enabled: true
      effect: block
      match:
        artifacts:
          - npm:bad-package
        harnesses:
          - claude-code
      lifetime:
        mode: permanent
        expiresAt: null
      provenance:
        source: suggested-memory
        createdAt: 2026-07-15T12:00:00Z
        createdBy: user-001
    - id: rule.block-other-package
      description: Block other package installs
      enabled: true
      effect: block
      match:
        artifacts:
          - npm:other-package
        harnesses:
          - claude-code
      lifetime:
        mode: permanent
        expiresAt: null
      provenance:
        source: suggested-memory
        createdAt: 2026-07-15T12:00:00Z
        createdBy: user-001
"""


@pytest.fixture()
def store(tmp_path: Path) -> GuardStore:
    return GuardStore(tmp_path / "guard-home")


def _import_policy(store: GuardStore, yaml: str, mode: str = "merge") -> None:
    """Compile and import a policy document, bypassing the approval gate."""
    from codex_plugin_scanner.guard.mcp.policy_tools import _now_iso
    from codex_plugin_scanner.guard.policy_document_compile import compile_policy_document
    from codex_plugin_scanner.guard.policy_document_yaml import parse_policy_document_yaml

    document = parse_policy_document_yaml(yaml)
    compiled = compile_policy_document(document)
    store.import_policy_document(
        document,
        compiled,
        mode=mode,
        now=_now_iso(),
        approval_gate_grant=None,
    )


@pytest.fixture()
def env_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOL_GUARD_POLICY_YAML_IMPORT", "1")
    monkeypatch.setenv("HOL_GUARD_MCP_POLICY_WRITE", "1")


def _digest(yaml: str) -> str:
    document = parse_policy_document_yaml(yaml)
    return policy_document_digest(document)


_FIXTURE_TOTP_REQUEST_ID = "FixturetotpRequestId0123456789AB"


_CREDENTIAL_WORDS = ("password", "totp", "secret", "token", "credential", "passphrase")
_REQUEST_ID_PATTERN = r"[A-Za-z0-9]{16,64}"
_REQUEST_ID_FIELD = "requestId"


@pytest.fixture(params=(None, _FIXTURE_TOTP_REQUEST_ID), ids=("random-id", "totp-id"))
def opaque_request_id(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> str | None:
    request_id = request.param
    if request_id is not None:
        monkeypatch.setattr("codex_plugin_scanner.guard.mcp.policy_store.generate_request_id", lambda: request_id)
    return request_id


def _assert_no_policy_response_leaks(
    payload: dict[str, object], *, request_id: str, sensitive_values: tuple[str, ...] = ()
) -> None:
    assert re.fullmatch(_REQUEST_ID_PATTERN, request_id), "Invalid expected request ID"
    assert payload.get(_REQUEST_ID_FIELD) == request_id, "Response request ID changed"
    serialized = json.dumps(payload, sort_keys=True)
    for value in sensitive_values:
        assert value and value not in serialized, "Response leaked sensitive value"

    # Only the verified root correlation ID may coincidentally contain a credential word.
    checked_payload = {**payload, _REQUEST_ID_FIELD: ""}
    serialized = json.dumps(checked_payload, sort_keys=True)
    assert "apiVersion:" not in serialized, "Response leaked policy YAML"
    for field in ("canonicalPolicyYaml", "canonical_policy_yaml"):
        assert field not in serialized, f"Response leaked policy YAML field: {field}"
    for word in _CREDENTIAL_WORDS:
        assert word not in serialized.lower(), f"Response leaked credential-like key or value: {word}"
