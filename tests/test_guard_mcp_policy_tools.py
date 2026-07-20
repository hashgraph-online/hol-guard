"""Tests for MCP policy authoring tools: validate_policy, create_policy,
get_policy_creation, apply_pending_policy_request, decline_pending_policy_request.

These tests exercise the framework-independent execute_* functions and the
MCPolicyRequestRepository directly, without FastMCP or stdio transport.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.mcp.policy_errors import PolicyToolError
from codex_plugin_scanner.guard.mcp.policy_schemas import (
    parse_create_policy_input,
    parse_get_policy_creation_input,
    parse_validate_policy_input,
)
from codex_plugin_scanner.guard.mcp.policy_store import MCPolicyRequestRepository, StageRequestInput
from codex_plugin_scanner.guard.mcp.policy_tools import (
    apply_pending_policy_request,
    decline_pending_policy_request,
    execute_create_policy,
    execute_get_policy_creation,
    execute_validate_policy,
)
from codex_plugin_scanner.guard.policy_document import policy_document_digest
from codex_plugin_scanner.guard.policy_document_yaml import (
    format_policy_document_yaml,
    parse_policy_document_yaml,
)
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


class TestValidatePolicy:
    """validate_policy: read-only, no state writes."""

    def test_validate_returns_valid_and_digests(self, store: GuardStore) -> None:
        result_text = execute_validate_policy(
            store,
            {"policyYaml": _BASIC_POLICY_YAML, "mode": "merge"},
        )
        result = json.loads(result_text)
        assert result["ok"] is True
        assert result["valid"] is True
        assert result["documentId"] == "policy.test-defaults"
        assert result["mode"] == "merge"
        assert result["ruleCount"] == 1
        assert result["writeEnabled"] is False
        assert result["requiresHumanApproval"] is True
        assert "candidateDigest" in result
        assert result["currentDigest"] is None
        assert "semanticDiff" in result
        assert "writePlan" in result

    def test_validate_reports_current_digest_when_policy_exists(self, store: GuardStore) -> None:
        _import_policy(store, _BASIC_POLICY_YAML, mode="merge")

        result_text = execute_validate_policy(
            store,
            {"policyYaml": _BASIC_POLICY_YAML, "mode": "merge"},
        )
        result = json.loads(result_text)
        assert result["currentDigest"] is not None
        # candidateDigest is computed from the YAML; currentDigest from
        # stored rows. They may differ due to row normalization, so we
        # only assert that a current digest exists.

    def test_validate_rejects_invalid_yaml(self, store: GuardStore) -> None:
        with pytest.raises(PolicyToolError) as exc:
            execute_validate_policy(store, {"policyYaml": "not: valid: yaml: [", "mode": "merge"})
        assert exc.value.code in {"policy_parse_failed", "yaml_parse", "schema_oneOf"}

    def test_validate_default_mode_is_merge(self, store: GuardStore) -> None:
        result_text = execute_validate_policy(store, {"policyYaml": _BASIC_POLICY_YAML})
        result = json.loads(result_text)
        assert result["mode"] == "merge"


class TestCreatePolicy:
    """create_policy: stages a pending request, does not apply."""

    def test_create_stages_pending_request(self, store: GuardStore, env_flags: None) -> None:
        candidate_digest = _digest(_BASIC_POLICY_YAML)
        result_text = execute_create_policy(
            store,
            {
                "policyYaml": _BASIC_POLICY_YAML,
                "mode": "merge",
                "candidateDigest": candidate_digest,
                "expectedCurrentDigest": None,
                "idempotencyKey": "policy-request-fixture",
            },
        )
        result = json.loads(result_text)
        assert result["ok"] is True
        assert result["status"] == "pending"
        assert "requestId" in result
        assert result["documentId"] == "policy.test-defaults"
        assert result["candidateDigest"] == candidate_digest
        assert "createdAt" in result
        assert "expiresAt" in result

    def test_create_rejects_digest_mismatch(self, store: GuardStore, env_flags: None) -> None:
        with pytest.raises(PolicyToolError) as exc:
            execute_create_policy(
                store,
                {
                    "policyYaml": _BASIC_POLICY_YAML,
                    "mode": "merge",
                    "candidateDigest": "a" * 64,
                    "expectedCurrentDigest": None,
                    "idempotencyKey": "policy-request-fixture",
                },
            )
        assert exc.value.code == "candidate_digest_mismatch"

    def test_create_stages_when_policy_exists(self, store: GuardStore, env_flags: None) -> None:
        _import_policy(store, _BASIC_POLICY_YAML, mode="merge")

        # Get the actual current digest from validate_policy (computed
        # from stored rows, which may differ from the YAML digest due to
        # row normalization).
        validate_result = json.loads(
            execute_validate_policy(store, {"policyYaml": _BASIC_POLICY_YAML, "mode": "merge"})
        )
        candidate_digest = validate_result["candidateDigest"]
        current_digest = validate_result["currentDigest"]

        result_text = execute_create_policy(
            store,
            {
                "policyYaml": _BASIC_POLICY_YAML,
                "mode": "merge",
                "candidateDigest": candidate_digest,
                "expectedCurrentDigest": current_digest,
                "idempotencyKey": "policy-request-fixture",
            },
        )
        result = json.loads(result_text)
        assert result["ok"] is True
        assert result["status"] == "pending"

    def test_create_rejects_when_write_disabled(self, store: GuardStore, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HOL_GUARD_POLICY_YAML_IMPORT", "1")
        monkeypatch.delenv("HOL_GUARD_MCP_POLICY_WRITE", raising=False)
        with pytest.raises(PolicyToolError) as exc:
            execute_create_policy(
                store,
                {
                    "policyYaml": _BASIC_POLICY_YAML,
                    "mode": "merge",
                    "candidateDigest": _digest(_BASIC_POLICY_YAML),
                    "expectedCurrentDigest": None,
                    "idempotencyKey": "policy-request-fixture",
                },
            )
        assert exc.value.code == "mcp_policy_write_disabled"

    def test_create_idempotency_replay(self, store: GuardStore, env_flags: None) -> None:
        candidate_digest = _digest(_BASIC_POLICY_YAML)
        args = {
            "policyYaml": _BASIC_POLICY_YAML,
            "mode": "merge",
            "candidateDigest": candidate_digest,
            "expectedCurrentDigest": None,
            "idempotencyKey": "replay-fixture-request",
        }
        result1 = json.loads(execute_create_policy(store, args))
        result2 = json.loads(execute_create_policy(store, args))
        assert result1["requestId"] == result2["requestId"]
        assert result1["status"] == result2["status"]

    def test_create_approval_url_builder(self, store: GuardStore, env_flags: None) -> None:
        candidate_digest = _digest(_BASIC_POLICY_YAML)

        def url_builder(request_id: str) -> str:
            return f"http://127.0.0.1:9999/requests/{request_id}"

        result_text = execute_create_policy(
            store,
            {
                "policyYaml": _BASIC_POLICY_YAML,
                "mode": "merge",
                "candidateDigest": candidate_digest,
                "expectedCurrentDigest": None,
                "idempotencyKey": "policy-request-fixture",
            },
            approval_url_builder=url_builder,
        )
        result = json.loads(result_text)
        assert result["approvalUrl"] == f"http://127.0.0.1:9999/requests/{result['requestId']}"


class TestGetPolicyCreation:
    """get_policy_creation: reads request status by opaque ID."""

    def test_get_returns_pending_status(self, store: GuardStore, env_flags: None) -> None:
        candidate_digest = _digest(_BASIC_POLICY_YAML)
        create_result = json.loads(
            execute_create_policy(
                store,
                {
                    "policyYaml": _BASIC_POLICY_YAML,
                    "mode": "merge",
                    "candidateDigest": candidate_digest,
                    "expectedCurrentDigest": None,
                    "idempotencyKey": "policy-request-fixture",
                },
            )
        )
        request_id = create_result["requestId"]

        result_text = execute_get_policy_creation(store, {"requestId": request_id})
        result = json.loads(result_text)
        assert result["ok"] is True
        assert result["requestId"] == request_id
        assert result["status"] == "pending"
        assert result["candidateDigest"] == candidate_digest

    def test_get_returns_not_found_for_unknown_id(self, store: GuardStore) -> None:
        with pytest.raises(PolicyToolError) as exc:
            execute_get_policy_creation(store, {"requestId": "nonexistentrequestid1234"})
        assert exc.value.code == "policy_request_not_found"


class TestApplyPendingPolicyRequest:
    """apply_pending_policy_request: atomic apply after approval."""

    def test_apply_transitions_to_applied(self, store: GuardStore, env_flags: None) -> None:
        candidate_digest = _digest(_BASIC_POLICY_YAML)
        create_result = json.loads(
            execute_create_policy(
                store,
                {
                    "policyYaml": _BASIC_POLICY_YAML,
                    "mode": "merge",
                    "candidateDigest": candidate_digest,
                    "expectedCurrentDigest": None,
                    "idempotencyKey": "policy-request-fixture",
                },
            )
        )
        request_id = create_result["requestId"]

        result = apply_pending_policy_request(store, request_id, approval_gate_grant=object())
        assert result["status"] == "applied"
        assert result["inserted"] >= 1
        assert "resolvedAt" in result

    def test_apply_rejects_already_resolved(self, store: GuardStore, env_flags: None) -> None:
        candidate_digest = _digest(_BASIC_POLICY_YAML)
        create_result = json.loads(
            execute_create_policy(
                store,
                {
                    "policyYaml": _BASIC_POLICY_YAML,
                    "mode": "merge",
                    "candidateDigest": candidate_digest,
                    "expectedCurrentDigest": None,
                    "idempotencyKey": "policy-request-fixture",
                },
            )
        )
        request_id = create_result["requestId"]

        apply_pending_policy_request(store, request_id, approval_gate_grant=object())
        with pytest.raises(PolicyToolError) as exc:
            apply_pending_policy_request(store, request_id, approval_gate_grant=object())
        assert exc.value.code == "approval_already_resolved"

    def test_apply_rejects_not_found(self, store: GuardStore) -> None:
        with pytest.raises(PolicyToolError) as exc:
            apply_pending_policy_request(store, "nonexistent-id", approval_gate_grant=object())
        assert exc.value.code == "policy_request_not_found"

    def test_apply_rejects_current_digest_mismatch(
        self, store: GuardStore, env_flags: None
    ) -> None:
        candidate_digest_v1 = _digest(_BASIC_POLICY_YAML)
        create_result = json.loads(
            execute_create_policy(
                store,
                {
                    "policyYaml": _BASIC_POLICY_YAML,
                    "mode": "merge",
                    "candidateDigest": candidate_digest_v1,
                    "expectedCurrentDigest": None,
                    "idempotencyKey": "policy-request-fixture",
                },
            )
        )
        request_id = create_result["requestId"]

        _import_policy(store, _BASIC_POLICY_YAML, mode="merge")

        with pytest.raises(PolicyToolError) as exc:
            apply_pending_policy_request(store, request_id, approval_gate_grant=object())
        assert exc.value.code == "current_digest_mismatch"


class TestDeclinePendingPolicyRequest:
    """decline_pending_policy_request: marks request as declined."""

    def test_decline_transitions_to_declined(self, store: GuardStore, env_flags: None) -> None:
        candidate_digest = _digest(_BASIC_POLICY_YAML)
        create_result = json.loads(
            execute_create_policy(
                store,
                {
                    "policyYaml": _BASIC_POLICY_YAML,
                    "mode": "merge",
                    "candidateDigest": candidate_digest,
                    "expectedCurrentDigest": None,
                    "idempotencyKey": "policy-request-fixture",
                },
            )
        )
        request_id = create_result["requestId"]

        result = decline_pending_policy_request(store, request_id)
        assert result["status"] == "declined"
        assert "resolvedAt" in result

    def test_decline_rejects_already_resolved(self, store: GuardStore, env_flags: None) -> None:
        candidate_digest = _digest(_BASIC_POLICY_YAML)
        create_result = json.loads(
            execute_create_policy(
                store,
                {
                    "policyYaml": _BASIC_POLICY_YAML,
                    "mode": "merge",
                    "candidateDigest": candidate_digest,
                    "expectedCurrentDigest": None,
                    "idempotencyKey": "policy-request-fixture",
                },
            )
        )
        request_id = create_result["requestId"]

        decline_pending_policy_request(store, request_id)
        with pytest.raises(PolicyToolError):
            decline_pending_policy_request(store, request_id)


class TestPolicySchemas:
    """Input validation for the three new tools."""

    def test_parse_validate_policy_input_defaults_mode(self) -> None:
        parsed = parse_validate_policy_input({"policyYaml": "apiVersion: x"})
        assert parsed.mode == "merge"

    def test_parse_validate_policy_input_rejects_missing_yaml(self) -> None:
        with pytest.raises(PolicyToolError):
            parse_validate_policy_input({})

    def test_parse_create_policy_input_requires_all_fields(self) -> None:
        with pytest.raises(PolicyToolError):
            parse_create_policy_input({"policyYaml": "x"})

    def test_parse_create_policy_input_validates_digest_format(self) -> None:
        with pytest.raises(PolicyToolError):
            parse_create_policy_input(
                {
                    "policyYaml": "x",
                    "mode": "merge",
                    "candidateDigest": "short",
                    "expectedCurrentDigest": None,
                    "idempotencyKey": "short",
                }
            )

    def test_parse_get_policy_creation_input_requires_request_id(self) -> None:
        with pytest.raises(PolicyToolError):
            parse_get_policy_creation_input({})


class TestPolicyStoreRepository:
    """Direct repository tests for staging, fetching, and expiry."""

    def test_stage_and_get_request(self, store: GuardStore) -> None:
        repo = MCPolicyRequestRepository(store)
        document = parse_policy_document_yaml(_BASIC_POLICY_YAML)
        digest = policy_document_digest(document)
        canonical_yaml = format_policy_document_yaml(document)

        staged = repo.stage_request(
            StageRequestInput(policy_document_id=document.metadata.id,
            policy_document_digest=digest,
            expected_current_digest=None,
            expected_policy_generation=None,
            mode="merge",
            canonical_policy_yaml=canonical_yaml,
            plan_json='{"additions":[],"replacements":[],"removals":[]}',
            idempotency_key="policy-request-fixture",)
        )
        assert staged.status == "pending"

        fetched = repo.get_request(staged.request_id)
        assert fetched is not None
        assert fetched.request_id == staged.request_id
        assert fetched.status == "pending"

    def test_list_pending_requests(self, store: GuardStore) -> None:
        repo = MCPolicyRequestRepository(store)
        document = parse_policy_document_yaml(_BASIC_POLICY_YAML)
        digest = policy_document_digest(document)
        canonical_yaml = format_policy_document_yaml(document)

        repo.stage_request(
            StageRequestInput(policy_document_id=document.metadata.id,
            policy_document_digest=digest,
            expected_current_digest=None,
            expected_policy_generation=None,
            mode="merge",
            canonical_policy_yaml=canonical_yaml,
            plan_json='{"additions":[],"replacements":[],"removals":[]}',
            idempotency_key="policy-request-fixture",)
        )
        pending = repo.list_pending_requests()
        assert len(pending) == 1

    def test_idempotency_conflict_on_different_yaml(self, store: GuardStore) -> None:
        repo = MCPolicyRequestRepository(store)
        document = parse_policy_document_yaml(_BASIC_POLICY_YAML)
        digest = policy_document_digest(document)
        canonical_yaml = format_policy_document_yaml(document)

        repo.stage_request(
            StageRequestInput(policy_document_id=document.metadata.id,
            policy_document_digest=digest,
            expected_current_digest=None,
            expected_policy_generation=None,
            mode="merge",
            canonical_policy_yaml=canonical_yaml,
            plan_json='{}',
            idempotency_key="shared-fixture-request",)
        )
        document2 = parse_policy_document_yaml(_BASIC_POLICY_YAML_2)
        digest2 = policy_document_digest(document2)
        canonical_yaml2 = format_policy_document_yaml(document2)
        with pytest.raises(PolicyToolError) as exc:
            repo.stage_request(
                StageRequestInput(policy_document_id=document2.metadata.id,
                policy_document_digest=digest2,
                expected_current_digest=None,
                expected_policy_generation=None,
                mode="merge",
                canonical_policy_yaml=canonical_yaml2,
                plan_json='{}',
                idempotency_key="shared-fixture-request",)
            )
        assert exc.value.code == "idempotency_conflict"


class TestGetGuardStatusPolicyFields:
    """get_guard_status includes additive policy authoring fields."""

    def test_status_includes_policy_authoring_fields(self, store: GuardStore) -> None:
        from codex_plugin_scanner.guard.mcp.tools import execute_get_guard_status

        result_text = execute_get_guard_status(store)
        result = json.loads(result_text)
        assert "policyAuthoringAvailable" in result
        assert "policyWriteEnabled" in result
        assert "policySchemaVersion" in result
        assert "pendingPolicyRequests" in result
        assert result["policySchemaVersion"] == "1.0"
        assert result["pendingPolicyRequests"] == 0

    def test_status_reflects_enabled_flags(
        self, store: GuardStore, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from codex_plugin_scanner.guard.mcp.tools import execute_get_guard_status

        monkeypatch.setenv("HOL_GUARD_POLICY_YAML_IMPORT", "1")
        monkeypatch.setenv("HOL_GUARD_MCP_POLICY_WRITE", "1")
        result = json.loads(execute_get_guard_status(store))
        assert result["policyAuthoringAvailable"] is True
        assert result["policyWriteEnabled"] is True

    def test_status_reflects_disabled_flags(
        self, store: GuardStore, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from codex_plugin_scanner.guard.mcp.tools import execute_get_guard_status

        monkeypatch.delenv("HOL_GUARD_POLICY_YAML_IMPORT", raising=False)
        monkeypatch.delenv("HOL_GUARD_MCP_POLICY_WRITE", raising=False)
        result = json.loads(execute_get_guard_status(store))
        assert result["policyAuthoringAvailable"] is False
        assert result["policyWriteEnabled"] is False


class TestDaemonMcpPolicyRequestSurface:
    """Daemon HTTP surfaces for MCP policy creation requests.

    VPC044-050: the daemon request page and POST decision endpoint enforce
    origin/CSRF, return honest plan display, handle terminal/expired/declined
    states stably, and never persist credentials.  These tests exercise the
    protocol and daemon surfaces without fake credentials.
    """

    @staticmethod
    def _dashboard_token(auth_token: str) -> str:
        import base64
        import hashlib
        import hmac
        from datetime import datetime, timezone

        from codex_plugin_scanner.guard.local_dashboard_session import (
            LOCAL_DASHBOARD_SESSION_AUDIENCE,
        )

        payload_json = json.dumps(
            {
                "aud": LOCAL_DASHBOARD_SESSION_AUDIENCE,
                "version": "guard-local-daemon-session.v1",
                "expires_at": datetime(2099, 1, 1, tzinfo=timezone.utc).isoformat(),
                "surface": "approval-center",
            },
            separators=(",", ":"),
        )
        payload = base64.urlsafe_b64encode(payload_json.encode("utf-8")).decode("ascii").rstrip("=")
        signature = hmac.new(auth_token.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).digest()
        encoded_signature = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
        return f"gld1.{payload}.{encoded_signature}"

    @staticmethod
    def _dashboard_token_for(store: GuardStore) -> str:
        from codex_plugin_scanner.guard.daemon.manager import load_guard_daemon_auth_token

        auth_token = load_guard_daemon_auth_token(store.guard_home)
        assert auth_token is not None
        return TestDaemonMcpPolicyRequestSurface._dashboard_token(auth_token)

    @staticmethod
    def _request(
        port: int,
        path: str,
        *,
        method: str = "POST",
        payload: dict[str, object] | None = None,
        token: str | None = None,
        origin: str | None = None,
    ) -> Any:
        import urllib.request

        data = json.dumps(payload or {}).encode("utf-8") if method != "GET" else None
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if origin is not None:
            headers["Origin"] = origin
        if token is not None:
            if token.startswith("gld1."):
                headers["X-Guard-Dashboard-Session"] = token
            else:
                headers["Authorization"] = f"Bearer {token}"
        return urllib.request.Request(
            f"http://127.0.0.1:{port}{path}",
            data=data,
            headers=headers,
            method=method,
        )

    @staticmethod
    def _read_response(request: Any) -> tuple[int, dict[str, object]]:
        import urllib.error
        import urllib.request

        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read().decode("utf-8"))

    @staticmethod
    def _stage_pending_request(store: GuardStore, *, idempotency_key: str = "daemon-surface-fixture") -> str:
        candidate_digest = _digest(_BASIC_POLICY_YAML)
        result = json.loads(
            execute_create_policy(
                store,
                {
                    "policyYaml": _BASIC_POLICY_YAML,
                    "mode": "merge",
                    "candidateDigest": candidate_digest,
                    "expectedCurrentDigest": None,
                    "idempotencyKey": idempotency_key,
                },
            )
        )
        assert result["status"] == "pending"
        return str(result["requestId"])

    def test_get_returns_vpc045_fields(self, store: GuardStore, env_flags: None, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.daemon import GuardDaemonServer

        request_id = self._stage_pending_request(store)
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()
        try:
            token = self._dashboard_token_for(store)
            status, payload = self._read_response(
                self._request(
                    daemon.port,
                    f"/v1/mcp-policy/requests/{request_id}",
                    method="GET",
                    token=token,
                )
            )
        finally:
            daemon.stop()

        assert status == 200
        assert payload["requestId"] == request_id
        assert payload["status"] == "pending"
        assert payload["mode"] == "merge"
        assert "candidateDigest" in payload
        assert "expectedCurrentDigest" in payload
        assert "expectedPolicyGeneration" in payload
        assert "createdAt" in payload
        assert "expiresAt" in payload
        assert payload["isTerminal"] is False
        assert payload["isExpired"] is False
        assert payload["activeEnforcementWarning"] is True
        assert "semanticDiff" in payload
        assert "writePlan" in payload
        diff = payload["semanticDiff"]
        assert "additionCount" in diff
        assert "replacementCount" in diff
        assert "removalCount" in diff

    def test_get_returns_404_for_unknown_request(self, store: GuardStore, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.daemon import GuardDaemonServer

        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()
        try:
            token = self._dashboard_token_for(store)
            status, payload = self._read_response(
                self._request(
                    daemon.port,
                    "/v1/mcp-policy/requests/nonexistent-request-id",
                    method="GET",
                    token=token,
                )
            )
        finally:
            daemon.stop()

        assert status == 404
        assert payload["error"] == "not_found"

    def test_get_requires_auth_token(self, store: GuardStore, env_flags: None, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.daemon import GuardDaemonServer

        self._stage_pending_request(store)
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()
        try:
            status, _payload = self._read_response(
                self._request(
                    daemon.port,
                    "/v1/mcp-policy/requests/some-id",
                    method="GET",
                    token=None,
                )
            )
        finally:
            daemon.stop()

        assert status == 401

    def test_decision_post_rejects_non_loopback_origin(
        self, store: GuardStore, env_flags: None, tmp_path: Path
    ) -> None:
        from codex_plugin_scanner.guard.daemon import GuardDaemonServer

        request_id = self._stage_pending_request(store)
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()
        try:
            token = self._dashboard_token_for(store)
            status, payload = self._read_response(
                self._request(
                    daemon.port,
                    f"/v1/mcp-policy/requests/{request_id}/decision",
                    method="POST",
                    payload={"action": "decline"},
                    token=token,
                    origin="https://evil.example",
                )
            )
        finally:
            daemon.stop()

        assert status == 403
        assert payload["error"] == "forbidden_origin"

    def test_decision_post_rejects_missing_token(
        self, store: GuardStore, env_flags: None, tmp_path: Path
    ) -> None:
        from codex_plugin_scanner.guard.daemon import GuardDaemonServer

        request_id = self._stage_pending_request(store)
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()
        try:
            status, _payload = self._read_response(
                self._request(
                    daemon.port,
                    f"/v1/mcp-policy/requests/{request_id}/decision",
                    method="POST",
                    payload={"action": "decline"},
                    token=None,
                    origin="http://127.0.0.1:5474",
                )
            )
        finally:
            daemon.stop()

        assert status == 401

    def test_decision_post_rejects_invalid_action(
        self, store: GuardStore, env_flags: None, tmp_path: Path
    ) -> None:
        from codex_plugin_scanner.guard.daemon import GuardDaemonServer

        request_id = self._stage_pending_request(store)
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()
        try:
            token = self._dashboard_token_for(store)
            status, payload = self._read_response(
                self._request(
                    daemon.port,
                    f"/v1/mcp-policy/requests/{request_id}/decision",
                    method="POST",
                    payload={"action": "maybe"},
                    token=token,
                    origin="http://127.0.0.1:5474",
                )
            )
        finally:
            daemon.stop()

        assert status == 400
        assert payload["error"] == "missing_required_fields"

    def test_decline_is_stable_for_already_declined_request(
        self, store: GuardStore, env_flags: None, tmp_path: Path
    ) -> None:
        """VPC047: re-declining a terminal request returns the honest state, not 400."""
        from codex_plugin_scanner.guard.daemon import GuardDaemonServer

        request_id = self._stage_pending_request(store)
        decline_pending_policy_request(store, request_id)

        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()
        try:
            token = self._dashboard_token_for(store)
            status, payload = self._read_response(
                self._request(
                    daemon.port,
                    f"/v1/mcp-policy/requests/{request_id}/decision",
                    method="POST",
                    payload={"action": "decline"},
                    token=token,
                    origin="http://127.0.0.1:5474",
                )
            )
        finally:
            daemon.stop()

        assert status == 200
        assert payload["resolved"] is True
        assert payload["status"] == "declined"
        assert "resolvedAt" in payload

    def test_decline_then_get_shows_terminal_state(
        self, store: GuardStore, env_flags: None, tmp_path: Path
    ) -> None:
        from codex_plugin_scanner.guard.daemon import GuardDaemonServer

        request_id = self._stage_pending_request(store)

        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()
        try:
            token = self._dashboard_token_for(store)
            self._read_response(
                self._request(
                    daemon.port,
                    f"/v1/mcp-policy/requests/{request_id}/decision",
                    method="POST",
                    payload={"action": "decline"},
                    token=token,
                    origin="http://127.0.0.1:5474",
                )
            )
            status, payload = self._read_response(
                self._request(
                    daemon.port,
                    f"/v1/mcp-policy/requests/{request_id}",
                    method="GET",
                    token=token,
                )
            )
        finally:
            daemon.stop()

        assert status == 200
        assert payload["status"] == "declined"
        assert payload["isTerminal"] is True
        assert payload["isExpired"] is False
        assert payload["activeEnforcementWarning"] is False
        assert payload["resolvedAt"] is not None

    def test_decision_response_contains_no_credentials(
        self, store: GuardStore, env_flags: None, tmp_path: Path
    ) -> None:
        """VPC046: the decision endpoint never echoes approval-gate material."""
        from codex_plugin_scanner.guard.daemon import GuardDaemonServer

        request_id = self._stage_pending_request(store)
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()
        try:
            token = self._dashboard_token_for(store)
            status, payload = self._read_response(
                self._request(
                    daemon.port,
                    f"/v1/mcp-policy/requests/{request_id}/decision",
                    method="POST",
                    payload={"action": "decline"},
                    token=token,
                    origin="http://127.0.0.1:5474",
                )
            )
        finally:
            daemon.stop()

        assert status == 200
        serialized = json.dumps(payload, sort_keys=True)
        for forbidden_key in ("password", "totp", "secret", "token", "credential", "passphrase"):
            assert forbidden_key not in serialized.lower(), (
                f"Decision response leaked credential-like key: {forbidden_key}"
            )

    def test_get_response_contains_no_policy_yaml_or_credentials(
        self, store: GuardStore, env_flags: None, tmp_path: Path
    ) -> None:
        """VPC045/046: GET never returns canonical YAML, plan JSON, or credentials."""
        from codex_plugin_scanner.guard.daemon import GuardDaemonServer

        request_id = self._stage_pending_request(store)
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()
        try:
            token = self._dashboard_token_for(store)
            status, payload = self._read_response(
                self._request(
                    daemon.port,
                    f"/v1/mcp-policy/requests/{request_id}",
                    method="GET",
                    token=token,
                )
            )
        finally:
            daemon.stop()

        assert status == 200
        serialized = json.dumps(payload, sort_keys=True)
        assert "apiVersion:" not in serialized
        assert "canonicalPolicyYaml" not in payload
        assert "canonical_policy_yaml" not in payload
        for forbidden_key in ("password", "totp", "secret", "credential", "passphrase"):
            assert forbidden_key not in serialized.lower(), (
                f"GET response leaked credential-like key: {forbidden_key}"
            )
