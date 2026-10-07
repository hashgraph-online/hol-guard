"""Framework-independent MCP policy authoring, decision, schema, and status tests."""

from __future__ import annotations

import json

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
from tests.guard_mcp_policy_test_support import (
    _BASIC_POLICY_YAML,
    _BASIC_POLICY_YAML_2,
    _digest,
    _import_policy,
)
from tests.guard_mcp_policy_test_support import env_flags as env_flags
from tests.guard_mcp_policy_test_support import store as store


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

    def test_apply_rejects_current_digest_mismatch(self, store: GuardStore, env_flags: None) -> None:
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
            StageRequestInput(
                policy_document_id=document.metadata.id,
                policy_document_digest=digest,
                expected_current_digest=None,
                expected_policy_generation=None,
                mode="merge",
                canonical_policy_yaml=canonical_yaml,
                plan_json='{"additions":[],"replacements":[],"removals":[]}',
                idempotency_key="policy-request-fixture",
            )
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
            StageRequestInput(
                policy_document_id=document.metadata.id,
                policy_document_digest=digest,
                expected_current_digest=None,
                expected_policy_generation=None,
                mode="merge",
                canonical_policy_yaml=canonical_yaml,
                plan_json='{"additions":[],"replacements":[],"removals":[]}',
                idempotency_key="policy-request-fixture",
            )
        )
        pending = repo.list_pending_requests()
        assert len(pending) == 1

    def test_idempotency_conflict_on_different_yaml(self, store: GuardStore) -> None:
        repo = MCPolicyRequestRepository(store)
        document = parse_policy_document_yaml(_BASIC_POLICY_YAML)
        digest = policy_document_digest(document)
        canonical_yaml = format_policy_document_yaml(document)

        repo.stage_request(
            StageRequestInput(
                policy_document_id=document.metadata.id,
                policy_document_digest=digest,
                expected_current_digest=None,
                expected_policy_generation=None,
                mode="merge",
                canonical_policy_yaml=canonical_yaml,
                plan_json="{}",
                idempotency_key="shared-fixture-request",
            )
        )
        document2 = parse_policy_document_yaml(_BASIC_POLICY_YAML_2)
        digest2 = policy_document_digest(document2)
        canonical_yaml2 = format_policy_document_yaml(document2)
        with pytest.raises(PolicyToolError) as exc:
            repo.stage_request(
                StageRequestInput(
                    policy_document_id=document2.metadata.id,
                    policy_document_digest=digest2,
                    expected_current_digest=None,
                    expected_policy_generation=None,
                    mode="merge",
                    canonical_policy_yaml=canonical_yaml2,
                    plan_json="{}",
                    idempotency_key="shared-fixture-request",
                )
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

    def test_status_reflects_enabled_flags(self, store: GuardStore, monkeypatch: pytest.MonkeyPatch) -> None:
        from codex_plugin_scanner.guard.mcp.tools import execute_get_guard_status

        monkeypatch.setenv("HOL_GUARD_POLICY_YAML_IMPORT", "1")
        monkeypatch.setenv("HOL_GUARD_MCP_POLICY_WRITE", "1")
        result = json.loads(execute_get_guard_status(store))
        assert result["policyAuthoringAvailable"] is True
        assert result["policyWriteEnabled"] is True

    def test_status_reflects_disabled_flags(self, store: GuardStore, monkeypatch: pytest.MonkeyPatch) -> None:
        from codex_plugin_scanner.guard.mcp.tools import execute_get_guard_status

        monkeypatch.delenv("HOL_GUARD_POLICY_YAML_IMPORT", raising=False)
        monkeypatch.delenv("HOL_GUARD_MCP_POLICY_WRITE", raising=False)
        result = json.loads(execute_get_guard_status(store))
        assert result["policyAuthoringAvailable"] is False
        assert result["policyWriteEnabled"] is False
