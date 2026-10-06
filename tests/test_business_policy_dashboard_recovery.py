"""Authenticated real HTTP/native-factor recovery; no provider work or request replay."""

import pytest

from codex_plugin_scanner.guard import native_business_source_store as owner
from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.mcp.policy_store import MCPolicyRequestRepository
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
from codex_plugin_scanner.guard.policy_document import policy_document_digest
from tests.guard_mcp_policy_test_support import env_flags as env_flags
from tests.guard_mcp_policy_test_support import store as store
from tests.test_business_policy_document_import import _stage
from tests.test_guard_mcp_policy_daemon import TestDaemonMcpPolicyRequestSurface as Surface
from tests.test_native_business_document_compile import document
from tests.test_native_business_source_store import _grant, _install, _key


def test_read_only_inspection_allows_native_publication(store, env_flags, native_mcp_probe, monkeypatch):
    from codex_plugin_scanner.guard.daemon import business_policy_recovery_inspection as inspection
    from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher

    native_mcp_probe(store.guard_home)
    candidate = document()
    staged = _stage(store, candidate, monkeypatch)
    _install(store, candidate, _grant(store, candidate))
    (store.guard_home / "config.toml").write_text('mode = "prompt"\nprotection_posture = "protected"\n')
    request = MCPolicyRequestRepository(store).get_request(staged["requestId"])
    assert request is not None
    publisher = NativePolicySnapshotPublisher(store=store)
    publisher._publish_once()
    assert publisher.is_ready(), publisher.last_error
    verify = inspection.verify_business_source_record
    publications = []

    def publish_during_inspection(*args, **kwargs):
        publisher._publish_once()
        assert publisher.is_ready(), publisher.last_error
        publications.append(publisher.current_snapshot())
        return verify(*args, **kwargs)

    monkeypatch.setattr(inspection, "verify_business_source_record", publish_during_inspection)
    try:
        result = inspection.inspect_business_policy_recovery(store, request, candidate)
        assert result["state"] == "installed"
        assert len(publications) == 1
    finally:
        publisher.close()


@pytest.mark.parametrize("authorized", [False, True])
@pytest.mark.parametrize("expired", [False, True])
def test_dashboard_recovery_requires_fresh_factor_and_preserves_request_status(
    store, env_flags, native_mcp_probe, monkeypatch, authorized, expired
):
    native_mcp_probe(store.guard_home)
    candidate = document()
    staged = _stage(store, candidate, monkeypatch)
    request_id = staged["requestId"]
    with pytest.raises(NativePolicySnapshotError, match="native_business_source_transaction_not_committed"):
        _install(store, candidate, _grant(store, candidate), commit=False)
    if expired:
        MCPolicyRequestRepository(store)._expire_request(request_id)
    witness = owner._database_witness(store)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        status, payload = Surface._read_response(
            Surface._request(
                daemon.port,
                f"/v1/mcp-policy/requests/{request_id}/decision",
                payload={
                    "action": "recover",
                    "candidateDigest": policy_document_digest(candidate),
                    "approval_gate": {
                        "password": "synthetic-source-installation-password" if authorized else "incorrect-password",
                        "use_cooldown": False,
                    },
                },
                token=Surface._dashboard_token_for(store),
                origin="http://127.0.0.1:5474",
            )
        )
    finally:
        daemon.stop()
    assert MCPolicyRequestRepository(store).get_request(request_id).status == ("expired" if expired else "pending")
    assert "synthetic-source-installation-password" not in str(payload)
    if authorized:
        assert status == 200 and payload["installationRecovered"] is True
        assert payload["sourceDigest"] == owner.read_installed_business_source(store, _key(store)).source_digest
        assert "resolved" not in payload and "status" not in payload
    else:
        assert status >= 400 and owner._database_witness(store) == witness
        with pytest.raises(NativePolicySnapshotError):
            owner.read_installed_business_source(store, _key(store))


@pytest.mark.parametrize(
    "rejection", ["declined", "changed-digest", "missing-session", "wrong-origin", "disabled-write"]
)
def test_dashboard_recovery_refuses_unreviewed_or_unauthenticated_candidate(
    store, env_flags, native_mcp_probe, monkeypatch, rejection
):
    native_mcp_probe(store.guard_home)
    candidate = document()
    request_id = _stage(store, candidate, monkeypatch)["requestId"]
    with pytest.raises(NativePolicySnapshotError):
        _install(store, candidate, _grant(store, candidate), commit=False)
    if rejection == "declined":
        MCPolicyRequestRepository(store).decline_request(request_id)
    if rejection == "disabled-write":
        monkeypatch.setenv("HOL_GUARD_MCP_POLICY_WRITE", "0")
    witness = owner._database_witness(store)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        status, payload = Surface._read_response(
            Surface._request(
                daemon.port,
                f"/v1/mcp-policy/requests/{request_id}/decision",
                payload={
                    "action": "recover",
                    "candidateDigest": policy_document_digest(
                        document(2) if rejection == "changed-digest" else candidate
                    ),
                    "approval_password": "synthetic-source-installation-password",
                },
                token=None if rejection == "missing-session" else Surface._dashboard_token_for(store),
                origin="https://untrusted.invalid" if rejection == "wrong-origin" else "http://127.0.0.1:5474",
            )
        )
    finally:
        daemon.stop()
    assert status >= 400 and payload.get("installationRecovered") is not True
    assert owner._database_witness(store) == witness


@pytest.mark.parametrize("expired", [False, True])
def test_inspection_discovers_saved_rules_and_recovered_request_remains_non_replayable(
    store, env_flags, native_mcp_probe, monkeypatch, expired
):
    from codex_plugin_scanner.guard.mcp.policy_apply import apply_pending_policy_request
    from codex_plugin_scanner.guard.mcp.policy_errors import PolicyToolError

    native_mcp_probe(store.guard_home)
    candidate = document()
    request_id = _stage(store, candidate, monkeypatch)["requestId"]
    digest = policy_document_digest(candidate)
    with pytest.raises(NativePolicySnapshotError):
        _install(store, candidate, _grant(store, candidate), commit=False)
    if expired:
        MCPolicyRequestRepository(store)._expire_request(request_id)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:

        def decision(action, **extra):
            return Surface._read_response(
                Surface._request(
                    daemon.port,
                    f"/v1/mcp-policy/requests/{request_id}/decision",
                    payload={"action": action, "candidateDigest": digest, **extra},
                    token=Surface._dashboard_token_for(store),
                    origin="http://127.0.0.1:5474",
                )
            )

        witness = owner._database_witness(store)
        status, preview = decision("inspect-recovery")
        assert status == 200 and preview["state"] == "interrupted"
        assert preview["candidateDigest"] == digest and preview["provenanceRedacted"] is True
        assert preview["requestRecovered"] is False
        expected_rules = candidate.to_mapping()["spec"]["rules"]
        actual_rules = preview["policy"]["spec"]["rules"]
        assert len(actual_rules) == len(expected_rules)
        for actual, expected in zip(actual_rules, expected_rules, strict=True):
            for field in ("id", "enabled", "effect", "match", "lifetime"):
                assert actual[field] == expected[field]
            assert actual["provenance"] == {"source": "local", "createdAt": "1970-01-01T00:00:00Z"}
        assert owner._database_witness(store) == witness
        status, recovered = decision("recover", approval_password="synthetic-source-installation-password")
        assert status == 200 and recovered["installationRecovered"] is True
        status, preview = decision("inspect-recovery")
        assert status == 200 and preview["state"] == "installed" and preview["requestRecovered"] is True
        assert MCPolicyRequestRepository(store).get_request(request_id).status == ("expired" if expired else "pending")
        newer = document(2)
        _install(store, newer, _grant(store, newer, initialize=False))
        status, preview = decision("inspect-recovery")
        assert status == 200 and preview["requestRecovered"] is True
        if not expired:
            with pytest.raises(PolicyToolError, match="already recovered"):
                apply_pending_policy_request(
                    store, request_id, approval_gate_grant=_grant(store, candidate, initialize=False)
                )
        assert owner.read_installed_business_source(store, _key(store)).source_digest == policy_document_digest(newer)
    finally:
        daemon.stop()
