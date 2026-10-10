"""Presentation/HTTP boundary tests; these do not qualify a provider journey."""

import json
import urllib.error
import urllib.request
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.daemon import business_review_summary as route
from codex_plugin_scanner.guard.runtime import native_business_review_summary as adapter
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_daemon_transport_security import _dashboard_token


def summary():
    return {
        "schema": "guard-native-local-business-review-summary.v1",
        "version": 1,
        "request_id": "business-test",
        "request_snapshot_digest": "a" * 64,
        "prepared_input_binding": "b" * 64,
        "service": "google_gmail",
        "operation": "mail_send",
        "audience_kind": "named",
        "audience_expansion_state": "known",
        "recipient_count": 3,
        "record_count": 1,
        "byte_count": 24,
        "attachment_count": 0,
        "inspection_state": "known",
        "sensitivity_labels": ["confidential"],
        "snapshot_fact_completeness": "known",
        "account_currentness": "not_asserted",
        "execution_state": "not_checked",
    }


def test_summary_sql_collision_is_absent_without_contacting_native(tmp_path, monkeypatch):
    store = GuardStore(tmp_path / "guard-home")
    monkeypatch.setattr(store, "get_approval_request", lambda request_id: {"request_id": request_id})
    monkeypatch.setattr(
        route,
        "read_native_business_review_summary",
        lambda *args: pytest.fail("SQL review must not read another native snapshot"),
    )
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        request = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}/v1/requests/business-test/business-summary",
            headers={"X-Guard-Dashboard-Session": _dashboard_token(store)},
        )
        with pytest.raises(urllib.error.HTTPError) as rejected:
            urllib.request.urlopen(request, timeout=5)
        assert rejected.value.code == 404
        assert rejected.value.headers["Cache-Control"] == "no-store"
        assert json.loads(rejected.value.read()) == {"error": "native_local_business_summary_unavailable"}
    finally:
        daemon.stop()


@pytest.mark.parametrize(
    "code",
    [
        "native_local_business_summary_unavailable",
        "native_workspace_review_request_missing",
        "native_policy_snapshot_missing",
        "native_policy_snapshot_unavailable",
    ],
)
def test_real_native_absence_error_envelope_is_optional(tmp_path, monkeypatch, code):
    monkeypatch.setattr(
        adapter,
        "native_runtime_status",
        lambda: SimpleNamespace(
            available=True,
            compatible=True,
            identity=SimpleNamespace(path=Path("/test/native")),
            capabilities=SimpleNamespace(features=("resident-protocol-v2", "native-local-business-review-summary-v1")),
        ),
    )
    monkeypatch.setattr(adapter, "_isolated_environment", lambda: {})
    monkeypatch.setattr(
        adapter,
        "native_resident_client_request",
        lambda **kwargs: json.dumps({"error": code, "retryable": False}).encode(),
    )
    assert adapter.read_native_business_review_summary(tmp_path, "business-test") is None


@pytest.mark.parametrize(
    "change",
    [
        {"subject": "private-canary"},
        {"request_id": "different"},
        {"version": True},
        {"account_currentness": "verified"},
        {"execution_state": "sent"},
        {"request_snapshot_digest": "g" * 64},
        {"prepared_input_binding": None},
        {"recipient_count": True},
        {"byte_count": 1 << 53},
        {"record_count": -1},
        {"attachment_count": 0.5},
        {"service": "google_drive"},
        {"service": []},
        {"operation": {}},
        {"audience_kind": []},
        {"inspection_state": "allowed"},
        {"sensitivity_labels": ["confidential", "confidential"]},
        {"sensitivity_labels": [[]]},
        {"snapshot_fact_completeness": "allowed"},
        {"audience_expansion_state": None},
    ],
)
def test_presentation_rejects_private_fields_and_invalid_claims(change):
    value = summary()
    value.update(change)
    assert adapter.valid_business_review_summary(value, "business-test") is None


def test_transport_sends_only_request_id_and_does_not_stage(tmp_path, monkeypatch):
    monkeypatch.setattr(
        adapter,
        "native_runtime_status",
        lambda: SimpleNamespace(
            available=True,
            compatible=True,
            identity=SimpleNamespace(path=Path("/test/native")),
            capabilities=SimpleNamespace(features=("resident-protocol-v2", "native-local-business-review-summary-v1")),
        ),
    )
    monkeypatch.setattr(adapter, "_isolated_environment", lambda: {})
    calls = []

    def request(**kwargs):
        calls.append(kwargs)
        return json.dumps(summary()).encode()

    monkeypatch.setattr(adapter, "native_resident_client_request", request)
    assert adapter.read_native_business_review_summary(tmp_path, "business-test") == summary()
    assert json.loads(calls[0]["payload"]) == {
        "operation": "workspace_review_local_summary",
        "request": {"request_id": "business-test"},
    }
    assert calls[0]["timeout_seconds"] == 2.0
    assert list(tmp_path.iterdir()) == []
    assert adapter.read_native_business_review_summary(tmp_path, "../business-test") is None
    assert len(calls) == 1


def test_missing_capability_never_contacts_resident(tmp_path, monkeypatch):
    monkeypatch.setattr(
        adapter,
        "native_runtime_status",
        lambda: SimpleNamespace(
            available=True,
            compatible=True,
            identity=SimpleNamespace(path=Path("/test/native")),
            capabilities=SimpleNamespace(features=("resident-protocol-v2",)),
        ),
    )
    monkeypatch.setattr(
        adapter, "native_resident_client_request", lambda **kwargs: pytest.fail("unexpected resident request")
    )
    assert adapter.read_native_business_review_summary(tmp_path, "business-test") is None


@pytest.mark.parametrize("encoded", [None, b"not-json", b"{}", b'{"error":"native_workspace_review_request_invalid"}'])
def test_transport_or_schema_failure_is_not_genuine_absence(tmp_path, monkeypatch, encoded):
    monkeypatch.setattr(
        adapter,
        "native_runtime_status",
        lambda: SimpleNamespace(
            available=True,
            compatible=True,
            identity=SimpleNamespace(path=Path("/test/native")),
            capabilities=SimpleNamespace(features=("resident-protocol-v2", "native-local-business-review-summary-v1")),
        ),
    )
    monkeypatch.setattr(adapter, "_isolated_environment", lambda: {})
    monkeypatch.setattr(adapter, "native_resident_client_request", lambda **kwargs: encoded)
    with pytest.raises(RuntimeError, match="native_local_business_summary_read_failed"):
        adapter.read_native_business_review_summary(tmp_path, "business-test")


@pytest.mark.parametrize("available", [True, False, "failure"])
def test_http_requires_dashboard_session_and_disables_caching(tmp_path, monkeypatch, available):
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    calls = []

    def read(guard_home, request_id):
        calls.append((guard_home, request_id))
        if available == "failure":
            raise adapter.NativeBusinessReviewSummaryReadError()
        return summary() if available else None

    monkeypatch.setattr(route, "read_native_business_review_summary", read)
    daemon.start()
    try:
        url = f"http://127.0.0.1:{daemon.port}/v1/requests/business-test/business-summary"
        with pytest.raises(urllib.error.HTTPError) as unauthorized:
            urllib.request.urlopen(url, timeout=5)
        assert unauthorized.value.code == 401
        assert calls == []
        foreign_request = urllib.request.Request(
            url,
            headers={
                "Origin": "https://example.invalid",
                "X-Guard-Dashboard-Session": _dashboard_token(store),
            },
        )
        with pytest.raises(urllib.error.HTTPError) as foreign:
            urllib.request.urlopen(foreign_request, timeout=5)
        assert foreign.value.code == 403
        assert calls == []
        request = urllib.request.Request(url, headers={"X-Guard-Dashboard-Session": _dashboard_token(store)})
        try:
            response = urllib.request.urlopen(request, timeout=5)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            expected_status = 503 if available == "failure" else (200 if available else 404)
            expected_body = (
                {"error": "native_local_business_summary_read_failed"}
                if available == "failure"
                else (summary() if available else {"error": "native_local_business_summary_unavailable"})
            )
            assert response.status == expected_status
            assert response.headers["Cache-Control"] == "no-store"
            assert json.loads(response.read()) == expected_body
        assert calls == [(store.guard_home, "business-test")]
    finally:
        daemon.stop()
