"""Guard evidence API contract tests."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path

from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_evidence import EvidenceRecord, store_evidence


def _record(evidence_id: str, **overrides: object) -> EvidenceRecord:
    details = overrides.pop("details", {"path": "/workspace/.env"})
    action_identity = overrides.pop("action_identity", "codex:shell:cat-env")
    return EvidenceRecord(
        evidence_id=str(overrides.pop("evidence_id", evidence_id)),
        action_id=str(overrides.pop("action_id", f"action-{evidence_id}")),
        request_id=str(overrides.pop("request_id", f"request-{evidence_id}")),
        harness=str(overrides.pop("harness", "codex")),
        workspace=str(overrides.pop("workspace", "/workspace")),
        signal_id=str(overrides.pop("signal_id", "signal-secret")),
        category=str(overrides.pop("category", "secret")),
        severity=str(overrides.pop("severity", "high")),
        confidence=float(overrides.pop("confidence", 0.92)),
        summary=str(overrides.pop("summary", "Secret read stopped")),
        details=details if isinstance(details, dict) else {},
        action_identity=str(action_identity) if action_identity is not None else None,
        created_at=str(overrides.pop("created_at", "2026-05-12T10:00:00Z")),
    )


def _store_record(store: GuardStore, record: EvidenceRecord) -> None:
    with store._connect() as connection:
        store_evidence(connection, record)


def _get(port: int, path: str) -> tuple[int, dict[str, str], bytes]:
    request = urllib.request.Request(f"http://127.0.0.1:{port}{path}", method="GET")
    with urllib.request.urlopen(request, timeout=5) as response:
        return response.status, dict(response.headers), response.read()


def _get_error(port: int, path: str) -> int:
    try:
        _get(port, path)
    except urllib.error.HTTPError as error:
        return error.code
    raise AssertionError("expected HTTPError")


def test_evidence_list_total_respects_filters(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _store_record(store, _record("codex-high", harness="codex", severity="high", category="secret"))
    _store_record(store, _record("codex-low", harness="codex", severity="low", category="network"))
    _store_record(store, _record("claude-high", harness="claude", severity="high", category="secret"))
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()

    try:
        _status, _headers, body = _get(daemon.port, "/v1/evidence?harness=codex&category=secret&severity=high&limit=1")
    finally:
        daemon.stop()

    payload = json.loads(body.decode("utf-8"))
    assert payload["total"] == 1
    assert [item["evidence_id"] for item in payload["items"]] == ["codex-high"]


def test_evidence_export_json_and_csv_include_warning_and_redaction(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _store_record(
        store,
        _record(
            "export-sensitive",
            workspace="/Users/alice/private/project",
            summary="Read /Users/alice/private/project/.env with token sk-live-secret-value",
            details={"token": "sk-live-secret-value", "path": "/Users/alice/private/project/.env"},
        ),
    )
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()

    try:
        json_status, json_headers, json_body = _get(daemon.port, "/v1/evidence/export?format=json")
        csv_status, csv_headers, csv_body = _get(daemon.port, "/v1/evidence/export?format=csv")
        invalid_status = _get_error(daemon.port, "/v1/evidence/export?format=xml")
    finally:
        daemon.stop()

    json_payload = json.loads(json_body.decode("utf-8"))
    json_encoded = json.dumps(json_payload)
    csv_text = csv_body.decode("utf-8")

    assert json_status == 200
    assert csv_status == 200
    assert invalid_status == 400
    assert json_headers["Content-Type"].startswith("application/json")
    assert csv_headers["Content-Type"].startswith("text/csv")
    assert json_payload["privacy_warning"]
    assert "privacy_warning" in csv_text
    assert "sk-live-secret-value" not in json_encoded
    assert "sk-live-secret-value" not in csv_text
    assert "/Users/alice" not in json_encoded
    assert "/Users/alice" not in csv_text
