from __future__ import annotations

import json
from datetime import UTC, datetime
from urllib.parse import parse_qs, urlparse

from codex_plugin_scanner.guarded_repository_evidence import (
    build_guarded_repository_evidence,
    guarded_repository_evidence_sha256,
)
from codex_plugin_scanner.guarded_repository_registration import register_guarded_repository_evidence


class _Response:
    def __init__(self, payload: dict[str, object]):
        self._payload = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None

    def read(self) -> bytes:
        return self._payload


def _evidence():
    return build_guarded_repository_evidence(
        repository="hashgraph-online/example",
        commit_sha="a" * 40,
        workflow_run_id="123456",
        scanner_version="3.0.0a1",
        scanner_profile="strict-security",
        score=93,
        grade="A",
        max_severity="medium",
        findings_total=2,
        sarif_sha256="b" * 64,
        visibility="public",
        generated_at=datetime(2026, 8, 9, 20, 0, tzinfo=UTC),
    )


def test_registration_binds_oidc_audience_and_keeps_token_out_of_body(monkeypatch) -> None:
    evidence = _evidence()
    digest = guarded_repository_evidence_sha256(evidence)
    requests = []

    def fake_urlopen(request, timeout):
        requests.append((request, timeout))
        if len(requests) == 1:
            return _Response({"value": "oidc-secret-token"})
        return _Response(
            {
                "status": "verified",
                "verificationUrl": "/guard/security/repository-attestations/example",
                "badgeUrl": "/api/guard/repository-attestations/example/badge.svg",
            }
        )

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    result = register_guarded_repository_evidence(
        evidence=evidence,
        attestation_url="https://github.com/hashgraph-online/example/attestations/123456",
        attestation_id="123456",
        endpoint="https://hol.org/api/guard/repository-attestations",
        oidc_request_url="https://token.actions.githubusercontent.com/request?base=1",
        oidc_request_token="runner-request-token",
    )

    oidc_request, oidc_timeout = requests[0]
    registration_request, registration_timeout = requests[1]
    oidc_query = parse_qs(urlparse(oidc_request.full_url).query)
    registration_body = json.loads(registration_request.data.decode("utf-8"))

    assert oidc_timeout == 10
    assert oidc_query["audience"] == [f"hol-guard-repository:{digest}"]
    assert oidc_request.get_header("Authorization") == "Bearer runner-request-token"
    assert registration_timeout == 15
    assert registration_request.full_url == "https://hol.org/api/guard/repository-attestations"
    assert registration_request.get_header("Authorization") == "Bearer oidc-secret-token"
    assert registration_body["evidenceSha256"] == digest
    assert registration_body["attestationId"] == "123456"
    assert "oidc" not in json.dumps(registration_body).lower()
    assert result["status"] == "verified"
