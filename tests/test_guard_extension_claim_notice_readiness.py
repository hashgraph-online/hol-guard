"""Readiness reporting and the portal gate in front of posting."""

from __future__ import annotations

from typing import Any

import pytest

from tests.extension_claim_notice_harness import (
    MERGE_SHA,
    MODULE,
    FakeGitHub,
    configure_new_contribution,
    configure_unmapped_contribution,
)


def test_readiness_report_types_not_merged_and_no_mapping() -> None:
    client = FakeGitHub()
    client.merged = False
    report = MODULE.readiness_report(client, 31)
    assert report["prStatus"] == "not_merged"
    assert report["entries"] == []

    client.merged = True
    client.files = [{"status": "added", "filename": "contributions/extensions/command.unmapped.json"}]
    client.file_payloads[(MERGE_SHA, "contributions/extensions/command.unmapped.json")] = {"schemaVersion": "v1"}
    report = MODULE.readiness_report(client, 31)
    assert report["prStatus"] == "no_mapping"
    assert report["entries"] == [{"extensionId": "command.unmapped", "status": "no_mapping", "notifiedIds": []}]


def test_readiness_report_types_empty_mapping_as_no_mapping() -> None:
    client = FakeGitHub()
    configure_new_contribution(client, "command.empty-authority", [])
    report = MODULE.readiness_report(client, 32)
    assert report["entries"] == [{"extensionId": "command.empty-authority", "status": "no_mapping", "notifiedIds": []}]


def test_readiness_report_maps_github_api_errors_to_provider_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    client = FakeGitHub()

    def api_failure(number: int) -> list[dict[str, Any]]:
        raise MODULE.ClaimNoticeError("GitHub API request failed")

    monkeypatch.setattr(client, "comments", api_failure)
    report = MODULE.readiness_report(client, 38)

    assert report["prStatus"] == "provider_unavailable"
    assert report["detail"] == "GitHub API request failed"
    assert report["entries"] == []


def test_readiness_report_reraises_non_api_claim_notice_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    client = FakeGitHub()

    def invalid_provenance(number: int) -> list[dict[str, Any]]:
        raise MODULE.ClaimNoticeError("invalid comment provenance")

    monkeypatch.setattr(client, "comments", invalid_provenance)
    with pytest.raises(MODULE.ClaimNoticeError, match="invalid comment provenance"):
        MODULE.readiness_report(client, 39)


def test_readiness_report_uses_first_entry_for_mixed_noneligible_statuses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = FakeGitHub()

    def mixed_statuses(
        _client: Any,
        _pr_number: int,
        *,
        allow_renames: bool = False,
        records: list[Any] | None = None,
    ) -> tuple[list[Any], str, bool]:
        assert records is not None
        records.extend(
            [
                MODULE.ExtensionReadiness("command.source-not-current", "source_not_current"),
                MODULE.ExtensionReadiness("command.no-mapping", "no_mapping"),
            ]
        )
        return [], "source_not_current", False

    monkeypatch.setattr(MODULE, "_plan_notice_items", mixed_statuses)
    report = MODULE.readiness_report(client, 40)

    assert [entry["status"] for entry in report["entries"]] == ["source_not_current", "no_mapping"]
    assert report["prStatus"] == "source_not_current"


def test_readiness_report_reports_eligible_entry_and_portal_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    client = FakeGitHub()
    configure_new_contribution(client, "command.ready", ["600"])
    client.logins = {"600": "ready-maintainer"}

    # Portal endpoint unconfigured: neither the entry nor the PR may claim ready.
    report = MODULE.readiness_report(client, 33)
    assert report["portalStatus"] == "not_configured"
    assert report["entries"][0]["status"] == "portal_not_ready"
    assert report["prStatus"] == "portal_not_ready"

    def ok(url: str) -> tuple[str, str]:
        return "ok", "portal reports ready"

    monkeypatch.setattr(MODULE, "portal_readiness", ok)
    report = MODULE.readiness_report(client, 33, portal_readiness_url="https://portal.example/ready")
    assert report["portalStatus"] == "ok"
    assert report["prStatus"] == "eligible_for_notice"
    assert report["entries"][0]["status"] == "eligible_for_notice"
    assert report["entries"][0]["notifiedIds"] == ["600"]


def test_readiness_report_fails_closed_when_portal_is_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    client = FakeGitHub()
    configure_new_contribution(client, "command.portal-down", ["700"])

    def unreachable(url: str) -> tuple[str, str]:
        return "provider_unavailable", "portal unreachable: connection refused"

    monkeypatch.setattr(MODULE, "portal_readiness", unreachable)
    report = MODULE.readiness_report(client, 34, portal_readiness_url="https://portal.example/ready")
    assert report["prStatus"] == "provider_unavailable"
    assert report["entries"][0]["status"] == "provider_unavailable"

    def lagging(url: str) -> tuple[str, str]:
        return "portal_not_ready", "portal did not affirm readiness"

    monkeypatch.setattr(MODULE, "portal_readiness", lagging)
    report = MODULE.readiness_report(client, 34, portal_readiness_url="https://portal.example/ready")
    assert report["prStatus"] == "portal_not_ready"
    assert report["entries"][0]["status"] == "portal_not_ready"


def test_process_never_posts_when_configured_portal_is_not_ready(monkeypatch: pytest.MonkeyPatch) -> None:
    client = FakeGitHub()
    configure_new_contribution(client, "command.gated", ["800"])
    client.logins = {"800": "gated-maintainer"}

    def not_ready(url: str) -> tuple[str, str]:
        return "portal_not_ready", "projection is stale"

    monkeypatch.setattr(MODULE, "portal_readiness", not_ready)
    assert (
        MODULE.process(
            client,
            35,
            MODULE.DEFAULT_STUDIO_URL,
            portal_readiness_url="https://portal.example/ready",
        )
        == 0
    )
    assert client.posted == []


def test_portal_outage_does_not_suppress_mapping_guidance(monkeypatch: pytest.MonkeyPatch) -> None:
    client = FakeGitHub()
    configure_unmapped_contribution(client, "command.unmapped")
    monkeypatch.setattr(MODULE, "portal_readiness", lambda _url: ("portal_not_ready", "projection is stale"))

    assert (
        MODULE.process(client, 7, MODULE.DEFAULT_STUDIO_URL, portal_readiness_url="https://portal.example/ready") == 0
    )
    assert len(client.posted) == 1
    assert MODULE.GUIDANCE_MARKER in client.posted[0][1]
    assert MODULE.MARKER not in client.posted[0][1]


def test_account_lookup_failure_does_not_suppress_mapping_guidance(monkeypatch: pytest.MonkeyPatch) -> None:
    client = FakeGitHub()
    configure_new_contribution(client, "command.mapped", ["800"])
    unmapped_path = "contributions/extensions/command.unmapped.json"
    client.files.append({"status": "added", "filename": unmapped_path})
    client.file_payloads[(MERGE_SHA, unmapped_path)] = {"schemaVersion": "v1"}
    client.file_payloads[(client.default_branch, unmapped_path)] = {"schemaVersion": "v1"}

    def lookup_failure(_account_id: str) -> str | None:
        raise MODULE.ClaimNoticeError("GitHub API request failed")

    monkeypatch.setattr(client, "user_login", lookup_failure)
    with pytest.raises(MODULE.ClaimNoticeError, match="GitHub API request failed"):
        MODULE.process(client, 7, MODULE.DEFAULT_STUDIO_URL)
    assert len(client.posted) == 1
    assert MODULE.GUIDANCE_MARKER in client.posted[0][1]
    assert MODULE.MARKER not in client.posted[0][1]


def test_trusted_marker_marks_readiness_already_notified() -> None:
    client = FakeGitHub()
    configure_new_contribution(client, "command.duplicate", ["900"])
    client.logins = {"900": "dup-maintainer"}
    client.comment_rows = [
        {
            "body": f"{MODULE.MARKER}\nEarlier notice",
            "user": {"id": MODULE.TRUSTED_NOTICE_ACTOR_ID, "type": "Bot"},
        }
    ]

    report = MODULE.readiness_report(client, 36)
    assert report["prStatus"] == "already_notified"
    assert report["entries"][0]["status"] == "already_notified"
    assert MODULE.process(client, 36, MODULE.DEFAULT_STUDIO_URL) == 0
    assert client.posted == []


def test_report_only_mode_prints_readiness_json_without_posting(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    client = FakeGitHub()
    configure_new_contribution(client, "command.report-only", ["950"])

    def ok(url: str) -> tuple[str, str]:
        return "ok", "portal reports ready"

    monkeypatch.setattr(MODULE, "portal_readiness", ok)
    assert (
        MODULE.process(
            client,
            37,
            MODULE.DEFAULT_STUDIO_URL,
            report_only=True,
            portal_readiness_url="https://portal.example/ready",
        )
        == 0
    )
    assert client.posted == []
    import json as jsonlib

    payload = jsonlib.loads(capsys.readouterr().out)
    assert payload["schemaVersion"] == "guard.extension-claim-notice-readiness.v1"
    assert payload["entries"][0]["status"] == "eligible_for_notice"


def test_portal_readiness_maps_transport_failures_without_claiming_ready(monkeypatch: pytest.MonkeyPatch) -> None:
    import urllib.error

    class Response:
        def __init__(self, payload: bytes, status: int = 200) -> None:
            self._payload = payload
            self.status = status

        def read(self, limit: int) -> bytes:
            return self._payload

        def __enter__(self) -> Response:
            return self

        def __exit__(self, *args: object) -> None:
            return None

    def ok(req: object, timeout: float) -> Response:
        return Response(b'{"ok": true}')

    monkeypatch.setattr(MODULE.urllib.request, "urlopen", ok)
    assert MODULE.portal_readiness("https://portal.example/ready") == ("ok", "portal reports ready")

    def ready_only_flag(req: object, timeout: float) -> Response:
        return Response(b'{"ready": true, "entries": 69}')

    monkeypatch.setattr(MODULE.urllib.request, "urlopen", ready_only_flag)
    assert MODULE.portal_readiness("https://portal.example/ready")[0] == "portal_not_ready"

    def not_affirming(req: object, timeout: float) -> Response:
        return Response(b'{"ok": false}')

    monkeypatch.setattr(MODULE.urllib.request, "urlopen", not_affirming)
    assert MODULE.portal_readiness("https://portal.example/ready")[0] == "portal_not_ready"

    def non_200(req: object, timeout: float) -> Response:
        return Response(b'{"ok": true}', status=202)

    monkeypatch.setattr(MODULE.urllib.request, "urlopen", non_200)
    assert MODULE.portal_readiness("https://portal.example/ready") == (
        "portal_not_ready",
        "portal returned HTTP 202",
    )

    def http_error(req: object, timeout: float) -> Response:
        raise urllib.error.HTTPError(req.url if hasattr(req, "url") else "x", 503, "unavailable", None, None)  # type: ignore[arg-type]

    monkeypatch.setattr(MODULE.urllib.request, "urlopen", http_error)
    assert MODULE.portal_readiness("https://portal.example/ready")[0] == "provider_unavailable"

    def http_not_found(req: object, timeout: float) -> Response:
        raise urllib.error.HTTPError(req.url if hasattr(req, "url") else "x", 404, "not found", None, None)  # type: ignore[arg-type]

    monkeypatch.setattr(MODULE.urllib.request, "urlopen", http_not_found)
    assert MODULE.portal_readiness("https://portal.example/ready") == (
        "portal_not_ready",
        "portal returned HTTP 404",
    )

    def os_error(req: object, timeout: float) -> Response:
        raise OSError("connection refused")

    monkeypatch.setattr(MODULE.urllib.request, "urlopen", os_error)
    assert MODULE.portal_readiness("https://portal.example/ready")[0] == "provider_unavailable"

    def not_json(req: object, timeout: float) -> Response:
        return Response(b"<html>maintenance</html>")

    monkeypatch.setattr(MODULE.urllib.request, "urlopen", not_json)
    assert MODULE.portal_readiness("https://portal.example/ready")[0] == "portal_not_ready"


def test_readyness_reasons_constant_covers_the_reviewed_vocabulary() -> None:
    assert (
        frozenset(
            {
                "no_mapping",
                "not_merged",
                "source_not_current",
                "portal_not_ready",
                "already_notified",
                "eligible_for_notice",
                "provider_unavailable",
            }
        )
        == MODULE.READYNESS_REASONS
    )
