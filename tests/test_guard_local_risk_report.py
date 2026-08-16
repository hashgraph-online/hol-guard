from __future__ import annotations

from dataclasses import replace

from codex_plugin_scanner.guard.local_risk_report import (
    build_local_risk_report,
    local_risk_report_json,
    render_local_risk_report_html,
    verify_local_risk_report,
)


def _status_payload() -> dict[str, object]:
    return {
        "generated_at": "2026-08-09T20:00:00Z",
        "guard_home": "~/.hol-guard",
        "workspace": "~/private-project",
        "runtime_status": "active",
        "managed_harnesses": 1,
        "pending_approvals": 0,
        "receipt_count": 7,
        "sync_configured": False,
        "harnesses": [
            {
                "harness": "codex",
                "installed": True,
                "managed": True,
                "review_count": 0,
                "config_paths": ["~/private-project/.codex/config.toml"],
                "shim_path": "/Users/alice/.hol-guard/shim",
            }
        ],
        "raw_prompt": "read SECRET_TOKEN from /Users/alice/private-project/.env",
        "hostname": "alice-macbook.local",
        "username": "alice",
    }


def test_report_is_coarse_and_integrity_bound() -> None:
    report = build_local_risk_report(_status_payload(), guard_version="3.0.0a1")

    assert report.risk_band == "low"
    assert report.installed_harnesses == ("codex",)
    assert report.sensitive_content_included is False
    assert report.certification is False
    assert verify_local_risk_report(report)
    assert len(report.integrity_sha256) == 64


def test_report_serialization_excludes_sensitive_local_content() -> None:
    report = build_local_risk_report(_status_payload(), guard_version="3.0.0a1")
    serialized = local_risk_report_json(report)

    for forbidden in (
        "SECRET_TOKEN",
        "/Users/alice",
        "private-project",
        ".env",
        "alice-macbook.local",
        '"username"',
        '"raw_prompt"',
        '"config_paths"',
        '"shim_path"',
    ):
        assert forbidden not in serialized


def test_html_is_noindex_and_not_a_certification() -> None:
    report = build_local_risk_report(_status_payload(), guard_version="3.0.0a1")
    rendered = render_local_risk_report_html(report)

    assert 'name="robots" content="noindex,nofollow"' in rendered
    assert "not a certification" in rendered
    assert "Sensitive local content included: no" in rendered
    assert report.integrity_sha256 in rendered


def test_risk_band_marks_offline_runtime_high() -> None:
    payload = _status_payload()
    payload["runtime_status"] = "offline"
    report = build_local_risk_report(payload, guard_version="3.0.0a1")

    assert report.risk_band == "high"
    assert any(check.id == "runtime" and check.status == "fail" for check in report.checks)


def test_digest_verifier_rejects_tampered_sanitized_summary() -> None:
    report = build_local_risk_report(_status_payload(), guard_version="3.0.0a1")
    tampered = replace(report, managed_harness_count=999)

    assert verify_local_risk_report(report)
    assert not verify_local_risk_report(tampered)
