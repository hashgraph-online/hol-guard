from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli import commands_dispatch_risk_report
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.store import GuardStore


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


def _report(monkeypatch: pytest.MonkeyPatch, report_format: str, output: str | None = None) -> tuple[int, str]:
    monkeypatch.setattr(commands_dispatch_risk_report, "build_guard_status_payload", lambda *_: _status_payload())
    stream = io.StringIO()
    code = commands_dispatch_risk_report.run_guard_risk_report_command(
        argparse.Namespace(format=report_format, output=output),
        context=cast(HarnessContext, object()),
        store=cast(GuardStore, object()),
        config=cast(GuardConfig, object()),
        output_stream=stream,
    )
    return code, stream.getvalue()


def test_only_coarse_status_fields_reach_the_runtime() -> None:
    status = commands_dispatch_risk_report._report_status(_status_payload())  # pyright: ignore[reportPrivateUsage]
    assert status == {
        "generated_at": "2026-08-09T20:00:00Z",
        "runtime_status": "active",
        "managed_harnesses": 1,
        "pending_approvals": 0,
        "receipt_count": 7,
        "sync_configured": False,
        "harnesses": [{"harness": "codex", "installed": True, "review_count": 0}],
    }


def test_json_report_is_coarse_and_verifiable(monkeypatch: pytest.MonkeyPatch) -> None:
    code, body = _report(monkeypatch, "json")
    assert code == 0
    report = json.loads(body)
    assert report["risk_band"] == "low"
    assert report["installed_harnesses"] == ["codex"]
    assert report["sensitive_content_included"] is False
    digest = report.pop("integrity_sha256")
    canonical = json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
    assert digest == hashlib.sha256(canonical).hexdigest()
    for leaked in ("alice", "SECRET_TOKEN", "private-project", "config.toml", "shim"):
        assert leaked not in body


def test_html_report_is_written_noindex(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    destination = tmp_path / "out" / "guard-report.html"
    code, message = _report(monkeypatch, "html", str(destination))
    assert code == 0
    assert str(destination) in message
    rendered = destination.read_text(encoding="utf-8")
    assert '<meta name="robots" content="noindex,nofollow">' in rendered
    assert "Sensitive local content included: no." in rendered
    assert "alice" not in rendered


def test_unavailable_runtime_builds_no_report(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(commands_dispatch_risk_report, "runtime_answer", lambda *_, **__: None)
    code, body = _report(monkeypatch, "json")
    assert code == 1
    assert body == ""
    assert "native runtime is unavailable" in capsys.readouterr().err
