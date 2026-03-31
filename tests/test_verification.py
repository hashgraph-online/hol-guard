"""Tests for runtime verification engine."""

from pathlib import Path

from codex_plugin_scanner.verification import build_doctor_report, verify_plugin

FIXTURES = Path(__file__).parent / "fixtures"


def test_verify_plugin_passes_for_good_fixture():
    result = verify_plugin(FIXTURES / "good-plugin")
    assert result.verify_pass is True


def test_verify_plugin_fails_for_insecure_remote(tmp_path: Path):
    (tmp_path / ".mcp.json").write_text('{"remotes":[{"url":"http://example.com"}]}', encoding="utf-8")
    result = verify_plugin(tmp_path)
    assert result.verify_pass is False


def test_doctor_report_filters_component():
    report = build_doctor_report(FIXTURES / "good-plugin", "manifest")
    assert report["component"] == "manifest"
    assert isinstance(report["cases"], list)
