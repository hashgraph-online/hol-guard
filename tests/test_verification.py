"""Tests for runtime verification engine."""

import json
import socket
import threading
import urllib.parse
from pathlib import Path

import pytest

from codex_plugin_scanner.pinned_https import probe_pinned_https
from codex_plugin_scanner.verification import (
    MAX_VALIDATED_HTTPS_ADDRESSES,
    _check_mcp_http,
    _validate_remote_url,
    build_doctor_report,
    verify_plugin,
)

FIXTURES = Path(__file__).parent / "fixtures"


def test_verify_plugin_passes_for_good_fixture():
    result = verify_plugin(FIXTURES / "good-plugin")
    assert result.verify_pass is True


def test_verify_plugin_fails_for_insecure_remote(tmp_path: Path):
    (tmp_path / ".mcp.json").write_text('{"remotes":[{"url":"http://example.com"}]}', encoding="utf-8")
    result = verify_plugin(tmp_path)
    assert result.verify_pass is False


def test_online_mcp_verification_rejects_private_dns_without_connecting(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))],
    )

    cases = _check_mcp_http([{"url": "https://metadata.example/token?secret=value"}], online=True)

    assert len(cases) == 1
    assert cases[0].passed is False
    assert cases[0].classification == "unsafe-destination"
    assert "secret" not in cases[0].message


def test_online_mcp_verification_refuses_redirects(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))],
    )

    monkeypatch.setattr("codex_plugin_scanner.verification.probe_pinned_https", lambda *_args, **_kwargs: 302)

    cases = _check_mcp_http([{"url": "https://example.com/redirect"}], online=True)

    assert cases[0].passed is False
    assert cases[0].classification == "unsafe-redirect"


def test_online_mcp_verification_pins_the_validated_address(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))],
    )
    observed_addresses: list[tuple[str, ...]] = []

    def _probe(_parsed, addresses, *, timeout_seconds):
        observed_addresses.append(addresses)
        assert 0 < timeout_seconds <= 3
        return 200

    monkeypatch.setattr("codex_plugin_scanner.verification.probe_pinned_https", _probe)

    cases = _check_mcp_http([{"url": "https://example.com/health"}], online=True)

    assert cases[0].passed is True
    assert observed_addresses == [("93.184.216.34",)]


def test_online_mcp_verification_caps_validated_addresses(monkeypatch):
    resolved = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", (f"8.8.8.{index}", 443))
        for index in range(1, MAX_VALIDATED_HTTPS_ADDRESSES + 5)
    ]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_args, **_kwargs: resolved)

    _parsed, error, addresses = _validate_remote_url("https://example.com", resolve_dns=True)

    assert error is None
    assert len(addresses) == MAX_VALIDATED_HTTPS_ADDRESSES


def test_online_mcp_verification_bounds_stalled_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    release = threading.Event()

    def stalled_resolver(*_args, **_kwargs):
        release.wait(10)
        return []

    monkeypatch.setattr(socket, "getaddrinfo", stalled_resolver)
    monkeypatch.setattr("codex_plugin_scanner.verification.time.monotonic", lambda: 10.0)

    _parsed, error, addresses = _validate_remote_url(
        "https://example.com",
        resolve_dns=True,
        deadline=10.001,
    )
    release.set()

    assert error == "Remote MCP hostname resolution timed out"
    assert addresses == ()


def test_malformed_remote_url_becomes_unsafe_destination_case() -> None:
    cases = _check_mcp_http([{"url": "https://[malformed"}], online=False)

    assert len(cases) == 1
    assert cases[0].classification == "unsafe-destination"
    assert cases[0].passed is False


def test_pinned_https_uses_one_deadline_across_addresses(monkeypatch):
    observed_timeouts: list[float] = []

    class FailingConnection:
        sock = None

        def __init__(self, _hostname, _port, _address, *, deadline):
            observed_timeouts.append(deadline)

        def request(self, _method, _target):
            raise OSError("unreachable")

        def close(self):
            return None

    monotonic_values = iter((10.0, 10.2, 10.6))
    monkeypatch.setattr("codex_plugin_scanner.pinned_https.time.monotonic", lambda: next(monotonic_values))
    monkeypatch.setattr("codex_plugin_scanner.pinned_https._PinnedHTTPSConnection", FailingConnection)

    with pytest.raises(TimeoutError):
        probe_pinned_https(
            urllib.parse.urlparse("https://example.com"),
            ("8.8.8.8", "8.8.4.4"),
            timeout_seconds=0.5,
        )

    assert observed_timeouts == [10.5, 10.5]


def test_verification_rejects_symlinked_configuration(tmp_path: Path):
    outside = tmp_path.parent / f"{tmp_path.name}-outside.json"
    outside.write_text('{"remotes": []}', encoding="utf-8")
    (tmp_path / ".mcp.json").symlink_to(outside)

    result = verify_plugin(tmp_path)

    assert result.verify_pass is False
    assert any(case.name == ".mcp.json parses" and not case.passed for case in result.cases)


def test_verification_rejects_dangling_configuration_symlink(tmp_path: Path):
    (tmp_path / ".mcp.json").symlink_to(tmp_path / "host-only-mcp.json")

    result = verify_plugin(tmp_path)

    assert result.verify_pass is False
    assert any(case.name == ".mcp.json parses" and not case.passed for case in result.cases)


def test_verification_rejects_symlinked_skill_manifest(tmp_path: Path):
    (tmp_path / ".codex-plugin").mkdir()
    (tmp_path / ".codex-plugin" / "plugin.json").write_text(
        '{"name":"demo","version":"1.0.0","description":"demo","skills":"./skills"}',
        encoding="utf-8",
    )
    (tmp_path / "skills" / "demo").mkdir(parents=True)
    outside = tmp_path.parent / f"{tmp_path.name}-outside-skill.md"
    outside.write_text("---\nname: outside\ndescription: outside\n---", encoding="utf-8")
    (tmp_path / "skills" / "demo" / "SKILL.md").symlink_to(outside)

    result = verify_plugin(tmp_path)

    assert result.verify_pass is False
    assert any(case.classification == "frontmatter" and not case.passed for case in result.cases)


def test_verify_plugin_handles_non_object_marketplace_payload(tmp_path: Path):
    (tmp_path / "marketplace.json").write_text('["not-an-object"]', encoding="utf-8")
    result = verify_plugin(tmp_path)
    assert result.verify_pass is False
    assert any(case.component == "marketplace" and case.classification == "schema" for case in result.cases)


def test_verify_plugin_marketplace_repo_checks_all_local_plugins():
    fixtures = Path(__file__).parent / "fixtures"
    result = verify_plugin(fixtures / "multi-plugin-repo")

    assert result.scope == "repository"
    assert result.verify_pass is False
    assert len(result.plugin_results) == 2
    assert {plugin.plugin_name for plugin in result.plugin_results} == {"alpha-plugin", "beta-plugin"}
    assert any(case.name.startswith("alpha-plugin · ") for case in result.cases)
    assert any(case.name.startswith("beta-plugin · ") for case in result.cases)
    assert any(skip.name == "remote-plugin" for skip in result.skipped_targets)


def test_verify_plugin_reports_real_workspace_path() -> None:
    result = verify_plugin(FIXTURES / "good-plugin")
    assert Path(result.workspace).exists()
    assert Path(result.workspace) == (FIXTURES / "good-plugin").resolve()


def test_verify_plugin_checks_skill_frontmatter_from_manifest(tmp_path: Path):
    (tmp_path / ".codex-plugin").mkdir()
    (tmp_path / ".codex-plugin" / "plugin.json").write_text(
        '{"name":"demo","version":"1.0.0","description":"demo","skills":"./skills"}',
        encoding="utf-8",
    )
    (tmp_path / "skills" / "broken").mkdir(parents=True)
    (tmp_path / "skills" / "broken" / "SKILL.md").write_text("no frontmatter", encoding="utf-8")

    result = verify_plugin(tmp_path)

    assert result.verify_pass is False
    assert any(case.component == "skills" and case.classification == "frontmatter" for case in result.cases)


def test_verify_plugin_skips_stdio_execution_for_untrusted_servers(tmp_path: Path):
    (tmp_path / ".codex-plugin").mkdir()
    (tmp_path / ".codex-plugin" / "plugin.json").write_text(
        '{"name":"demo","version":"1.0.0","description":"demo"}',
        encoding="utf-8",
    )
    (tmp_path / ".mcp.json").write_text(
        '{"mcpServers":{"demo":{"command":"python","args":["-c","print(1)"]}}}',
        encoding="utf-8",
    )

    result = verify_plugin(tmp_path)

    assert result.verify_pass is False
    assert any(case.name == "stdio execution:demo" for case in result.cases)
    assert any(case.classification == "safety-skip" for case in result.cases)
    assert all(not trace.name.startswith("stdio") for trace in result.traces)


def test_verify_plugin_reports_stdio_servers_without_spawning_them(tmp_path: Path):
    (tmp_path / ".codex-plugin").mkdir()
    (tmp_path / ".codex-plugin" / "plugin.json").write_text(
        '{"name":"demo","version":"1.0.0","description":"demo"}',
        encoding="utf-8",
    )
    (tmp_path / ".mcp.json").write_text(
        '{"mcpServers":{"demo":{"command":"python","args":["-c","print(1)"]}}}',
        encoding="utf-8",
    )

    result = verify_plugin(tmp_path)

    assert result.verify_pass is False
    expected_message = "Skipped stdio command execution for safety; manual review is required before trusting it."
    assert any(case.message == expected_message for case in result.cases)


def test_doctor_report_filters_component():
    report = build_doctor_report(FIXTURES / "good-plugin", "manifest")
    assert report["component"] == "manifest"
    assert isinstance(report["cases"], list)


def test_doctor_report_explains_when_stdio_execution_is_skipped(tmp_path: Path):
    (tmp_path / ".codex-plugin").mkdir()
    (tmp_path / ".codex-plugin" / "plugin.json").write_text(
        '{"name":"mcp-demo","version":"1.0.0","description":"demo"}',
        encoding="utf-8",
    )
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "stub": {
                        "command": "python",
                        "args": ["-u", "-c", "print('unsafe')"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    report = build_doctor_report(tmp_path, "mcp")

    assert report["verify_pass"] is False
    assert report["stdout_log"] == ""
    assert any(case["classification"] == "safety-skip" for case in report["cases"])
