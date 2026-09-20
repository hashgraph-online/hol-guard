from __future__ import annotations

from pathlib import Path

from scripts.ci.python_static_bindings import Reference, StaticBindings

ROOT = Path(__file__).resolve().parents[1]


def test_native_resident_client_has_bounded_admission() -> None:
    source = (ROOT / "src/codex_plugin_scanner/guard/native_runtime_resident.py").read_text(encoding="utf-8")
    assert "@native_resident_admission" in source
    assert "from .native_runtime_admission import native_resident_admission" in source


def test_daemon_http_server_is_bounded() -> None:
    resolver = StaticBindings(ROOT / "src/codex_plugin_scanner/guard/daemon/server.py")
    path, owner = resolver.resolved_class("_GuardDaemonHTTPServer")
    assert len(owner.bases) == 1
    reference, _ = resolver.expression(path, owner.bases[0])
    assert reference == Reference("codex_plugin_scanner.guard.daemon.bounded_http", "BoundedThreadingHTTPServer")


def test_native_runtime_tracks_total_request_age() -> None:
    runtime_source = (ROOT / "rust/crates/guard-runtime/src/main.rs").read_text(encoding="utf-8")
    transport_source = (ROOT / "rust/crates/guard-runtime/src/resident_transport.rs").read_text(encoding="utf-8")
    assert "mod hardening;" in runtime_source
    assert "accepted_at: Instant" in transport_source
    assert "hardening::request_expired" in transport_source
    assert "native_request_deadline_exceeded" in transport_source


def test_native_io_failures_have_stable_non_integrity_classes() -> None:
    source = (ROOT / "rust/crates/guard-runtime/src/hardening.rs").read_text(encoding="utf-8")
    for reason in (
        "native_client_disconnected",
        "native_request_read_timeout",
        "native_response_write_timeout",
        "native_resource_pressure",
        "native_local_transport_changed",
    ):
        assert reason in source


def test_doctor_reports_aggregate_admission_without_payloads() -> None:
    source = (ROOT / "src/codex_plugin_scanner/guard/cli/commands_dispatch_admin.py").read_text(encoding="utf-8")
    assert "native_resident_admission_snapshot" in source
    assert "daemon_admission_snapshot" in source
    combined = (ROOT / "src/codex_plugin_scanner/guard/native_runtime_admission.py").read_text(encoding="utf-8") + (
        ROOT / "src/codex_plugin_scanner/guard/daemon/bounded_http.py"
    ).read_text(encoding="utf-8")
    for prohibited in ("raw_command", "prompt_text", "request_payload", "environment_values", "credential"):
        assert prohibited not in combined
