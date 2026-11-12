from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_production_native_resident_client_has_bounded_admission() -> None:
    from codex_plugin_scanner.guard.native_resident_client import _MAX_PERSISTENT_CLIENTS, _MAX_PERSISTENT_POOLS

    assert 0 < _MAX_PERSISTENT_CLIENTS <= 16
    assert 0 < _MAX_PERSISTENT_POOLS <= 16


def test_native_runtime_tracks_total_request_age() -> None:
    runtime_source = (ROOT / "rust/crates/guard-runtime/src/lib.rs").read_text(encoding="utf-8")
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
