"""Bounded adapter scheduling and the HTTP readiness deadline."""

from __future__ import annotations

import base64
import json
import threading
import time
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_catalog_read as native
from codex_plugin_scanner.guard.catalog_delivery import discovery, installed_bundle
from tests.test_catalog_discovery_backend import prepared_fixture


def status_for(binary):
    return SimpleNamespace(
        available=True,
        compatible=True,
        identity=SimpleNamespace(path=binary, size=binary.stat().st_size, mtime_ns=binary.stat().st_mtime_ns),
        capabilities=SimpleNamespace(features=[discovery.CAPABILITY, discovery.BATCH_CAPABILITY]),
    )


@pytest.mark.parametrize("replace_runtime", [False, True])
def test_preparation_captures_identity_once_and_rechecks_boundaries(tmp_path, monkeypatch, replace_runtime):
    authority, _, _, _ = prepared_fixture(tmp_path, monkeypatch, count=1)
    binary = tmp_path / "binary"
    binary.write_bytes(b"test")
    status = status_for(binary)
    probes, calls = [], []

    def probe():
        probes.append(True)
        return status

    def request(**kwargs):
        action = json.loads(kwargs["payload"])["request"]["action"]
        calls.append(action["kind"])
        if action["kind"] == "begin_batched":
            result = {"outcome": "fetch_batch", "session": "test", "fetches": [{"location": "opaque", "length": 1}] * 8}
        else:
            assert action["kind"] == "advance_batch"
            assert action["data"] == [base64.b64encode(b"x").decode()] * 8
            result = {"outcome": "complete", "handle": {"root": "c" * 64}}
        return json.dumps({"schema": "guard.catalog-prepare-result.v1", **result}).encode()

    def fetch(*_):
        if replace_runtime:
            binary.write_bytes(b"changed")
        return b"x"

    monkeypatch.setattr(discovery, "native_runtime_status", probe)
    monkeypatch.setattr(discovery, "native_resident_client_request", request)
    if replace_runtime:
        with pytest.raises(ValueError, match="runtime changed"):
            discovery.prepare_discovery(tmp_path, authority, fetch=fetch)
        assert calls == ["begin_batched"]
        assert discovery._cached is None
    else:
        discovery.prepare_discovery(tmp_path, authority, fetch=fetch)
        assert len(probes) == 2  # begin and completion, not once per object
        assert calls == ["begin_batched", "advance_batch"]


def test_first_http_call_never_waits_for_cold_preparation(tmp_path, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    handle = SimpleNamespace(root="c" * 64, native={"root": "c" * 64})

    def load():
        entered.set()
        assert release.wait(10)
        return object()

    monkeypatch.setattr(discovery, "_home", None)
    monkeypatch.setattr(discovery, "_handle", None)
    monkeypatch.setattr(discovery, "_worker", None)
    monkeypatch.setattr(discovery, "_retry_after", 0.0)
    monkeypatch.setattr(installed_bundle, "load_installed_bundle", load)
    monkeypatch.setattr(discovery, "prepare_discovery", lambda *_: handle)
    (tmp_path / "binary").write_bytes(b"test")
    status = status_for(tmp_path / "binary")
    status.capabilities.features += [native.CATALOG_DISCOVERY_FEATURE, native.CATALOG_READ_FEATURE]
    monkeypatch.setattr(native, "native_runtime_status", lambda **_: status)
    monkeypatch.setattr(native, "_supports_catalog_read", lambda _: True)
    monkeypatch.setattr(native, "native_resident_client_request", lambda **_: pytest.fail("not ready"))
    started = time.monotonic()
    result = native.native_catalog_read(
        guard_home=tmp_path, route="index", query="", if_none_match=None, expected_catalog_digest="b" * 64
    )
    elapsed = time.monotonic() - started
    try:
        assert entered.wait(1)
        assert result.status == 503
        assert elapsed < 2.0
        worker = discovery._worker
        with pytest.raises(ValueError, match="preparing"):
            discovery.installed_discovery(tmp_path)
        assert discovery._worker is worker
    finally:
        release.set()
        worker.join(5)
    assert discovery.installed_discovery(tmp_path) is handle
    discovery.invalidate(tmp_path, handle)
    assert discovery._handle is None


def test_old_prepare_capability_is_explicitly_unsupported(tmp_path, monkeypatch):
    binary = tmp_path / "binary"
    binary.write_bytes(b"test")
    status = status_for(binary)
    status.capabilities.features.remove(discovery.BATCH_CAPABILITY)
    monkeypatch.setattr(discovery, "native_runtime_status", lambda: status)
    with pytest.raises(ValueError, match="batched preparation unavailable"):
        discovery._native(tmp_path, {"kind": "begin"})
    status.capabilities.features += [native.CATALOG_READ_FEATURE, "resident-protocol-v2"]
    assert not native._supports_catalog_read(status)


def test_native_deadline_frame_is_transient_not_protocol_absence(tmp_path, monkeypatch):
    (tmp_path / "binary").write_bytes(b"test")
    status = status_for(tmp_path / "binary")
    status.capabilities.features = [native.CATALOG_READ_FEATURE]
    monkeypatch.setattr(native, "native_runtime_status", lambda **_: status)
    monkeypatch.setattr(native, "_supports_catalog_read", lambda _: True)
    monkeypatch.setattr(
        native,
        "native_resident_client_request",
        lambda **_: b'{"error":"native_client_deadline_exceeded","retryable":false}',
    )
    result = native.native_catalog_read(
        guard_home=tmp_path, route="index", query="", if_none_match=None, expected_catalog_digest="b" * 64
    )
    assert result.status == 503 and result.error_code == native.CATALOG_READ_TRANSPORT_FAILED


def test_real_native_cold_read_returns_preparing_before_factory_finishes(tmp_path, monkeypatch, native_hook_force):
    from tests.test_catalog_discovery_backend import provision

    entered, release = threading.Event(), threading.Event()

    def load():
        entered.set()
        assert release.wait(10)
        raise ValueError("synthetic factory unavailable")

    provision(tmp_path)
    monkeypatch.setattr(installed_bundle, "load_installed_bundle", load)
    monkeypatch.setattr(discovery, "_home", None)
    monkeypatch.setattr(discovery, "_handle", None)
    monkeypatch.setattr(discovery, "_worker", None)
    monkeypatch.setattr(discovery, "_retry_after", 0.0)
    started = time.monotonic()
    try:
        result = native.native_catalog_read(
            guard_home=tmp_path, route="index", query="", if_none_match=None, expected_catalog_digest="b" * 64
        )
        elapsed = time.monotonic() - started
        worker = discovery._worker
        assert result.status == 503 and result.error_code == "catalog_read_model_unavailable"
        assert entered.wait(1)
        assert elapsed < 2.0
    finally:
        release.set()
        if discovery._worker is not None:
            worker.join(5)


def test_real_restart_stale_and_expired_handles(tmp_path, monkeypatch, native_hook_force):
    from codex_plugin_scanner.guard.native_resident_client import close_native_residents
    from tests.test_catalog_discovery_backend import provision

    authority, fetch, requests, _ = prepared_fixture(tmp_path, monkeypatch, count=2)
    home = tmp_path / "home"
    provision(home)
    try:
        first = discovery.prepare_discovery(home, authority, fetch=fetch)
        before = len(requests)
        close_native_residents(guard_home=home)
        with pytest.raises(ValueError, match="handle_invalid"):
            discovery.require_handle(first, home)
        second = discovery.prepare_discovery(home, authority, fetch=fetch)
        assert second.root == first.root and second.native["token"] != first.native["token"]
        assert len(requests) > before  # Restart rebuilds transient input from the verified source.
        arguments = dict(
            guard_home=home,
            discovery_handle=first,
            route="index",
            query="",
            if_none_match=None,
            expected_catalog_digest="b" * 64,
        )
        assert native.native_catalog_read(**arguments).status == 503
        arguments["discovery_handle"] = second
        assert native.native_catalog_read(**arguments).status == 200
        second.native["expires_at"] = 1
        assert native.native_catalog_read(**arguments).status == 503
    finally:
        close_native_residents(guard_home=home)
