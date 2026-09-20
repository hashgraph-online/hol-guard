"""Exercise the mutable facade seams crossed by the package evaluator partition."""

from __future__ import annotations

from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.runtime import supply_chain_package_eval as evaluator


@pytest.mark.parametrize("raise_uncached", [False, True])
def test_request_cache_scope_restores_outer_state_and_current_dispatch(monkeypatch, tmp_path, raise_uncached):
    outer_cache = {}
    seen_caches = []
    result = object()
    artifact = object()
    store = object()

    def config_reader(_):
        return {"current": True}

    expected = {
        "artifact": artifact,
        "store": store,
        "workspace_dir": tmp_path,
        "now": "2026-09-19T00:00:00Z",
        "external_archive_network_authorized": True,
        "retain_external_archive_blob": True,
        "config_reader": config_reader,
    }

    class DispatchObservedError(RuntimeError):
        pass

    def current_dispatch(**kwargs):
        assert kwargs == expected
        cache = evaluator._LOCKFILE_PARSE_CACHE.get()
        assert cache == {}
        assert cache is not outer_cache
        seen_caches.append(cache)
        if raise_uncached:
            raise DispatchObservedError
        return result

    monkeypatch.setattr(evaluator, "workspace_input_snapshot", nullcontext)
    monkeypatch.setattr(evaluator, "_evaluate_package_request_artifact_uncached", current_dispatch)
    token = evaluator._LOCKFILE_PARSE_CACHE.set(outer_cache)
    try:
        if raise_uncached:
            with pytest.raises(DispatchObservedError):
                evaluator.evaluate_package_request_artifact(**expected)
        else:
            assert evaluator.evaluate_package_request_artifact(**expected) is result
        assert evaluator._LOCKFILE_PARSE_CACHE.get() is outer_cache
        assert len(seen_caches) == 1
    finally:
        evaluator._LOCKFILE_PARSE_CACHE.reset(token)


def test_lockfile_cache_only_admits_complete_results_and_reads_current_parsers(monkeypatch):
    incomplete = SimpleNamespace(complete=False)
    complete = SimpleNamespace(complete=True)
    results = iter((incomplete, complete))
    first_dependency_parser = object()
    current_dependency_parser = object()
    current_package_parser = object()
    calls = []

    def parse(path, source, **kwargs):
        calls.append((path, source, kwargs))
        return next(results)

    monkeypatch.setattr(evaluator, "parse_lockfile_with_budget", parse)
    monkeypatch.setattr(evaluator, "_lockfile_parse_budget_seconds", lambda _: 0.125)
    monkeypatch.setattr(evaluator, "_dependency_map_for_path", first_dependency_parser)
    monkeypatch.setattr(evaluator, "_package_lock_entries", current_package_parser)
    cache = {}
    token = evaluator._LOCKFILE_PARSE_CACHE.set(cache)
    try:
        assert evaluator._parse_lockfile_text_result("package-lock.json", b"source") is incomplete
        assert cache == {}
        monkeypatch.setattr(evaluator, "_dependency_map_for_path", current_dependency_parser)
        assert evaluator._parse_lockfile_text_result("package-lock.json", "source") is complete
        assert evaluator._parse_lockfile_text_result("PACKAGE-LOCK.JSON", b"source") is complete
        assert len(calls) == 2
        assert calls[0][2]["dependency_parser"] is first_dependency_parser
        assert calls[1][2] == {
            "budget_seconds": 0.125,
            "dependency_parser": current_dependency_parser,
            "package_lock_parser": current_package_parser,
        }
        assert cache == {("package-lock.json", b"source"): complete}
    finally:
        evaluator._LOCKFILE_PARSE_CACHE.reset(token)


def test_download_preserves_captured_timeout_and_current_transport_limits(monkeypatch):
    defaults = evaluator._download_external_tarball.__kwdefaults__
    assert defaults is not None
    captured_timeout = defaults["timeout_seconds"]
    current_limit = evaluator._TARBALL_SCAN_MAX_BYTES + 1
    calls = []
    result = object()

    def download(source_url, **kwargs):
        calls.append((source_url, kwargs))
        return result

    monkeypatch.setattr(evaluator, "_TARBALL_SCAN_TIMEOUT_SECONDS", captured_timeout + 1)
    monkeypatch.setattr(evaluator, "_TARBALL_SCAN_MAX_BYTES", current_limit)
    monkeypatch.setattr(evaluator, "download_restricted_archive", download)

    assert evaluator._download_external_tarball("https://example.com/package.tgz") is result
    assert calls == [
        ("https://example.com/package.tgz", {"max_bytes": current_limit, "timeout_seconds": captured_timeout}),
    ]


@pytest.mark.parametrize(
    ("network_authorized", "integrity_invalid", "decision", "code"),
    [
        (False, False, "ask", "external_tarball_source"),
        (True, True, "block", "external_archive_source_integrity_invalid"),
    ],
)
def test_archive_guards_prevent_scan_before_current_authority(
    monkeypatch,
    network_authorized,
    integrity_invalid,
    decision,
    code,
):
    scans = []

    def scan(*args, **kwargs):
        scans.append((args, kwargs))
        raise AssertionError("The archive scan must remain behind the approval and source-integrity guards")

    monkeypatch.setattr(evaluator, "_scan_external_tarball", scan)
    target = {
        "ecosystem": "npm",
        "name": "demo",
        "namespace": None,
        "source_url": "https://registry.npmjs.org/demo/-/demo-1.0.0.tgz",
        "external_archive_source_integrity_invalid": integrity_invalid,
    }

    package, retained_download = evaluator._external_tarball_dependency_result(
        target,
        network_authorized=network_authorized,
        retain_download=True,
    )

    assert scans == []
    assert retained_download is None
    assert package["decision"] == decision
    assert package["reasons"][0]["code"] == code


def test_nested_cloud_failure_callbacks_read_current_facade_authority(monkeypatch, tmp_path):
    store = object()
    result = object()

    def config_reader(_):
        return {"current": True}

    authority_calls = []
    fail_closed_calls = []

    def stale_authority(*_args, **_kwargs):
        raise AssertionError("A superseded authority callback was used")

    def current_policy(**kwargs):
        authority_calls.append(kwargs)
        return "block"

    def expire_auth(current_store, **kwargs):
        assert current_store is store
        assert kwargs == {"allow_primary_repair": False}
        monkeypatch.setattr(
            evaluator,
            "resolve_package_firewall_entitlement",
            lambda _: {"allowed": False, "reason": "paid_guard_cloud_required"},
        )
        monkeypatch.setattr(evaluator, "_cloud_fail_closed_decision", current_policy)
        raise evaluator.GuardSyncAuthorizationExpiredError("expired test session")

    def fail_closed(**kwargs):
        fail_closed_calls.append(kwargs)
        return result

    monkeypatch.setattr(evaluator, "resolve_package_firewall_entitlement", stale_authority)
    monkeypatch.setattr(evaluator, "_cloud_fail_closed_decision", stale_authority)
    monkeypatch.setattr(evaluator, "_resolve_guard_sync_auth_context", expire_auth)
    monkeypatch.setattr(evaluator, "_cloud_fail_closed_evaluation", fail_closed)

    evaluation, fallback = evaluator._evaluate_with_cloud(
        artifact=object(),
        targets=({"ecosystem": "npm", "name": "demo", "namespace": None},),
        workspace_dir=tmp_path,
        workspace_id="workspace",
        workspace_fingerprint="fingerprint",
        bundle_meta=None,
        bundle_defer_eligible=False,
        bundle_decision=None,
        store=store,
        config_reader=config_reader,
    )

    assert evaluation is result
    assert fallback is None
    assert authority_calls == [{"store": store, "workspace_dir": tmp_path, "config_reader": config_reader}]
    assert len(fail_closed_calls) == 1
    assert fail_closed_calls[0]["code"] == "cloud_auth_error"
    assert fail_closed_calls[0]["fail_closed_decision"] == "block"
