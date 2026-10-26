"""End-to-end workspace protection scenarios against the compiled runtime.

Each scenario drives the real admission, observation, scheduling and native
snapshot path with a cached advisory bundle and no network. They pin the
behavior a person sees from background assessment: a known risk is reported
once, an equivalent fixed workspace stays quiet, a feed update or a lockfile
edit reassesses exactly once, linked worktrees never borrow each other's
results, incomplete coverage is never reported as clean, and restoring
protection is never mistaken for a fix.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import threading
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard import local_supply_chain
from codex_plugin_scanner.guard import native_supply_chain_egress as egress_module
from codex_plugin_scanner.guard import workspace_assessment_runner as runner
from codex_plugin_scanner.guard import workspace_assessment_store as assessments
from codex_plugin_scanner.guard import workspace_assessment_worker as worker
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.config import load_guard_config
from codex_plugin_scanner.guard.daemon.server import _GuardDaemonHandler
from codex_plugin_scanner.guard.store import GuardStore
from tests.daemon_control_patching import patch_daemon_global
from tests.native_workspace import bind_workspace
from tests.test_guard_phase06_workspace_audit import WORKSPACE_AUDIT_NOW
from tests.test_guard_supply_chain_evaluator import WORKSPACE_ID, _bundle_response, _package

AFFECTED = "1.2.8"
FIXED = "1.2.9"
# Far enough apart that every automatic run clears the debounce and interval.
STEP_MS = assessments.MIN_INTERVAL_MS + assessments.MAX_DEBOUNCE_WAIT_MS


@pytest.fixture
def native_binary() -> None:
    if not Path(os.environ.get("HOL_GUARD_NATIVE_BINARY") or "").is_file():
        pytest.skip("needs HOL_GUARD_NATIVE_BINARY for the compiled runtime")


@pytest.fixture
def offline(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    def no_network(*args, **kwargs):
        raise AssertionError("a background assessment must not open a connection")

    monkeypatch.setattr(egress_module, "_fetch_raw", no_network)
    # Give Guard sync, Python and native alike, credentials that point at a
    # local listener, so a Cloud request from any layer is caught rather than
    # skipped for want of credentials.
    listener = socket.create_server(("127.0.0.1", 0))
    listener.settimeout(0.2)
    attempts: list[object] = []
    stopped = threading.Event()

    def accept() -> None:
        while not stopped.is_set():
            try:
                connection, _address = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            attempts.append(connection.getsockname())
            connection.close()

    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    port = listener.getsockname()[1]
    monkeypatch.setenv("HOL_GUARD_TEST_SYNC_URL", f"http://127.0.0.1:{port}/api/guard/receipts/sync")
    monkeypatch.setenv("HOL_GUARD_TEST_ACCESS_TOKEN", "scenario-token")
    try:
        yield
    finally:
        stopped.set()
        thread.join()
        listener.close()
    assert attempts == [], "a background assessment must not contact Guard Cloud"


class Clock:
    def __init__(self) -> None:
        self.now = 1_000_000_000

    def __call__(self) -> int:
        return self.now

    def advance(self) -> int:
        self.now += STEP_MS
        return self.now


def _write_project(root: Path, version: str) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_text('{"dependencies":{"minimist":"^1.2.0"}}', encoding="utf-8")
    _write_lock(root, version)


def _write_lock(root: Path, version: str) -> None:
    lock = {
        "packages": {
            "": {"dependencies": {"minimist": "^1.2.0"}},
            "node_modules/minimist": {"version": version},
        }
    }
    (root / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")


def _store(tmp_path: Path, *, blocked: bool = True, bundle_version: str = "1747612800000-deadbeef") -> GuardStore:
    store = GuardStore(tmp_path / "guard-home")
    bind_workspace(store, WORKSPACE_ID)
    _cache_feed(store, blocked=blocked, bundle_version=bundle_version)
    return store


def _cache_feed(store: GuardStore, *, blocked: bool, bundle_version: str) -> None:
    packages = []
    if blocked:
        packages.append(
            _package(
                ecosystem="npm",
                name="minimist",
                version=AFFECTED,
                default_action="block",
                recommended_fix_version=FIXED,
            )
        )
    response = _bundle_response(packages=packages, bundle_version=bundle_version)
    store.cache_supply_chain_bundle(WORKSPACE_ID, response, WORKSPACE_AUDIT_NOW)


def _admit(store: GuardStore, root: Path, clock: Clock) -> assessments.WorktreeKeys:
    admitted = worker.admit_workspace(store, str(root), clock=clock)
    return assessments.WorktreeKeys(str(admitted["codebase_key"]), str(admitted["worktree_key"]))


def _run_all(store: GuardStore, clock: Clock) -> int:
    clock.advance()
    ran = 0
    while runner.run_next(store, load_guard_config(store.guard_home), owner="test", clock=clock):
        ran += 1
    return ran


def _latest(store: GuardStore, keys: assessments.WorktreeKeys) -> dict[str, Any]:
    [run] = [item for item in assessments.latest_assessed_runs(store) if item["worktree_key"] == keys.worktree_key]
    return run


def _minimist(run: dict[str, object]) -> list[dict[str, object]]:
    findings = run["findings"]
    assert isinstance(findings, list)
    return [item for item in findings if item["package_name"] == "minimist"]


def _queued(store: GuardStore, keys: assessments.WorktreeKeys) -> list[dict[str, object]]:
    return [run for run in assessments.recent_runs(store, keys) if run["state"] == "queued"]


def test_known_risk_is_reported_and_the_fixed_equivalent_stays_quiet(
    tmp_path: Path, native_binary: None, offline: None
) -> None:
    clock = Clock()
    store = _store(tmp_path)
    _write_project(tmp_path / "affected", AFFECTED)
    _write_project(tmp_path / "fixed", FIXED)
    affected = _admit(store, tmp_path / "affected", clock)
    fixed = _admit(store, tmp_path / "fixed", clock)
    assert _run_all(store, clock) == 2

    [finding] = _minimist(_latest(store, affected))
    assert (finding["decision"], finding["package_version"], finding["fix_version"]) == ("block", AFFECTED, FIXED)
    quiet = _latest(store, fixed)
    assert _minimist(quiet) == []
    # The cached bundle names only risky versions and a background run never
    # asks Cloud about the rest, so the fixed version is unanswered, not clean.
    assert quiet["state"] == "partial"
    assert quiet["coverage"]["detectors"]["supply_chain"] == "incomplete"
    assert str(tmp_path) not in json.dumps(assessments.latest_assessed_runs(store))


def test_feed_update_rematches_the_same_snapshot_once(tmp_path: Path, native_binary: None, offline: None) -> None:
    clock = Clock()
    store = _store(tmp_path, blocked=False)
    _write_project(tmp_path / "workspace", AFFECTED)
    keys = _admit(store, tmp_path / "workspace", clock)
    assert _run_all(store, clock) == 1
    before = _latest(store, keys)
    assert _minimist(before) == []
    assert worker.observe(store, clock=clock) == 0

    _cache_feed(store, blocked=True, bundle_version="1747699200000-feedface")
    assert worker.observe(store, clock=clock) == 1
    [queued] = _queued(store, keys)
    assert queued["trigger_kind"] == "feed_change"
    assert _run_all(store, clock) == 1

    after = _latest(store, keys)
    assert after["snapshot_digest"] == before["snapshot_digest"]
    [finding] = _minimist(after)
    assert finding["decision"] == "block"
    assert worker.observe(store, clock=clock) == 0


def test_lockfile_change_reassesses_and_replaces_the_old_result(
    tmp_path: Path, native_binary: None, offline: None
) -> None:
    clock = Clock()
    store = _store(tmp_path)
    root = tmp_path / "workspace"
    _write_project(root, AFFECTED)
    keys = _admit(store, root, clock)
    assert _run_all(store, clock) == 1
    before = _latest(store, keys)
    assert len(_minimist(before)) == 1
    assert worker.observe(store, clock=clock) == 0

    _write_lock(root, FIXED)
    assert worker.observe(store, clock=clock) == 1
    [queued] = _queued(store, keys)
    assert queued["trigger_kind"] == "file_change"
    assert _run_all(store, clock) == 1

    after = _latest(store, keys)
    assert after["snapshot_digest"] != before["snapshot_digest"]
    assert _minimist(after) == []


def test_an_edit_storm_coalesces_into_one_queued_run(tmp_path: Path, native_binary: None, offline: None) -> None:
    clock = Clock()
    store = _store(tmp_path)
    root = tmp_path / "workspace"
    _write_project(root, AFFECTED)
    keys = _admit(store, root, clock)
    assert _run_all(store, clock) == 1
    worker.observe(store, clock=clock)

    for index in range(25):
        (root / "notes.txt").write_text(f"edit {index}", encoding="utf-8")
        worker.observe(store, clock=clock)
        clock.now += 100
    assert len(_queued(store, keys)) == 1
    assert _run_all(store, clock) == 1
    assert _queued(store, keys) == []


@pytest.mark.skipif(shutil.which("git") is None, reason="needs git for linked worktrees")
def test_linked_worktrees_keep_their_own_dirty_inputs(tmp_path: Path, native_binary: None, offline: None) -> None:
    clock = Clock()
    store = _store(tmp_path)
    main = tmp_path / "main"
    _write_project(main, FIXED)
    git = ["git", "-c", "user.name=fixture", "-c", "user.email=fixture@example.test", "-c", "commit.gpgsign=false"]
    subprocess.run([*git, "init", "-q", str(main)], check=True)
    subprocess.run([*git, "-C", str(main), "add", "."], check=True)
    subprocess.run([*git, "-C", str(main), "commit", "-q", "-m", "fixture"], check=True)
    linked = tmp_path / "linked"
    subprocess.run([*git, "-C", str(main), "worktree", "add", "-q", str(linked)], check=True)
    # Same commit, but the linked worktree carries an uncommitted downgrade.
    _write_lock(linked, AFFECTED)

    main_keys = _admit(store, main, clock)
    linked_keys = _admit(store, linked, clock)
    assert main_keys.worktree_key != linked_keys.worktree_key
    assert _run_all(store, clock) == 2

    main_run = _latest(store, main_keys)
    linked_run = _latest(store, linked_keys)
    assert main_run["coverage"]["head_commit"] == linked_run["coverage"]["head_commit"]
    assert main_run["snapshot_digest"] != linked_run["snapshot_digest"]
    assert _minimist(main_run) == []
    [finding] = _minimist(linked_run)
    assert (finding["decision"], finding["package_version"]) == ("block", AFFECTED)


def test_missing_lockfile_is_partial_and_never_clean(tmp_path: Path, native_binary: None, offline: None) -> None:
    clock = Clock()
    store = _store(tmp_path)
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "package.json").write_text('{"dependencies":{"minimist":"^1.2.0"}}', encoding="utf-8")
    keys = _admit(store, root, clock)
    assert _run_all(store, clock) == 1

    run = _latest(store, keys)
    assert run["state"] == "partial"
    assert run["coverage"]["status"] == "partial"
    assert run["coverage"]["detectors"]["supply_chain"] != "complete"


@pytest.mark.skipif(os.name == "nt", reason="symlink creation needs extra rights on Windows")
def test_a_symlink_out_of_the_root_is_not_followed(tmp_path: Path, native_binary: None, offline: None) -> None:
    clock = Clock()
    store = _store(tmp_path)
    outside = tmp_path / "outside"
    _write_project(outside, AFFECTED)
    root = tmp_path / "workspace"
    _write_project(root, FIXED)
    (root / "vendor").symlink_to(outside, target_is_directory=True)
    keys = _admit(store, root, clock)
    assert _run_all(store, clock) == 1

    run = _latest(store, keys)
    assert all(item["package_version"] != AFFECTED for item in _minimist(run))
    assert str(outside) not in json.dumps(run)


def test_restoring_protection_leaves_the_known_risk_open(
    tmp_path: Path, native_binary: None, offline: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = Clock()
    store = _store(tmp_path)
    root = tmp_path / "workspace"
    _write_project(root, AFFECTED)
    keys = _admit(store, root, clock)
    assert _run_all(store, clock) == 1
    before = _latest(store, keys)
    assert len(_minimist(before)) == 1
    lock = (root / "package-lock.json").read_bytes()

    # Drive the daemon's Restore protection handler with its real workspace
    # context and intelligence sync. Only the device-level package tool steps
    # are stubbed, since they install shims into the user's real profile.
    handler = object.__new__(_GuardDaemonHandler)
    handler.server = SimpleNamespace(store=store)
    responses: list[dict[str, Any]] = []
    shim_contexts: list[HarnessContext] = []
    monkeypatch.setattr(handler, "_enforce_package_firewall_rate_limit", lambda *args: True)
    monkeypatch.setattr(handler, "_supply_chain_entitlement", lambda: {"allowed": True})
    monkeypatch.setattr(handler, "_write_json", lambda payload, status=200: responses.append(payload))
    monkeypatch.setattr(handler, "_record_headless_receipt", lambda **kwargs: None)
    patch_daemon_global(monkeypatch, "require_high_risk", lambda *args, **kwargs: None)
    patch_daemon_global(monkeypatch, "package_shim_status", lambda context: {"installed_managers": ["npm"]})
    patch_daemon_global(
        monkeypatch,
        "_repair_detected_package_shims",
        lambda context, **kwargs: shim_contexts.append(context),
    )
    patch_daemon_global(monkeypatch, "_activate_package_firewall_runtime", lambda context: (200, {}))
    patch_daemon_global(monkeypatch, "_resolve_guard_sync_auth_context", lambda _store: {"sync_url": "local"})

    def refresh_bundle(actual: GuardStore, *, auth_context: dict[str, object]) -> dict[str, object]:
        _cache_feed(actual, blocked=True, bundle_version="1747699200000-feedface")
        return {"status": "synced"}

    def reject_workspace_audit(*_args: object, **_kwargs: object) -> dict[str, object]:
        pytest.fail("restore must not audit the workspace inline")

    monkeypatch.setattr(local_supply_chain, "sync_supply_chain_bundle", refresh_bundle)
    monkeypatch.setattr(local_supply_chain, "sync_managed_workspace_audits", reject_workspace_audit)

    handler._handle_supply_chain_repair({"workspace_dir": str(root)})

    [response] = responses
    assert response["status"] == "completed"
    assert response["result"]["repaired"] is True
    assert [context.workspace_dir for context in shim_contexts] == [root.resolve()]
    # Restore protection repairs package tools and routing and refreshes the
    # advisory feed; it never edits the project, so it is not a fix.
    assert (root / "package-lock.json").read_bytes() == lock

    assert worker.observe(store, clock=clock) == 1
    [queued] = _queued(store, keys)
    assert queued["trigger_kind"] == "feed_change"
    assert _run_all(store, clock) == 1
    after = _latest(store, keys)
    assert after["snapshot_digest"] == before["snapshot_digest"]
    [finding] = _minimist(after)
    assert (finding["decision"], finding["package_version"], finding["fix_version"]) == ("block", AFFECTED, FIXED)
