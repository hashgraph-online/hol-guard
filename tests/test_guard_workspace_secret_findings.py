"""Secret findings in background workspace assessments.

The unit tests cover projection, coverage and the merge bounds with synthetic
native replies. The end-to-end tests run the compiled runtime over a worktree
holding planted fake credentials and look for those values everywhere the
daemon stores or serves a result.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_workspace_snapshot as native
from codex_plugin_scanner.guard import workspace_assessment_runner as runner
from codex_plugin_scanner.guard import workspace_assessment_store as assessments
from codex_plugin_scanner.guard import workspace_assessment_worker as worker
from codex_plugin_scanner.guard import workspace_secret_findings as secret_findings
from codex_plugin_scanner.guard.config import load_guard_config
from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_headless_daemon_api import _dashboard_token_for, _read_json_response, _request
from tests.test_guard_workspace_assessment_runner import (
    AUDIT,
    HOOKS_COMPLETE,
    KEYS,
    PLUGINS_COMPLETE,
    SCANNED,
    SECRETS_COMPLETE,
    SKILLS_COMPLETE,
    SNAPSHOT,
    T0,
    queued_run,
)

# The values are split so repository secret scanners do not read this file as
# holding a credential; they are joined into the planted files below.
GITHUB_TOKEN = "".join(["ghp_", "AbCdEfGhIjKlMnOpQrStUvWxYz", "012345"])
AWS_KEY = "".join(["AKIA", "IOSFODNN7", "REALKEY"])
FINGERPRINT = "0123456789abcdef0123456789abcdef"
FINDING_ID = "fedcba9876543210fedcba9876543210"


def digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def native_finding(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "finding_id": FINDING_ID,
        "rule_id": "github-token",
        "family": "provider",
        "severity": "high",
        "confidence": "high",
        "line": 2,
        "lines": [2],
        "occurrences": 1,
        "path": "src/deploy.py",
        "fingerprint": FINGERPRINT,
    }
    return {**base, **overrides}


def secrets_result(*findings: dict[str, object], **overrides: object) -> dict[str, object]:
    return {**SECRETS_COMPLETE, "findings": list(findings), **overrides}


@pytest.fixture
def native_binary(monkeypatch: pytest.MonkeyPatch) -> None:
    if not Path(os.environ.get("HOL_GUARD_NATIVE_BINARY") or "").is_file():
        pytest.skip("needs HOL_GUARD_NATIVE_BINARY for the compiled runtime")
    # These runs exercise the native snapshot and secret scan; the local
    # supply-chain audit is covered by its own end-to-end test.
    empty_audit = {
        "audit_status": "complete",
        "manifest_paths": [],
        "lockfile_paths": [],
        "evaluation": {"packages": []},
    }
    monkeypatch.setattr(runner, "_local_audit", lambda store, config, root: empty_audit)


def test_detector_set_names_the_secret_detector_and_changes_the_digest() -> None:
    assert "secrets" in runner.DETECTOR_SET
    legacy = hashlib.sha256(b"guard.workspace-detectors.v1\0supply_chain_local_v1").hexdigest()
    assert legacy != runner.DETECTOR_SET_DIGEST


def test_projection_carries_location_and_fingerprint_only() -> None:
    [finding] = secret_findings.project_secret_findings(secrets_result(native_finding()))
    assert finding["finding_id"] == FINDING_ID
    assert finding["source_kind"] == "secret"
    assert finding["detector"] == "secrets"
    assert finding["severity"] == "high"
    assert finding["validation_state"] == "unvalidated"
    assert finding["rule_ids"] == ["github-token"]
    assert (finding["path"], finding["line"], finding["fingerprint"]) == ("src/deploy.py", 2, FINGERPRINT)
    assert all(finding[name] is None for name in ("ecosystem", "package_name", "package_version", "fix_version"))


def test_every_location_of_a_repeated_secret_is_kept() -> None:
    [finding] = secret_findings.project_secret_findings(
        secrets_result(native_finding(line=2, lines=[2, 9, 31], occurrences=3))
    )
    assert (finding["line"], finding["lines"], finding["occurrences"]) == (2, [2, 9, 31], 3)


def test_a_deeply_nested_path_is_kept() -> None:
    path = "/".join(["d" * 100] * 12) + "/a.py"
    assert len(path) > 1200
    [finding] = secret_findings.project_secret_findings(secrets_result(native_finding(path=path)))
    assert finding["path"] == path
    assert secret_findings.secret_coverage(secrets_result(native_finding(path=path)))[0] == "complete"


@pytest.mark.parametrize(
    "bad",
    [
        {"finding_id": "short"},
        {"finding_id": None},
        {"rule_id": "has space"},
        {"rule_id": None},
        {"path": ""},
        {"path": "a\0b"},
        {"path": "p" * 5000},
        {"line": 0},
        {"line": True},
        {"line": "3"},
        {"lines": []},
        {"lines": [0]},
        {"lines": list(range(1, 40))},
        {"occurrences": 0},
        {"fingerprint": "short"},
        {"fingerprint": "G" * 32},
        {"severity": "catastrophic"},
    ],
)
def test_malformed_findings_are_dropped_and_leave_the_detector_incomplete(bad: dict[str, object]) -> None:
    result = secrets_result(native_finding(**bad))
    assert secret_findings.project_secret_findings(result) == []
    status, summary, reasons = secret_findings.secret_coverage(result)
    assert (status, reasons) == ("incomplete", ["invalid_finding"])
    assert summary["truncation_reasons"] == ["invalid_finding"]


def test_unknown_native_fields_are_not_copied() -> None:
    raw = native_finding(candidate="leaked-value", snippet="x = leaked-value")
    [finding] = secret_findings.project_secret_findings(secrets_result(raw))
    assert "leaked-value" not in json.dumps(finding)


def test_fingerprint_key_is_created_once_and_kept_in_the_local_store(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "home")
    first = secret_findings.load_fingerprint_key(store, "2026-10-24T00:00:00Z")
    assert len(first) >= 32
    assert secret_findings.load_fingerprint_key(store, "2026-10-25T00:00:00Z") == first
    other = secret_findings.load_fingerprint_key(GuardStore(tmp_path / "other"), "2026-10-24T00:00:00Z")
    assert other != first


def test_a_concurrent_first_run_reuses_the_key_another_worker_stored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path / "home")
    winner = "a" * 64
    store.set_sync_payload(secret_findings.FINGERPRINT_KEY_STATE_KEY, {"key": winner}, "2026-10-24T00:00:00Z")
    real_read = store.get_sync_payload
    calls = {"n": 0}

    def stale_first_read(key: str) -> object:
        # The first read happens before the other worker's write lands.
        calls["n"] += 1
        return None if calls["n"] == 1 else real_read(key)

    monkeypatch.setattr(store, "get_sync_payload", stale_first_read)

    assert secret_findings.load_fingerprint_key(store, "2026-10-24T00:00:01Z") == winner
    # The miss sends it through the insert-if-absent path and its read-back.
    assert calls["n"] == 2
    assert real_read(secret_findings.FINGERPRINT_KEY_STATE_KEY) == {"key": winner}


def test_a_stored_value_that_is_not_a_key_is_replaced(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "home")
    store.set_sync_payload(secret_findings.FINGERPRINT_KEY_STATE_KEY, {"key": "short"}, "2026-10-24T00:00:00Z")
    created = secret_findings.load_fingerprint_key(store, "2026-10-24T00:00:01Z")
    assert len(created) >= 32
    assert secret_findings.load_fingerprint_key(store, "2026-10-24T00:00:02Z") == created


def test_complete_scan_makes_a_complete_run() -> None:
    coverage = runner.coverage_summary(SCANNED, AUDIT, findings_truncated=False)
    assert coverage["status"] == "complete"
    assert coverage["detectors"]["secrets"] == "complete"
    assert coverage["secrets"]["skipped"] == {"credential_store": 0, "not_text": 0, "oversize": 0}
    assert not any("secrets" in reason for reason in coverage["reasons"])


@pytest.mark.parametrize(
    ("reason", "expected"),
    [("entry_cap", ["secrets_incomplete"]), ("max_findings", ["secrets_incomplete", "finding_cap"])],
)
def test_truncated_scan_keeps_the_run_partial(reason: str, expected: list[str]) -> None:
    truncated = replace(SNAPSHOT, secrets=secrets_result(status="incomplete", truncation_reasons=[reason]))
    coverage = runner.coverage_summary(truncated, AUDIT, findings_truncated=False)
    assert coverage["status"] == "partial"
    assert coverage["reasons"] == expected
    assert coverage["detectors"]["secrets"] == "incomplete"
    assert coverage["secrets"]["truncation_reasons"] == [reason]


def test_a_scan_that_hit_its_own_cap_marks_the_findings_list_truncated() -> None:
    capped = replace(SNAPSHOT, secrets=secrets_result(status="incomplete", truncation_reasons=["max_findings"]))
    coverage = runner.coverage_summary(capped, AUDIT, findings_truncated=False)
    assert coverage["reasons"] == ["secrets_incomplete", "finding_cap"]
    # Other secret limits leave the run partial without claiming a cut list.
    walked = replace(SNAPSHOT, secrets=secrets_result(status="incomplete", truncation_reasons=["entry_cap"]))
    assert "finding_cap" not in runner.coverage_summary(walked, AUDIT, findings_truncated=False)["reasons"]


@pytest.mark.parametrize("payload", [{"schema": "other"}, {**SECRETS_COMPLETE, "status": "weird"}, {}])
def test_unreadable_secret_result_is_an_error(payload: dict[str, object]) -> None:
    coverage = runner.coverage_summary(replace(SNAPSHOT, secrets=payload), AUDIT, findings_truncated=False)
    assert coverage["status"] == "partial"
    assert coverage["reasons"] == ["secrets_incomplete"]
    assert coverage["detectors"]["secrets"] == "error"


def test_runner_projects_secret_findings_and_stays_complete(tmp_path: Path, monkeypatch) -> None:
    store, claimed = queued_run(tmp_path)
    scanned = replace(
        SNAPSHOT,
        secrets=secrets_result(native_finding()),
        skills=SKILLS_COMPLETE,
        hooks=HOOKS_COMPLETE,
        plugins=PLUGINS_COMPLETE,
    )
    monkeypatch.setattr(runner, "workspace_snapshot", lambda root, **_: scanned)
    monkeypatch.setattr(runner, "_local_audit", lambda store, config, root: AUDIT)
    outcome = runner.execute(store, None, claimed, clock=lambda: T0)
    assert outcome.state == "completed"
    assert sorted(str(item["source_kind"]) for item in outcome.findings) == ["secret", "supply_chain"]
    assert assessments.finish(store, claimed, outcome, now_ms=1_000_000_001)


def test_runner_hands_the_native_scan_a_stable_per_install_key(tmp_path: Path, monkeypatch) -> None:
    store, claimed = queued_run(tmp_path)
    keys: list[object] = []

    def snapshot(
        root: Path,
        *,
        mode: str = "content",
        secrets: bool = False,
        secret_key: str | None = None,
        skills: bool = False,
        hooks: bool = False,
        plugins: bool = False,
    ):
        if secrets:
            keys.append(secret_key)
        return replace(SNAPSHOT, secrets=secrets_result(native_finding()))

    monkeypatch.setattr(runner, "workspace_snapshot", snapshot)
    monkeypatch.setattr(runner, "_local_audit", lambda store, config, root: AUDIT)
    first = runner.execute(store, None, claimed, clock=lambda: T0)
    runner.execute(store, None, claimed, clock=lambda: T0)
    assert len(keys) == 2 and keys[0] == keys[1]
    assert isinstance(keys[0], str) and len(keys[0]) >= 32
    assert keys[0] not in json.dumps(first.coverage) + json.dumps(list(first.findings))
    assert keys[0] == secret_findings.load_fingerprint_key(store, "2026-10-24T00:00:00Z")


def test_older_runtime_falls_back_and_reports_the_detector_not_run(tmp_path: Path, monkeypatch) -> None:
    store, claimed = queued_run(tmp_path)
    requested: list[bool] = []

    def snapshot(
        root: Path,
        *,
        mode: str = "content",
        secrets: bool = False,
        secret_key: str | None = None,
        skills: bool = False,
        hooks: bool = False,
        plugins: bool = False,
    ) -> native.WorkspaceSnapshot:
        requested.append(secrets)
        if secrets:
            raise native.WorkspaceSnapshotError("workspace_snapshot_secrets_unavailable")
        return SNAPSHOT

    monkeypatch.setattr(runner, "workspace_snapshot", snapshot)
    monkeypatch.setattr(runner, "_local_audit", lambda store, config, root: AUDIT)
    outcome = runner.execute(store, None, claimed, clock=lambda: T0)
    assert requested == [True, False, False]
    assert outcome.state == "partial"
    assert outcome.coverage is not None
    assert outcome.coverage["reasons"] == [
        "detector_not_run:secrets",
        "detector_not_run:skill_content_v1",
        "detector_not_run:hook_config_v1",
        "detector_not_run:plugin_manifest_v1",
    ]
    assert outcome.coverage["detectors"]["secrets"] == "not_run"


def test_merged_findings_stay_bounded_and_most_severe_first() -> None:
    many = [
        secret_findings.project_secret_findings(
            secrets_result(
                native_finding(
                    finding_id=f"{index:032x}",
                    fingerprint=f"{index:032x}",
                    severity="low" if index else "critical",
                )
            ),
        )[0]
        for index in range(runner.MAX_FINDINGS + 20)
    ]
    packages, _ = runner.project_supply_chain_findings(KEYS.worktree_key, AUDIT)
    merged, truncated = runner.merge_findings(packages, many)
    assert truncated is True
    assert len(merged) == runner.MAX_FINDINGS
    assert [item["severity"] for item in merged[:2]] == ["critical", "critical"]


def plant_workspace(root: Path) -> None:
    (root / "src").mkdir(parents=True)
    (root / "src/deploy.py").write_text(f"import os\nGH_TOKEN = {GITHUB_TOKEN}\n", encoding="utf-8")
    (root / "settings.yaml").write_text(f"name: app\naws_access_key_id: {AWS_KEY}\n", encoding="utf-8")
    # Credential stores hold the same values but are never read by the scan.
    (root / ".env").write_text(f"GH_TOKEN={GITHUB_TOKEN}\n", encoding="utf-8")
    (root / "server.pem").write_text(f"{GITHUB_TOKEN}\n", encoding="utf-8")


BENIGN_FILES = {
    "ids.json": '{"request_id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301"}\n',
    "package-lock.json": (
        '{"integrity": "sha512-Zq0m3sT8kQeWw1Hn5y9bQ2sXk7mVdP4aLr6uYc0tJf1gN8oRhEiBvDxUaCwMlK2Zp3y5q9A=="}\n'
    ),
    "yarn.lock": 'resolved "https://registry.example.test/a/-/a-1.0.0.tgz#da39a3ee5e6b4b0d3255bfef95601890afd80709"\n',
    "config.example.yaml": "api_key: YOUR_API_KEY\nsecret_token: changeme\n",
    "README.md": "Set `API_KEY` to YOUR_API_KEY before running.\n",
    "tests/auth.test.js": "expect(login({ password: 'fake-password-value' })).toBe(false);\n",
    "src/main.rs": 'fn main() {\n    let token = std::env::var("API_TOKEN");\n}\n',
}


def run_assessment(
    tmp_path: Path, workspace: Path, store: GuardStore | None = None
) -> tuple[GuardStore, dict[str, object]]:
    store = store or GuardStore(tmp_path / "guard-home")
    admitted = worker.admit_workspace(store, str(workspace))
    keys = assessments.WorktreeKeys(str(admitted["codebase_key"]), str(admitted["worktree_key"]))
    assert worker.queue_manual_run(store, keys) == admitted["run_id"]
    assert runner.run_next(store, load_guard_config(store.guard_home), owner="test")
    [latest] = assessments.latest_assessed_runs(store)
    return store, latest


def test_planted_secrets_are_reported_without_their_values(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, capfd: pytest.CaptureFixture[str], native_binary: None
) -> None:
    workspace = tmp_path / "workspace"
    plant_workspace(workspace)
    caplog.set_level(logging.DEBUG)
    store, latest = run_assessment(tmp_path, workspace)
    secrets = [item for item in latest["findings"] if item["source_kind"] == "secret"]
    assert {(item["path"], item["rule_ids"][0]) for item in secrets} == {
        ("src/deploy.py", "github-token"),
        ("settings.yaml", "aws-access-key"),
    }
    assert {item["path"]: item["line"] for item in secrets} == {"src/deploy.py": 2, "settings.yaml": 2}
    assert all(item["validation_state"] == "unvalidated" and item["detector"] == "secrets" for item in secrets)
    assert latest["coverage"]["detectors"]["secrets"] == "complete"
    assert latest["coverage"]["secrets"]["skipped"]["credential_store"] >= 2
    assert "detector_not_run:secrets" not in latest["coverage"]["reasons"]
    with sqlite3.connect(store.guard_home / "guard.db") as connection:
        stored = " ".join(
            str(value) for row in connection.execute("select * from workspace_assessment_runs") for value in row
        )
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        served = []
        for path in ("/v1/supply-chain/workspace-findings", "/v1/supply-chain/workspace-assessments"):
            status, body = _read_json_response(_request(daemon.port, path, method="GET", token=token))
            assert status == 200
            served.append(json.dumps(body))
    finally:
        daemon.stop()
    observed = capfd.readouterr()
    surfaces = [json.dumps(latest), stored, *served, caplog.text, observed.out, observed.err]
    assert any("src/deploy.py" in surface for surface in surfaces[:3])
    for surface in surfaces:
        for value in (GITHUB_TOKEN, AWS_KEY):
            # No whole value and no fragment long enough to identify it.
            assert value not in surface
            assert value[4:] not in surface
            assert value[:-6] not in surface


def test_benign_files_produce_no_findings(tmp_path: Path, native_binary: None) -> None:
    workspace = tmp_path / "workspace"
    for name, body in BENIGN_FILES.items():
        path = workspace / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    _, latest = run_assessment(tmp_path, workspace)
    assert [item for item in latest["findings"] if item["source_kind"] == "secret"] == []
    assert latest["coverage"]["detectors"]["secrets"] == "complete"
    assert latest["coverage"]["secrets"]["files_scanned"] >= len(BENIGN_FILES)


def test_a_repeated_secret_keeps_every_line_end_to_end(tmp_path: Path, native_binary: None) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "config.py").write_text(f"A = {GITHUB_TOKEN}\nB = 1\nC = {GITHUB_TOKEN}\n", encoding="utf-8")
    _, latest = run_assessment(tmp_path, workspace)
    [finding] = [item for item in latest["findings"] if item["source_kind"] == "secret"]
    assert (finding["line"], finding["lines"], finding["occurrences"]) == (1, [1, 3], 2)
    assert GITHUB_TOKEN not in json.dumps(latest)


def test_finding_identity_survives_a_rescan_and_a_moved_line(tmp_path: Path, native_binary: None) -> None:
    workspace = tmp_path / "workspace"
    plant_workspace(workspace)
    store, first = run_assessment(tmp_path, workspace)
    deploy = workspace / "src/deploy.py"
    deploy.write_text("# moved down\n" + deploy.read_text(encoding="utf-8"), encoding="utf-8")
    _, second = run_assessment(tmp_path, workspace, store)

    def ids(latest: dict[str, object]) -> dict[str, tuple[object, ...]]:
        return {
            str(item["finding_id"]): (item["path"], item["line"])
            for item in latest["findings"]  # type: ignore[attr-defined]
            if item["source_kind"] == "secret"
        }

    before, after = ids(first), ids(second)
    assert before.keys() == after.keys() and len(before) == 2
    assert before != after
