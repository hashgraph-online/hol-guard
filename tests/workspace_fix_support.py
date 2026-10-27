"""Shared fixtures for the workspace fix proposal tests."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import workspace_assessment_store as assessments
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.workspace_assessment_reads import _run_payload


def admit_worktree(
    store: GuardStore, keys: assessments.WorktreeKeys, *, root: str, now_ms: int, resume: bool = True
) -> bool:
    """Admit a worktree; ``resume`` also unpauses one admitted before.

    Without ``resume`` an already admitted worktree is left exactly as it is and
    the call returns False, so an automatic admission never undoes a pause.
    """

    conflict = "update set private_root = excluded.private_root, paused = 0" if resume else "nothing"
    with store._connect() as connection:
        cursor = connection.execute(
            f"""
            insert into workspace_assessment_state (codebase_key, worktree_key, private_root, admitted_at_ms)
            values (?, ?, ?, ?)
            on conflict(codebase_key, worktree_key) do {conflict}
            """,
            (keys.codebase_key, keys.worktree_key, root, now_ms),
        )
        return cursor.rowcount == 1


@pytest.fixture
def native_binary() -> None:
    """Fix planning and applying run in the compiled runtime, so these tests need it."""

    if not Path(os.environ.get("HOL_GUARD_NATIVE_BINARY") or "").is_file():
        pytest.skip("needs HOL_GUARD_NATIVE_BINARY for the compiled runtime")


DETECTORS = "d" * 64
T0 = 1_000_000_000
FINDING_ID = "f" * 32

# Quoted braces, an escaped quote, nested arrays and a nested object that reuses
# the package name all sit before and around the real declarations.
MANIFEST = """{
    "name": "demo \\"quoted\\" {app}",
    "version": "1.0.0",
    "scripts": {"echo": "echo \\"}\\" && true", "lint": "x"},
    "files": ["a", "b"],
    "config": {"n": [1, 2.5e3, null, true, {"minimist": "^1.2.0"}]},
    "dependencies": {
        "other": "^1.2.0",
        "minimist": "^1.2.0"
    },
    "devDependencies": {"minimist": "~1.2.0"}
}"""
FIXED_MANIFEST = MANIFEST.replace('"minimist": "^1.2.0"\n    },', '"minimist": "^1.2.9"\n    },').replace(
    '{"minimist": "~1.2.0"}', '{"minimist": "~1.2.9"}'
)

COMPLETE_SUPPLY_CHAIN = {
    "status": "partial",
    # The secrets detector does not exist yet, so every real run lists this.
    "reasons": ["detector_not_run:secrets"],
    "detectors": {"supply_chain": "complete", "secrets": "not_run"},
}


def digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


KEYS = assessments.WorktreeKeys(digest("codebase"), digest("worktree"))


def finding(**overrides: object) -> dict[str, object]:
    return {
        "finding_id": FINDING_ID,
        "source_kind": "supply_chain",
        "ecosystem": "npm",
        "package_name": "minimist",
        "package_version": "1.2.8",
        "fix_version": "1.2.9",
        "rule_ids": ["known-malicious"],
        "advisory_ids": ["GHSA-demo-0001"],
        **overrides,
    }


def write_manifest(directory: Path, text: str = MANIFEST) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "package.json"
    # CRLF and no trailing newline: both must survive an edit byte for byte.
    path.write_bytes(text.replace("\n", "\r\n").encode("utf-8"))
    return path


def seeded_store(tmp_path: Path, root: Path) -> GuardStore:
    store = GuardStore(tmp_path / "home")
    admit_worktree(store, KEYS, root=str(root), now_ms=T0)
    return store


def assess(
    store: GuardStore,
    *,
    snapshot: str,
    at: int,
    findings: list[dict[str, object]] | None = None,
    coverage: dict[str, object] | None = None,
) -> str:
    """Run one manual assessment to the end the way the worker would."""

    run_id = assessments.enqueue(store, KEYS, trigger_kind="manual", detector_set_digest=DETECTORS, now_ms=at)
    claimed = assessments.claim_next(store, owner="test", now_ms=at)
    assert claimed is not None and claimed.run_id == run_id
    outcome = assessments.RunOutcome(
        state="partial",
        snapshot_digest=digest(snapshot),
        coverage=coverage if coverage is not None else COMPLETE_SUPPLY_CHAIN,
        findings=[finding()] if findings is None else findings,
    )
    assert assessments.finish(store, claimed, outcome, now_ms=at + 1)
    return str(run_id)


def get_run(store: GuardStore, run_id: str) -> dict[str, object] | None:
    with store._connect() as connection:
        row = connection.execute(
            """
            select run_id, codebase_key, worktree_key, snapshot_digest, kind, trigger_kind, state,
                   dirty_generation, coverage_json, findings_json, error_code,
                   created_at_ms, started_at_ms, finished_at_ms
            from workspace_assessment_runs where run_id = ?
            """,
            (run_id,),
        ).fetchone()
    return _run_payload(row) if row is not None else None
