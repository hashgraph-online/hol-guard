"""Private bounded evidence survives semantic failure without retaining input."""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from scripts import native_slo_registered_surfaces_evidence as journal
from scripts import native_slo_registered_surfaces_run as runner
from scripts.native_slo_registered_surfaces import RegisteredSurface


def test_failure_keeps_prior_success_and_attempted_exit_without_exception_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from scripts.native_slo_workloads import QualificationCase

    path = tmp_path / "evidence.jsonl"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    surface = RegisteredSurface(
        "cursor", "afterShellExecution", "global", (), (), workspace, tmp_path / "hooks.json", "a" * 64
    )
    pending: dict[str, object] = {}

    class Metrics:
        def snapshot(self) -> dict[str, object]:
            return {"routes": {"native_resident": len(pending)}}

    def control(operation: str, **_kwargs: object) -> dict[str, object]:
        if operation == "case_before":
            return {}
        case = pending["case"]
        assert isinstance(case, QualificationCase) and case.native_expected is not None
        return {
            "setup": {"isolated_store": True, "effective_policy_allow": True, "policy_ack_current": True},
            "native_result": dict(case.native_expected.fields),
        }

    def observe(*args: object, attempt: journal.SurfaceAttempt) -> tuple[dict[str, object], float]:
        if pending:
            attempt.stage = "delivery"
            attempt.attempted_exit = 2
            raise AssertionError("raw stdout secret must never be persisted")
        pending["case"] = args[-1]
        attempt.attempted_exit = 0
        return {"stdout_checked": True, "exit_checked": True}, 1.0

    session = cast(
        runner.SurfaceSession,
        cast(
            object,
            SimpleNamespace(
                root=tmp_path,
                workspace=workspace,
                guard_home=tmp_path / "guard-home",
                control=control,
                daemon=SimpleNamespace(_server=SimpleNamespace(hook_worker=SimpleNamespace(metrics=Metrics()))),
            ),
        ),
    )
    monkeypatch.setattr(runner, "install_registered_surface", lambda *_args: (surface,))
    monkeypatch.setattr(runner, "observe_registered_surface", observe)
    with pytest.raises(AssertionError, match="raw stdout"):
        runner.run_registered_surface_corpus(session, harnesses=("cursor",), evidence_file=path)
    raw = path.read_text()
    assert "secret" not in raw and "stdout" not in raw
    records = [json.loads(line) for line in raw.splitlines()]
    assert [item["status"] for item in records] == ["offered", "completed", "offered", "failed"]
    assert records[-1]["attempted_exit"] == 2
    assert records[-1]["stage"] == "delivery"
    assert records[-1]["route"] is None
    assert records[-1]["case_id"].startswith("global/cursor/afterShellExecution/")
    assert records[-1]["registration_sha256"] == "a" * 64
    if os.name != "nt":
        assert path.stat().st_mode & 0o777 == 0o600


def test_existing_file_or_symlink_is_never_overwritten(tmp_path: Path) -> None:
    path = tmp_path / "retained.jsonl"
    path.write_text("prior evidence\n")
    with pytest.raises(FileExistsError):
        journal.SurfaceEvidence(path)
    assert path.read_text() == "prior evidence\n"
    if os.name != "nt":
        link = tmp_path / "redirect.jsonl"
        link.symlink_to(path)
        with pytest.raises(FileExistsError):
            journal.SurfaceEvidence(link)
        assert path.read_text() == "prior evidence\n"


@pytest.mark.parametrize("kind", ("bytes", "records"))
def test_capacity_is_reserved_for_terminal_record_before_offering(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    if kind == "bytes":
        monkeypatch.setattr(journal, "MAX_EVIDENCE_BYTES", 2 * journal.MAX_RECORD_BYTES)
    else:
        monkeypatch.setattr(journal, "MAX_EVIDENCE_RECORDS", 2)
    path = tmp_path / "limited.jsonl"
    with journal.SurfaceEvidence(path) as evidence:
        evidence.offer("global/cursor/afterShellExecution/benign/1k", "a" * 64)
        evidence.finish("failed", journal.SurfaceAttempt(stage="delivery", attempted_exit=2))
        with pytest.raises(RuntimeError, match="evidence_limit"):
            evidence.offer("global/cursor/afterShellExecution/block/1k", "a" * 64)
    assert len(path.read_text().splitlines()) == 2


def test_unknown_route_is_not_logged_as_arbitrary_text(tmp_path: Path) -> None:
    path = tmp_path / "bounded.jsonl"
    with journal.SurfaceEvidence(path) as evidence:
        evidence.offer("global/cursor/afterShellExecution/block/1k", "a" * 64)
        evidence.finish("failed", journal.SurfaceAttempt(stage="route", route="untrusted secret output"))
    assert json.loads(path.read_text().splitlines()[-1])["route"] is None
    assert "secret" not in path.read_text()


def test_untrusted_stage_and_case_identity_are_rejected(tmp_path: Path) -> None:
    with journal.SurfaceEvidence(tmp_path / "bounded.jsonl") as evidence:
        with pytest.raises(RuntimeError, match="identity_invalid"):
            evidence.offer("payload\nraw", "a" * 64)
        evidence.offer("global/cursor/afterShellExecution/block/1k", "a" * 64)
        with pytest.raises(RuntimeError, match="state_invalid"):
            evidence.finish("failed", journal.SurfaceAttempt(stage="raw exception text"))
        evidence.finish("failed", journal.SurfaceAttempt(stage="setup"))
