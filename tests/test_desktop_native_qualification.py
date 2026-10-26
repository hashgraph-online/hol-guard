"""The updater qualification contract requires native proof and retirement."""

import argparse
import io
import json
import os
import sys
import time
import uuid

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli import desktop_qualification as qualification
from codex_plugin_scanner.guard.codex_hook_launch_runtime import run_isolated_hook_process
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.native_resident_client import close_native_residents
from codex_plugin_scanner.guard.runtime_transition import TransitionError
from codex_plugin_scanner.guard.store import GuardStore


@pytest.fixture
def candidate(tmp_path, monkeypatch):
    home = tmp_path / ("preflight-home-" + str(uuid.uuid4()))
    home.mkdir(mode=0o700)
    monkeypatch.setenv("HOL_GUARD_DESKTOP_PREFLIGHT", "1")
    store = GuardStore(home)
    context = HarnessContext(home, None, home, {})
    args = argparse.Namespace(
        operation_id=str(uuid.uuid4()), artifact_generation="a" * 64, deadline_epoch=time.time() + 10
    )
    return args, context, store


@pytest.mark.usefixtures("native_hook_force")
@pytest.mark.parametrize("incomplete_cleanup", [False, True])
def test_qualification_requires_real_native_proof_and_owned_cleanup(candidate, monkeypatch, incomplete_cleanup):
    args, context, store = candidate
    output = io.StringIO()
    workers = []

    def create_worker(**kwargs):
        worker = HookWorker(**kwargs)
        workers.append(worker)
        if incomplete_cleanup:
            original = worker.close

            def close(**kwargs):
                original(**kwargs)
                return False

            worker.close = close
        return worker

    monkeypatch.setattr(qualification, "HookWorker", create_worker)
    try:
        result = qualification.run_desktop_qualification(args, context=context, store=store, output_stream=output)
        document = json.loads(output.getvalue())
        assert result == (2 if incomplete_cleanup else 0)
        assert document["qualified"] is not incomplete_cleanup
        assert document["cleanup_complete"] is not incomplete_cleanup
        assert document["schema"] == qualification.CANDIDATE_QUALIFICATION_SCHEMA
        assert document["operation_id"] == args.operation_id
        assert document["generation"] == args.artifact_generation
        assert document["native_admission"]["allow_receipt"]["authority"] == "rust"
        assert document["native_admission"]["allow_receipt"]["decision"] == "allow"
        assert document["native_admission"]["deny_receipt"]["decision"] == "deny"
        assert context.guard_home.exists()
        if incomplete_cleanup:
            assert document["reason_code"] == "qualification_cleanup_incomplete"
    finally:
        for worker in workers:
            HookWorker.close(worker, deadline_monotonic=time.monotonic() + 3)
        assert close_native_residents(store.guard_home, deadline_monotonic=time.monotonic() + 3)


@pytest.mark.parametrize("fault", ["expired", "not_isolated", "wrong_generation"])
def test_invalid_qualification_starts_no_worker(candidate, monkeypatch, fault):
    args, context, store = candidate
    if fault == "expired":
        args.deadline_epoch = time.time() - 1
    elif fault == "not_isolated":
        monkeypatch.delenv("HOL_GUARD_DESKTOP_PREFLIGHT")
    else:
        args.artifact_generation = "unbound"

    def forbidden_worker(**kwargs):
        raise AssertionError("invalid qualification started a worker")

    monkeypatch.setattr(qualification, "HookWorker", forbidden_worker)
    output = io.StringIO()
    assert qualification.run_desktop_qualification(args, context=context, store=store, output_stream=output) == 2
    document = json.loads(output.getvalue())
    assert document["qualified"] is False and document["cleanup_complete"] is True
    assert "native_admission" not in document


@pytest.mark.usefixtures("native_hook_force")
def test_actual_cli_child_qualifies_and_retires_its_isolated_native_runtime(candidate):
    args, context, _store = candidate
    budget = 30
    args.deadline_epoch = time.time() + budget
    deadline = time.monotonic() + budget
    environment = dict(os.environ)
    environment.update(
        HOME=str(context.home_dir),
        USERPROFILE=str(context.home_dir),
        HOL_GUARD_HOME=str(context.guard_home),
        HOL_GUARD_DESKTOP_PREFLIGHT="1",
    )
    result = run_isolated_hook_process(
        [
            sys.executable,
            "-c",
            "import os,sys; os.environ['HOL_GUARD_DESKTOP_PREFLIGHT']='1'; "
            "sys.argv[0]='hol-guard'; from codex_plugin_scanner.cli import main; "
            "raise SystemExit(main())",
            "desktop",
            "qualify",
            "--json",
            "--operation-id",
            args.operation_id,
            "--artifact-generation",
            args.artifact_generation,
            "--deadline-epoch",
            str(args.deadline_epoch),
            "--guard-home",
            str(context.guard_home),
            "--home",
            str(context.home_dir),
        ],
        input_text="",
        cwd=context.home_dir,
        environment=environment,
        deadline_monotonic=deadline,
    )
    assert not result.timed_out and not result.containment_failed
    document = json.loads(result.stdout)
    assert result.returncode == 0, (document.get("reason_code"), result.stderr)
    assert document["qualified"] is True and document["cleanup_complete"] is True
    assert document["operation_id"] == args.operation_id
    assert document["native_admission"]["allow_receipt"]["decision"] == "allow"
    assert document["native_admission"]["deny_receipt"]["decision"] == "deny"


@pytest.mark.usefixtures("native_hook_force")
def test_qualification_preserves_probe_cause_when_both_cleanup_steps_fail(candidate, monkeypatch):
    args, context, store = candidate
    workers, deadlines = [], []

    def create_worker(**kwargs):
        worker = HookWorker(**kwargs)
        workers.append(worker)

        def close(*, deadline_monotonic):
            deadlines.append(deadline_monotonic)
            raise OSError("fixture cleanup failure")

        worker.close = close
        return worker

    def failed_probe(**kwargs):
        deadlines.append(kwargs["deadline_monotonic"])
        raise TransitionError("admission_protection_failed")

    def failed_resident_close(home, *, deadline_monotonic):
        deadlines.append(deadline_monotonic)
        raise OSError("fixture resident cleanup failure")

    monkeypatch.setattr(qualification, "HookWorker", create_worker)
    monkeypatch.setattr(qualification, "probe_native_protection", failed_probe)
    monkeypatch.setattr(qualification, "close_native_residents", failed_resident_close)
    output = io.StringIO()
    try:
        assert qualification.run_desktop_qualification(args, context=context, store=store, output_stream=output) == 2
        document = json.loads(output.getvalue())
        assert document["qualified"] is False and document["cleanup_complete"] is False
        assert document["reason_code"] == "admission_protection_failed"
        assert document["cleanup_reason_codes"] == [
            "qualification_publisher_cleanup_failed",
            "qualification_resident_cleanup_failed",
        ]
        assert len(deadlines) == 3 and len(set(deadlines)) == 1
    finally:
        for worker in workers:
            HookWorker.close(worker, deadline_monotonic=time.monotonic() + 3)
