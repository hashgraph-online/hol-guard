"""Explicit app repair prepares before proof and reports native completion."""

import argparse
import base64
import hashlib
import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.approval_gate import ApprovalGateInput
from codex_plugin_scanner.guard.cli import codex_authority_repair as command
from codex_plugin_scanner.guard.cli import run_guard_command
from codex_plugin_scanner.guard.cli.commands_lifecycle_gate import lifecycle_gate_requirement
from codex_plugin_scanner.guard.cli.commands_parser import add_guard_root_parser
from codex_plugin_scanner.guard.codex_hook_integrity import hook_secret_path
from codex_plugin_scanner.guard.codex_hook_recovery import hook_publication_pending
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.native_resident_client import close_native_residents
from codex_plugin_scanner.guard.sqlite_tuning import sqlite_operation_deadline_monotonic
from codex_plugin_scanner.guard.store import GuardStore

from .test_codex_hook_recovery import installed  # noqa: F401 -- shared fixture
from .test_codex_hook_repair_authorization import PASSWORD, prepared_repair  # noqa: F401 -- shared fixture
from .test_codex_publication_preparation import _tree


def _args(*extra):
    parser = argparse.ArgumentParser()
    add_guard_root_parser(parser)
    return parser.parse_args(["apps", "repair", "codex", "--restore-authority", "--json", *extra])


def _tree_without_resident_lease_state(root):
    # A live resident client creates its lease file and then writes it, so a snapshot can
    # land between the two. Keep the lease path, mode and inode; ignore its time and body.
    tree = _tree(root)
    for relative_path, metadata in tree.items():
        path = Path(relative_path)
        if (
            path.parent.name == "resident-client-leases.v1"
            and path.parent.parent.name == "native-runtime"
            and path.name.startswith("client-")
            and path.suffix == ".lease"
        ):
            tree[relative_path] = (*metadata[:2], None, None)
    return tree


def test_only_explicit_restore_path_defers_to_exact_gate():
    explicit = _args()
    assert lifecycle_gate_requirement(explicit) is None
    explicit.restore_authority = False
    requirement = lifecycle_gate_requirement(explicit)
    assert requirement is not None
    assert requirement.action == "apps.repair"
    assert requirement.subject == "codex"


@pytest.mark.parametrize("deadline", ["nan", "inf", "-inf", "0", "expired", "too-long"])
def test_parent_deadline_refuses_before_preparation_or_factors(
    prepared_repair,
    monkeypatch,
    deadline,
):
    context, _config, manifest, _plan = prepared_repair
    store = GuardStore(context.guard_home)
    value = {"expired": str(time.time() - 1), "too-long": str(time.time() + 90)}.get(deadline, deadline)

    def forbidden(*args, **kwargs):
        raise AssertionError("expired parent budget reached preparation or authentication")

    monkeypatch.setattr(command, "prepare_authenticated_hook_manifest_repair", forbidden)
    monkeypatch.setattr(command, "consume_desktop_lifecycle_env", forbidden)
    code, payload = command.run_codex_authority_repair(
        _args("--authority-deadline-epoch=" + value, "--dry-run"),
        context,
        store,
        None,
    )
    assert code == 2
    assert payload["error"] == "authority_repair_deadline_invalid"
    assert payload["verified"] is False
    assert not manifest.exists()


def test_deadline_flag_alone_cannot_fall_through_to_generic_repair(prepared_repair, monkeypatch):  # noqa: F811
    context, _config, manifest, _plan = prepared_repair
    args = _args("--authority-deadline-epoch", str(time.time() + 20))
    args.restore_authority = False
    assert lifecycle_gate_requirement(args) is None
    code, payload = command.run_codex_authority_repair(args, context, GuardStore(context.guard_home), None)
    assert code == 2
    assert payload["error"] == "authority_repair_restore_flag_required"
    assert not manifest.exists()


@pytest.mark.usefixtures("native_hook_force")
def test_approval_prompt_does_not_restart_expired_parent_budget(prepared_repair, monkeypatch):  # noqa: F811
    context, config, manifest, _plan = prepared_repair
    store = GuardStore(context.guard_home)
    before_config = config.read_bytes()
    now = time.monotonic()
    epoch = time.time()
    observed = []
    monkeypatch.setattr(command, "time", SimpleNamespace(monotonic=lambda: now, time=lambda: epoch))
    original_inspect = command.inspect_codex_repair_native_runtime

    def inspect(*, deadline_monotonic):
        observed.append(deadline_monotonic)
        assert sqlite_operation_deadline_monotonic() == deadline_monotonic
        return original_inspect(deadline_monotonic=deadline_monotonic)

    def expire_during_prompt(*args, **kwargs):
        nonlocal now
        now += 11
        return ApprovalGateInput(password=PASSWORD)

    def forbidden(*args, **kwargs):
        raise AssertionError("expired parent budget reached grant authentication")

    monkeypatch.setattr(command, "inspect_codex_repair_native_runtime", inspect)
    monkeypatch.setattr(command, "consume_desktop_lifecycle_env", lambda **kwargs: None)
    monkeypatch.setattr(command, "prompt_for_approval_gate", expire_during_prompt)
    monkeypatch.setattr(command, "require_high_risk", forbidden)
    code, payload = command.run_codex_authority_repair(
        _args("--authority-deadline-epoch", str(epoch + 10)),
        context,
        store,
        None,
    )
    assert len(observed) == 1
    assert observed[0] == pytest.approx(now - 1)
    assert code == 2
    assert payload["error"] == "authority_repair_deadline_exceeded"
    assert not manifest.exists()
    assert config.read_bytes() == before_config
    assert not hook_publication_pending(context.guard_home)
    assert sqlite_operation_deadline_monotonic() is None


@pytest.mark.usefixtures("native_hook_force")
def test_dry_run_prepares_without_factors_or_publication(prepared_repair, tmp_path, monkeypatch):  # noqa: F811
    context, _config, manifest, _plan = prepared_repair
    store = GuardStore(context.guard_home)
    before = _tree_without_resident_lease_state(tmp_path)
    factors = []
    monkeypatch.setattr(command, "consume_desktop_lifecycle_env", lambda **kwargs: factors.append(kwargs))
    code, payload = command.run_codex_authority_repair(_args("--dry-run"), context, store, None)
    assert code == 0
    assert payload["status"] == "prepared"
    assert payload["verified"] is False
    assert factors == []
    assert not manifest.exists()
    assert _tree_without_resident_lease_state(tmp_path) == before


@pytest.mark.usefixtures("native_hook_force")
@pytest.mark.parametrize("proof", ["absent", "incorrect"])
def test_refused_authentication_preserves_missing_authority(prepared_repair, monkeypatch, proof):  # noqa: F811
    context, config, manifest, _plan = prepared_repair
    before_config = config.read_bytes()
    key_metadata = hook_secret_path(context.guard_home).stat()
    store = GuardStore(context.guard_home)
    monkeypatch.setattr(command, "consume_desktop_lifecycle_env", lambda **kwargs: None)
    if proof == "incorrect":
        monkeypatch.setattr(
            command,
            "prompt_for_approval_gate",
            lambda *args, **kwargs: ApprovalGateInput(password="wrong generated password"),
        )
    code, payload = command.run_codex_authority_repair(_args(), context, store, None)
    assert code == 2
    assert payload["status"] == "failed"
    assert payload["verified"] is False
    assert str(payload["error"]).startswith("approval_gate_")
    assert not manifest.exists()
    assert config.read_bytes() == before_config
    after = hook_secret_path(context.guard_home).stat()
    assert (after.st_ino, after.st_size, after.st_mtime_ns) == (
        key_metadata.st_ino,
        key_metadata.st_size,
        key_metadata.st_mtime_ns,
    )
    assert not hook_publication_pending(context.guard_home)


@pytest.mark.parametrize("journal", ["runtime-transition.json", "codex/pending-hook-publication.json"])
def test_existing_inverse_reports_recovery_required_before_factors(prepared_repair, monkeypatch, journal):  # noqa: F811
    context, _config, manifest, _plan = prepared_repair
    store = GuardStore(context.guard_home)
    pending_path = context.guard_home / "managed" / journal
    pending_path.write_bytes(b"isolated existing recovery journal")
    factors = []
    monkeypatch.setattr(command, "consume_desktop_lifecycle_env", lambda **kwargs: factors.append(kwargs))
    code, payload = command.run_codex_authority_repair(_args(), context, store, None)
    assert code == 2
    assert payload["status"] == "recovery-required"
    assert payload["recovery_required"] is True
    assert payload["verified"] is False
    assert factors == []
    assert not manifest.exists()
    assert pending_path.read_bytes() == b"isolated existing recovery journal"


@pytest.mark.usefixtures("native_hook_force")
def test_public_apps_repair_uses_exact_plan_and_real_native_protection(
    prepared_repair,
    monkeypatch,
    capsys,
):
    context, config, manifest, _plan = prepared_repair
    store = GuardStore(context.guard_home)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0, home_dir=context.home_dir)
    prepared = []
    original_prepare = command.prepare_codex_hook_repair_verification

    def capture_plan(*args, **kwargs):
        plan = original_prepare(*args, **kwargs)
        prepared.append(plan)
        return plan

    def factor_after_preparation(*args, **kwargs):
        assert len(prepared) == 1
        assert prepared[0].native_runtime is not None
        assert not manifest.exists()
        assert prepared[0].subject() in kwargs["summary"]
        assert prepared[0].native_runtime.sha256 in kwargs["summary"]
        assert str(manifest) in kwargs["summary"]
        return ApprovalGateInput(password=PASSWORD)

    monkeypatch.setattr(command, "prepare_codex_hook_repair_verification", capture_plan)
    monkeypatch.setattr(command, "consume_desktop_lifecycle_env", lambda **kwargs: None)
    monkeypatch.setattr(command, "prompt_for_approval_gate", factor_after_preparation)
    daemon.start()
    try:
        config_before = config.read_bytes()
        code = run_guard_command(_args())
        output = json.loads(capsys.readouterr().out)
        assert code == 0, output
        assert output["status"] == "verified"
        assert output["verified"] is True
        assert output["recovery_required"] is False
        assert manifest.read_bytes() == prepared[0].manifest_change.after
        assert config.read_bytes() == config_before
        assert not hook_publication_pending(context.guard_home)
        assert PASSWORD not in json.dumps(output)
    finally:
        daemon.stop()
        close_native_residents()


@pytest.mark.usefixtures("native_hook_force")
def test_captured_request_apply_does_not_prepare_under_collected_factors(
    prepared_repair,
    tmp_path,
    monkeypatch,
    capsys,
):
    context, _config, manifest, _plan = prepared_repair
    store = GuardStore(context.guard_home)
    folder = tmp_path / "private-desktop-review"
    folder.mkdir(mode=0o700)
    path = folder / "request.json"
    code = run_guard_command(_args("--dry-run", "--authority-request", str(path)))
    prepared = json.loads(capsys.readouterr().out)
    assert code == 0 and prepared["status"] == "prepared"
    assert prepared["request_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert prepared["subject"] == json.loads(path.read_bytes())["subject"]
    assert not manifest.exists()

    def forbid_preparation(*args, **kwargs):
        raise AssertionError("Captured request must not regenerate its plan or native inspection")

    monkeypatch.setattr(command, "prepare_authenticated_hook_manifest_repair", forbid_preparation)
    monkeypatch.setattr(command, "inspect_codex_repair_native_runtime", forbid_preparation)
    monkeypatch.setattr(command, "prepare_codex_hook_repair_verification", forbid_preparation)
    monkeypatch.setattr(command, "consume_desktop_lifecycle_env", lambda **kwargs: ApprovalGateInput(password=PASSWORD))
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0, home_dir=context.home_dir)
    daemon.start()
    try:
        code = run_guard_command(
            _args("--authority-request", str(path), "--authority-request-sha256", str(prepared["request_sha256"]))
        )
        result = json.loads(capsys.readouterr().out)
        assert code == 0, result
        assert result["status"] == "verified" and result["verified"] is True
        assert result["operation_id"] == prepared["operation_id"]
        assert result["native_runtime_sha256"] == json.loads(path.read_bytes())["plan"]["native_runtime"]["sha256"]
        assert manifest.exists()
        assert not hook_publication_pending(context.guard_home)
    finally:
        daemon.stop()
        close_native_residents()


@pytest.mark.usefixtures("native_hook_force")
def test_changed_captured_dependency_refuses_before_factor_consumption(
    prepared_repair,
    tmp_path,
    monkeypatch,
):
    context, config, manifest, _plan = prepared_repair
    store = GuardStore(context.guard_home)
    folder = tmp_path / "private-desktop-review"
    folder.mkdir(mode=0o700)
    path = folder / "request.json"
    code, prepared = command.run_codex_authority_repair(
        _args("--dry-run", "--authority-request", str(path)),
        context,
        store,
        None,
    )
    assert code == 0
    foreign = config.read_bytes() + b"\n# newer generation during review\n"
    config.write_bytes(foreign)
    factors = []
    monkeypatch.setattr(command, "consume_desktop_lifecycle_env", lambda **kwargs: factors.append(kwargs))
    code, result = command.run_codex_authority_repair(
        _args("--authority-request", str(path), "--authority-request-sha256", str(prepared["request_sha256"])),
        context,
        store,
        None,
    )
    assert code == 2 and result["verified"] is False
    assert factors == []
    assert config.read_bytes() == foreign
    assert not manifest.exists()


@pytest.mark.usefixtures("native_hook_force")
def test_verification_workspace_does_not_change_signed_installation_context(
    prepared_repair,
    tmp_path,
    capsys,
):
    _context, _config, manifest, _plan = prepared_repair
    folder = tmp_path / "private-review-context"
    folder.mkdir(mode=0o700)
    workspace = tmp_path / "native-verification-workspace"
    workspace.mkdir(mode=0o700)
    request = folder / "request.json"
    code = run_guard_command(
        _args("--dry-run", "--authority-request", str(request), "--authority-verification-workspace", str(workspace))
    )
    output = capsys.readouterr()
    result = json.loads(output.out)
    assert code == 0, result
    stages = [
        json.loads(line.removeprefix("guard_runtime_stage "))
        for line in output.err.splitlines()
        if line.startswith("guard_runtime_stage ")
    ]
    started = [entry["stage"] for entry in stages if entry["phase"] == "started"]
    finished = [entry["stage"] for entry in stages if entry["phase"] == "finished"]
    assert started == finished == ["control", "plan_preparation", "request_capture"]
    assert all(set(entry) == {"stage", "phase", "elapsed_ms", "duration_ms"} for entry in stages)
    assert all(0 <= entry["duration_ms"] <= entry["elapsed_ms"] for entry in stages)
    assert str(tmp_path) not in output.err
    captured = json.loads(request.read_bytes())["plan"]
    assert captured["verification_workspace"] == str(workspace.resolve())
    binding = next(item for item in captured["files"] if item["kind"] == "binding")
    signed_manifest = json.loads(base64.b64decode(binding["after"], validate=True))
    assert signed_manifest["context"]["workspace_dir"] is None
    assert result["status"] == "prepared" and result["verified"] is False
    assert not manifest.exists()


def test_verification_flag_alone_cannot_borrow_generic_repair_approval(prepared_repair):  # noqa: F811
    context, _config, manifest, _plan = prepared_repair
    args = _args("--authority-verification-workspace", str(context.home_dir))
    args.restore_authority = False
    assert lifecycle_gate_requirement(args) is None
    code, result = command.run_codex_authority_repair(args, context, GuardStore(context.guard_home), None)
    assert code == 2 and result["error"] == "authority_repair_restore_flag_required"
    assert not manifest.exists()
