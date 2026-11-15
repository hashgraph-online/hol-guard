"""Artifact dependencies hash real large files without copying them into inverses."""

import hashlib
import os
import time
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import runtime_transition as module
from codex_plugin_scanner.guard.codex_hook_file_integrity import describe_regular_file

from .test_runtime_transition import begin, transition  # noqa: F401 -- shared pytest fixture


def _artifact(tmp_path, *, large=False):
    path = tmp_path / "candidate-executable"
    with path.open("wb") as handle:
        for _ in range(144 if large else 2):
            handle.write(b"artifact fixture " * 4096)
    path.chmod(0o755)
    identity = describe_regular_file(path, role="interpreter", executable_required=True)
    return path, identity


def test_large_artifact_is_pinned_by_digest_with_no_snapshot_bytes(tmp_path):
    path, identity = _artifact(tmp_path, large=True)
    assert path.stat().st_size > 4 * 1024 * 1024
    change = module.TransitionFile.artifact_dependency(identity)
    payload = change.payload()
    assert payload["before"] is None and payload["after"] is None
    assert payload["expected_digest"] == identity["sha256"]
    assert len(str(payload)) < 1024
    before = path.stat()
    module.RuntimeTransition._write_file(payload, "after")
    module.RuntimeTransition._write_file(payload, "before")
    assert path.stat() == before


@pytest.mark.skipif(os.name == "nt", reason="POSIX system owner qualification")
def test_root_owned_system_artifact_is_verified_without_changing_authority_rules():
    path = Path("/usr/bin/true").resolve(strict=True)
    identity = describe_regular_file(path, role="interpreter", executable_required=True)
    assert identity["owner_uid"] == 0
    change = module.TransitionFile.artifact_dependency(identity)
    assert change.expected_digest == identity["sha256"]
    assert change.artifact_identity["owner_uid"] == 0


@pytest.mark.skipif(os.name == "nt", reason="POSIX interpreter permission policy")
def test_trusted_group_writable_interpreter_retains_existing_identity_policy(tmp_path):
    path, _identity = _artifact(tmp_path)
    path.chmod(0o775)
    identity = describe_regular_file(path, role="interpreter", executable_required=True)
    before = path.stat()
    change = module.TransitionFile.artifact_dependency(identity)
    module.RuntimeTransition._compare({"files": [change.payload()]}, "after")
    assert path.stat() == before
    assert change.artifact_identity["role"] == "interpreter"


@pytest.mark.skipif(os.name == "nt", reason="POSIX artifact permission policy")
def test_group_writable_package_does_not_gain_interpreter_exception(tmp_path):
    path, _identity = _artifact(tmp_path)
    path.chmod(0o775)
    identity = describe_regular_file(path, role="interpreter", executable_required=True)
    with pytest.raises(module.TransitionError, match="artifact_permissions_invalid"):
        module.TransitionFile.artifact_dependency({**identity, "role": "bridge"})


@pytest.mark.skipif(os.name == "nt", reason="POSIX binding permission policy")
def test_group_writable_binding_remains_forbidden(tmp_path):
    change = module.TransitionFile(tmp_path / "binding", None, b"candidate", after_mode=0o775)
    with pytest.raises(module.TransitionError, match="file_mode_invalid"):
        change.checked()


@pytest.mark.skipif(os.name == "nt", reason="POSIX artifact permission policy")
def test_world_writable_artifact_is_forbidden_even_for_interpreter_role(tmp_path):
    path, identity = _artifact(tmp_path)
    path.chmod(0o777)
    with pytest.raises(module.TransitionError, match="file_mode_invalid"):
        module.TransitionFile.artifact_dependency({**identity, "mode": 0o777})


def test_prior_artifact_record_without_role_preserves_strict_mode_validation(tmp_path):
    path, identity = _artifact(tmp_path)
    payload = module.TransitionFile.artifact_dependency(identity).payload()
    payload["artifact_identity"].pop("role")
    module.check_transition_files([payload])
    module.RuntimeTransition._compare({"files": [payload]}, "before")
    payload["before_mode"] = payload["after_mode"] = 0o775
    with pytest.raises(module.TransitionError, match="file_mode_invalid"):
        module.check_transition_files([payload])
    assert path.stat().st_mode & 0o777 == 0o755


@pytest.mark.parametrize(
    "field,value",
    [("size", True), ("size", -1), ("size", 2**63), ("owner_uid", True), ("owner_uid", -1), ("sha256", "invalid")],
)
def test_malformed_signed_artifact_metadata_is_refused(tmp_path, field, value):
    _path, identity = _artifact(tmp_path)
    with pytest.raises(module.TransitionError):
        module.TransitionFile.artifact_dependency({**identity, field: value})


@pytest.mark.parametrize("mutation", ["bytes", "mode", "size"])
def test_artifact_change_after_capture_is_refused(tmp_path, mutation):
    path, identity = _artifact(tmp_path)
    change = module.TransitionFile.artifact_dependency(identity)
    if mutation == "bytes":
        with path.open("r+b") as handle:
            handle.write(b"foreign")
    elif mutation == "mode":
        path.chmod(0o700)
    else:
        with path.open("ab") as handle:
            handle.write(b"foreign")
    with pytest.raises(module.TransitionError, match=r"generation_changed|file_mode_changed"):
        module.RuntimeTransition._compare({"files": [change.payload()]}, "after")


def test_expired_forward_budget_does_not_open_artifact(tmp_path, monkeypatch):
    _path, identity = _artifact(tmp_path)
    change = module.TransitionFile.artifact_dependency(identity)

    def forbidden_open(*args, **kwargs):
        raise AssertionError("expired artifact check opened a file")

    token = module._ACTIVE_TRANSITION.set((tmp_path, "fixture", time.monotonic() - 1))
    try:
        monkeypatch.setattr(module.os, "open", forbidden_open)
        with pytest.raises(module.TransitionError, match="forward_authorization_expired"):
            module.RuntimeTransition._compare({"files": [change.payload()]}, "before")
    finally:
        module._ACTIVE_TRANSITION.reset(token)


@pytest.mark.parametrize(
    "changes",
    [
        {"artifact_identity": None},
        {"expected_digest": None},
        {"artifact_identity": {"size": 1, "owner_uid": 0, "unknown": 1}},
    ],
)
def test_artifact_record_schema_refuses_missing_digest_and_unknown_identity_fields(tmp_path, changes):
    _path, identity = _artifact(tmp_path)
    payload = module.TransitionFile.artifact_dependency(identity).payload()
    if changes.get("expected_digest", "present") is None:
        payload.pop("expected_digest")
    else:
        payload.update(changes)
    with pytest.raises(module.TransitionError, match="artifact_dependency_invalid"):
        module.check_transition_files([payload])


def test_artifact_dependency_cannot_be_used_for_reserved_hook_key(
    transition,
    tmp_path,
):
    runtime, plan, _bindings, _pointer = transition
    key = plan.guard_home / "managed/codex/hook-manifest.key"
    key.write_bytes(b"isolated fixture key")
    key.chmod(0o600)
    identity = describe_regular_file(key, role="fixture", executable_required=False)
    change = module.TransitionFile.artifact_dependency(identity)
    with pytest.raises(module.TransitionError, match="authority_target_forbidden"):
        begin(runtime, replace(plan, files=(*plan.files, change)))
    assert not runtime.path.exists()


def test_signed_large_artifact_dependency_never_mutates_or_journals_artifact(
    transition,
    tmp_path,
):
    runtime, plan, _bindings, _pointer = transition
    path, identity = _artifact(tmp_path, large=True)
    change = module.TransitionFile.artifact_dependency(identity)
    plan = replace(plan, files=(*plan.files, change))
    before = path.stat()
    begin(runtime, plan)
    assert runtime.path.stat().st_size < 64 * 1024
    runtime.publish(plan.operation_id, "AuthorizedForExactTransition")
    runtime.publish(plan.operation_id, "HooksPrepared")
    runtime.restore_files(plan.operation_id, first_cause="fixture bootstrap failed")
    assert path.stat() == before
    with path.open("rb") as handle:
        assert hashlib.file_digest(handle, "sha256").hexdigest() == identity["sha256"]
