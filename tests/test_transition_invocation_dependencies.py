"""Transition dependencies preserve executable invocation and symlink identity."""

import os
import time
from dataclasses import replace

import pytest

from codex_plugin_scanner.guard import runtime_transition as module
from codex_plugin_scanner.guard.codex_hook_file_integrity import describe_executable_file

from .test_runtime_transition import begin, transition  # noqa: F401 -- shared pytest fixture
from .test_transition_artifact_dependencies import _artifact


def _invocation(tmp_path, *, symlink=True):
    target, _identity = _artifact(tmp_path)
    invocation = tmp_path / "venv-python" if symlink else target
    if symlink:
        invocation.symlink_to(target.name)
    identity = describe_executable_file(invocation, role="interpreter")
    change = module.TransitionFile.artifact_dependency(identity["target"], invocation=identity)
    return target, invocation, change


@pytest.mark.parametrize("symlink", [False, True])
def test_invocation_dependency_preserves_signed_path_and_does_not_write(tmp_path, symlink):
    target, invocation, change = _invocation(tmp_path, symlink=symlink)
    before = invocation.lstat()
    payload = change.payload()
    assert payload["path"] == str(target)
    assert payload["invocation_identity"]["path"] == str(invocation)
    assert payload["invocation_identity"]["link_target"] == (target.name if symlink else None)
    module.RuntimeTransition._compare({"files": [payload]}, "before")
    module.RuntimeTransition._write_file(payload, "after")
    module.RuntimeTransition._write_file(payload, "before")
    assert invocation.lstat() == before


@pytest.mark.parametrize("replacement", ["other-target", "absolute-same-target", "regular-file", "missing"])
def test_retargeted_invocation_is_refused_even_when_old_target_is_unchanged(tmp_path, replacement):
    target, invocation, change = _invocation(tmp_path)
    payload = change.payload()
    original = target.read_bytes()
    invocation.unlink()
    if replacement == "other-target":
        other = tmp_path / "other-python"
        other.write_bytes(original)
        other.chmod(0o755)
        invocation.symlink_to(other.name)
    elif replacement == "absolute-same-target":
        invocation.symlink_to(target)
    elif replacement == "regular-file":
        invocation.write_bytes(original)
        invocation.chmod(0o755)
    with pytest.raises(
        module.TransitionError, match=r"invocation_generation_changed|invocation_dependency_unavailable"
    ):
        module.RuntimeTransition._compare({"files": [payload]}, "after")
    assert target.read_bytes() == original


def test_symlink_recreated_during_hash_is_rejected_and_preserved(tmp_path, monkeypatch):
    target, invocation, change = _invocation(tmp_path)
    read = module.os.read
    replaced = False

    def replace_link(descriptor, size):
        nonlocal replaced
        data = read(descriptor, size)
        if not replaced:
            replaced = True
            invocation.unlink()
            invocation.symlink_to(target.name)
        return data

    monkeypatch.setattr(module.os, "read", replace_link)
    with pytest.raises(module.TransitionError, match="invocation_generation_changed"):
        module.RuntimeTransition._compare({"files": [change.payload()]}, "before")
    assert invocation.is_symlink() and os.readlink(invocation) == target.name


def test_parent_alias_retarget_is_refused(tmp_path):
    target, identity = _artifact(tmp_path)
    first, second = tmp_path / "first", tmp_path / "second"
    first.mkdir()
    second.mkdir()
    (first / "python").symlink_to(target)
    other = second / "python"
    other.write_bytes(target.read_bytes())
    other.chmod(0o755)
    alias = tmp_path / "venv"
    alias.symlink_to(first, target_is_directory=True)
    invocation = describe_executable_file(alias / "python", role="interpreter")
    change = module.TransitionFile.artifact_dependency(identity, invocation=invocation)
    alias.unlink()
    alias.symlink_to(second, target_is_directory=True)
    with pytest.raises(module.TransitionError, match="invocation_generation_changed"):
        module.RuntimeTransition._compare({"files": [change.payload()]}, "before")


@pytest.mark.parametrize(
    "field,value",
    [
        ("path", "relative"),
        ("mode", True),
        ("mode", -1),
        ("owner_uid", True),
        ("link_target", ""),
        ("link_target", "bad\0path"),
    ],
)
def test_invocation_record_schema_is_strict(tmp_path, field, value):
    _target, _unused_invocation, change = _invocation(tmp_path)
    payload = change.payload()
    payload["invocation_identity"][field] = value
    with pytest.raises(module.TransitionError, match="invocation_dependency_invalid"):
        module._record_files({"files": [payload]})


def test_invocation_record_cannot_be_attached_to_authority_dependency(tmp_path):
    target, _unused_invocation, artifact = _invocation(tmp_path)
    authority = module.TransitionFile.identity_dependency(target).payload()
    authority["invocation_identity"] = artifact.payload()["invocation_identity"]
    with pytest.raises(module.TransitionError, match="invocation_dependency_invalid"):
        module._record_files({"files": [authority]})


def test_expired_invocation_check_does_not_read_link_metadata(tmp_path, monkeypatch):
    target, _invocation_path, change = _invocation(tmp_path)

    def forbidden_lstat(*args, **kwargs):
        raise AssertionError("expired invocation check touched filesystem")

    token = module._ACTIVE_TRANSITION.set((tmp_path, "fixture", time.monotonic() - 1))
    try:
        monkeypatch.setattr(module.Path, "lstat", forbidden_lstat)
        with pytest.raises(module.TransitionError, match="forward_authorization_expired"):
            module._invocation_generation(target, change.invocation_identity)
    finally:
        module._ACTIVE_TRANSITION.reset(token)


def test_signed_inverse_preserves_invocation_and_target(
    transition,
    tmp_path,
):
    runtime, plan, _bindings, _pointer = transition
    target, invocation, change = _invocation(tmp_path)
    plan = replace(plan, files=(*plan.files, change))
    before = invocation.lstat(), target.stat()
    begin(runtime, plan)
    runtime.publish(plan.operation_id, "AuthorizedForExactTransition")
    runtime.publish(plan.operation_id, "HooksPrepared")
    runtime.restore_files(plan.operation_id, first_cause="fixture candidate failed")
    assert (invocation.lstat(), target.stat()) == before
