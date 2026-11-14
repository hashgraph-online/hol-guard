"""Captured legacy shell cleanup restores exact profile and managed file generations."""

from dataclasses import replace

import pytest

from codex_plugin_scanner.guard.adapters import codex as adapter
from codex_plugin_scanner.guard.adapters import codex_install_plan as install_plan
from codex_plugin_scanner.guard.codex_hook_integrity import CodexHookIntegrityError
from codex_plugin_scanner.guard.runtime_transition import RuntimeTransition, TransitionError

from .test_codex_publication_preparation import _context, _tree
from .test_runtime_transition import begin, transition  # noqa: F401 -- shared pytest fixture


def _publish(change):
    payload = {"files": [change.payload()]}
    RuntimeTransition._compare(payload, "before")
    RuntimeTransition._write_file(payload["files"][0], "after")
    RuntimeTransition._compare(payload, "after")


def _block():
    return (install_plan.SHELL_GUARD_BEGIN + "\r\nlegacy\r\n" + install_plan.SHELL_GUARD_END + "\r\n").encode()


def _sources(tmp_path, monkeypatch):
    context = _context(tmp_path, monkeypatch)
    profile = context.home_dir / ".zshenv"
    only_managed = context.home_dir / ".bashrc"
    guard = context.guard_home / "managed/codex/codex-zshenv-guard.zsh"
    for path, data, mode in (
        (profile, b"\xffKEEP\r\n\r\n" + _block() + b"AFTER\xfe\r\n", 0o640),
        (only_managed, _block(), 0o644),
        (guard, b"legacy guard script", 0o700),
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(mode)
    return context, profile, only_managed, guard


def test_capture_never_publishes_and_preserves_all_rollback_material(tmp_path, monkeypatch):
    context, profile, only_managed, guard = _sources(tmp_path, monkeypatch)
    before = _tree(tmp_path)
    files = adapter.prepare_codex_shell_cleanup(context)
    assert _tree(tmp_path) == before
    assert len(files) == 9
    changes = {change.path: change for change in files}
    assert changes[profile].after == b"\xffKEEP\r\nAFTER\xfe\r\n"
    assert changes[profile].before_mode == changes[profile].after_mode == 0o640
    for path in (only_managed, guard):
        assert changes[path].before == path.read_bytes()
        assert changes[path].after is None


def test_empty_and_unmatched_profiles_are_dependencies_not_deletions(tmp_path, monkeypatch):
    context = _context(tmp_path, monkeypatch)
    context.home_dir.mkdir()
    for name, data in ((".zshenv", b""), (".bashrc", install_plan.SHELL_GUARD_BEGIN.encode() + b"\nunterminated\n")):
        (context.home_dir / name).write_bytes(data)
    before = _tree(tmp_path)
    files = adapter.prepare_codex_shell_cleanup(context)
    for change in files:
        assert change.before == change.after
        _publish(change)
    assert _tree(tmp_path) == before
    assert not context.guard_home.exists()


def test_ordinary_cleanup_uses_captured_bytes_and_retains_permissions(tmp_path, monkeypatch):
    context, profile, only_managed, guard = _sources(tmp_path, monkeypatch)
    for change in adapter.prepare_codex_shell_cleanup(context):
        _publish(change)
    assert profile.read_bytes() == b"\xffKEEP\r\nAFTER\xfe\r\n"
    assert profile.stat().st_mode & 0o777 == 0o640
    assert not only_managed.exists() and not guard.exists()
    before = _tree(tmp_path)
    for change in adapter.prepare_codex_shell_cleanup(context):
        _publish(change)
    assert _tree(tmp_path) == before


def test_foreign_profile_during_capture_prevents_all_cleanup(tmp_path, monkeypatch):
    context, profile, only_managed, guard = _sources(tmp_path, monkeypatch)
    plan = adapter.planned_files

    def foreign_write(answer):
        files = plan(answer)
        profile.write_bytes(b"foreign profile")
        return files

    monkeypatch.setattr(adapter, "planned_files", foreign_write)
    with pytest.raises(TransitionError, match="generation_changed"):
        for change in adapter.prepare_codex_shell_cleanup(context):
            _publish(change)
    assert profile.read_bytes() == b"foreign profile"
    assert only_managed.read_bytes() == _block()
    assert guard.read_bytes() == b"legacy guard script"


@pytest.mark.parametrize("managed_file", [False, True])
def test_symlink_target_is_refused_before_any_cleanup(tmp_path, monkeypatch, managed_file):
    context, profile, _only_managed, guard = _sources(tmp_path, monkeypatch)
    target = tmp_path / "foreign"
    target.write_bytes(b"foreign bytes")
    link = guard if managed_file else profile
    link.unlink()
    link.symlink_to(target)
    before = _tree(tmp_path)
    with pytest.raises(CodexHookIntegrityError) as failure:
        for change in adapter.prepare_codex_shell_cleanup(context):
            _publish(change)
    assert failure.value.reason == "codex_hook_recovery_target_invalid"
    assert _tree(tmp_path) == before
    assert target.read_bytes() == b"foreign bytes"


def test_signed_inverse_restores_deleted_files_and_non_utf8_profile(
    transition,
    tmp_path,
    monkeypatch,
):
    runtime, plan, _bindings, _pointer = transition
    context, profile, only_managed, guard = _sources(tmp_path, monkeypatch)
    files = adapter.prepare_codex_shell_cleanup(context)
    plan = replace(plan, files=(*plan.files, *files))
    begin(runtime, plan)
    runtime.publish(plan.operation_id, "AuthorizedForExactTransition")
    runtime.publish(plan.operation_id, "HooksPrepared")
    assert profile.read_bytes() == b"\xffKEEP\r\nAFTER\xfe\r\n"
    assert not only_managed.exists() and not guard.exists()
    runtime.restore_files(plan.operation_id, first_cause="fixture candidate failed")
    for change in files:
        if change.before is None:
            assert not change.path.exists()
        else:
            assert change.path.read_bytes() == change.before
            assert change.path.stat().st_mode & 0o777 == change.before_mode
