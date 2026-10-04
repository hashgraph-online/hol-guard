"""Provisional repair is crash reversible and cannot claim native completion."""

import multiprocessing
import os
import time
from dataclasses import replace

import pytest

from codex_plugin_scanner.guard import codex_hook_repair as repair
from codex_plugin_scanner.guard.codex_hook_file_integrity import CodexHookIntegrityError
from codex_plugin_scanner.guard.codex_hook_integrity import hook_authority_receipt_path, hook_secret_path
from codex_plugin_scanner.guard.codex_hook_manifest import CODEX_AUTHORITY_REPAIR_ACTION
from codex_plugin_scanner.guard.codex_hook_recovery import (
    commit_hook_publication,
    hook_publication_pending,
    recover_hook_publication,
)
from codex_plugin_scanner.guard.codex_install_transaction import codex_install_transaction
from codex_plugin_scanner.guard.runtime_transition import TransitionError

from .test_codex_hook_recovery import installed  # noqa: F401 -- shared isolated fixture
from .test_codex_hook_repair_authorization import _grant, prepared_repair  # noqa: F401 -- shared isolated fixture


def _authorize(prepared, owner):
    return repair.authorize_codex_hook_repair(
        prepared,
        authority_home=prepared.guard_home,
        grant=_grant(prepared, owner),
        deadline_monotonic=time.monotonic() + 10,
    )


def _unchanged_identity(path):
    metadata = path.stat()
    return path.read_bytes(), metadata.st_ino, metadata.st_mtime_ns, metadata.st_mode


def test_provisional_manifest_only_and_ordinary_commit_refused(prepared_repair):  # noqa: F811
    context, config, manifest, prepared = prepared_repair
    preserved = [config, hook_secret_path(context.guard_home), hook_authority_receipt_path(context.guard_home, config)]
    before = [_unchanged_identity(path) for path in preserved]
    with codex_install_transaction(context.guard_home, config, actor=CODEX_AUTHORITY_REPAIR_ACTION) as owner:
        authorization = _authorize(prepared, owner)
        pending = repair.publish_codex_hook_repair(authorization)
        pending.compare("after")
        with pytest.raises(CodexHookIntegrityError) as wrong_record:
            replace(pending, config_bytes=b"another snapshot").compare("after")
        assert wrong_record.value.reason == "codex_hook_recovery_repair_owner_mismatch"
        with pytest.raises(CodexHookIntegrityError) as wrong_time:
            replace(pending, publication_monotonic=0).compare("after")
        assert wrong_time.value.reason == "codex_hook_recovery_repair_owner_mismatch"
        assert manifest.read_bytes() == prepared.manifest_change.after
        assert hook_publication_pending(context.guard_home)
        with pytest.raises(CodexHookIntegrityError) as refusal:
            commit_hook_publication(context.guard_home)
        assert refusal.value.reason == "codex_hook_recovery_repair_requires_native_verification"
        assert recover_hook_publication(context.guard_home)
        assert not manifest.exists()
        assert not hook_publication_pending(context.guard_home)
        with pytest.raises(TransitionError, match="publication_claimed"):
            repair.publish_codex_hook_repair(authorization)
    assert [_unchanged_identity(path) for path in preserved] == before


def test_post_publication_failure_restores_absence(prepared_repair, monkeypatch):  # noqa: F811
    context, config, manifest, prepared = prepared_repair
    original_write = repair.atomic_write_bytes

    def failing_write(*args, **kwargs):
        original_write(*args, **kwargs)
        raise OSError("isolated write failure after publication")

    monkeypatch.setattr(repair, "atomic_write_bytes", failing_write)
    with (
        codex_install_transaction(context.guard_home, config, actor=CODEX_AUTHORITY_REPAIR_ACTION) as owner,
        pytest.raises(OSError, match="isolated write failure"),
    ):
        repair.publish_codex_hook_repair(_authorize(prepared, owner))
    assert not manifest.exists()
    assert not hook_publication_pending(context.guard_home)


def test_foreign_config_is_preserved_and_both_causes_retained(prepared_repair, monkeypatch):  # noqa: F811
    context, config, manifest, prepared = prepared_repair
    original_write = repair.atomic_write_bytes
    foreign_config = config.read_bytes() + b"\n# foreign fixture generation\n"

    def intervening_write(*args, **kwargs):
        original_write(*args, **kwargs)
        config.write_bytes(foreign_config)
        raise OSError("first publication cause")

    monkeypatch.setattr(repair, "atomic_write_bytes", intervening_write)
    with (
        codex_install_transaction(context.guard_home, config, actor=CODEX_AUTHORITY_REPAIR_ACTION) as owner,
        pytest.raises(repair.CodexHookRepairError) as failure,
    ):
        repair.publish_codex_hook_repair(_authorize(prepared, owner))
    assert isinstance(failure.value.first_error, OSError)
    assert "first publication cause" in str(failure.value.first_error)
    assert isinstance(failure.value.rollback_error, CodexHookIntegrityError)
    assert failure.value.rollback_error.reason == "codex_hook_recovery_generation_changed"
    assert config.read_bytes() == foreign_config
    assert manifest.read_bytes() == prepared.manifest_change.after
    assert hook_publication_pending(context.guard_home)


def test_expired_parent_retains_inverse_without_resetting_budget(prepared_repair, monkeypatch):  # noqa: F811
    context, config, manifest, prepared = prepared_repair
    original_write = repair.atomic_write_bytes
    with codex_install_transaction(context.guard_home, config, actor=CODEX_AUTHORITY_REPAIR_ACTION) as owner:
        authorization = _authorize(prepared, owner)

        def expire_after_write(*args, **kwargs):
            original_write(*args, **kwargs)
            monkeypatch.setattr(repair.time, "monotonic", lambda: authorization.deadline_monotonic + 1)

        monkeypatch.setattr(repair, "atomic_write_bytes", expire_after_write)
        with pytest.raises(repair.CodexHookRepairError) as failure:
            repair.publish_codex_hook_repair(authorization)
        assert isinstance(failure.value.first_error, TransitionError)
        assert failure.value.first_error.reason == "deadline_exceeded"
        assert isinstance(failure.value.rollback_error, TransitionError)
        assert failure.value.rollback_error.reason == "deadline_exceeded"
        assert hook_publication_pending(context.guard_home)
        assert manifest.exists()
        monkeypatch.undo()
        assert recover_hook_publication(context.guard_home)
    assert not manifest.exists()


@pytest.mark.skipif(not hasattr(os, "fork"), reason="POSIX isolated crash qualification")
@pytest.mark.parametrize("phase", ["prepared", "published"])
def test_process_exit_keeps_only_inverse_not_forward_replay(prepared_repair, phase):  # noqa: F811
    context, config, manifest, prepared = prepared_repair
    preserved = [config, hook_secret_path(context.guard_home), hook_authority_receipt_path(context.guard_home, config)]
    before = [_unchanged_identity(path) for path in preserved]

    def crash():
        with codex_install_transaction(context.guard_home, config, actor=CODEX_AUTHORITY_REPAIR_ACTION) as owner:
            authorization = _authorize(prepared, owner)
            if phase == "prepared":
                repair.atomic_write_bytes = lambda *args, **kwargs: os._exit(0)
            repair.publish_codex_hook_repair(authorization)
            os._exit(0)

    child = multiprocessing.get_context("fork").Process(target=crash)
    child.start()
    try:
        child.join(10)
        assert child.exitcode == 0
    finally:
        if child.is_alive():
            child.terminate()
            child.join(5)
        child.close()
    assert hook_publication_pending(context.guard_home)
    assert manifest.exists() is (phase == "published")
    with codex_install_transaction(context.guard_home, config, actor="isolated-inverse"):
        assert recover_hook_publication(context.guard_home)
    assert not manifest.exists()
    assert not hook_publication_pending(context.guard_home)
    assert [_unchanged_identity(path) for path in preserved] == before
