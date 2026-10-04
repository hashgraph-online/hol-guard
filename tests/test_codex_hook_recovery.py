from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import codex_hook_recovery
from codex_plugin_scanner.guard.adapters import codex
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.codex import CodexHarnessAdapter, codex_native_hook_state
from codex_plugin_scanner.guard.codex_hook_file_integrity import CodexHookIntegrityError
from codex_plugin_scanner.guard.codex_hook_integrity import hook_manifest_path, hook_secret_path
from codex_plugin_scanner.guard.codex_hook_recovery import recover_hook_publication
from codex_plugin_scanner.guard.codex_install_transaction import codex_install_transaction

CRASHING_INSTALLER = r"""
import os, sys
from pathlib import Path
from codex_plugin_scanner.guard.adapters import codex
from codex_plugin_scanner.guard.adapters.base import HarnessContext
home = Path(sys.argv[1])
phase = sys.argv[2]
context = HarnessContext(home_dir=home, guard_home=home / ".hol-guard", workspace_dir=None)
if phase == "commit_cleanup":
    from codex_plugin_scanner.guard import codex_hook_recovery
    codex_hook_recovery._remove_record = lambda *_: os._exit(17)
    codex.CodexHarnessAdapter().install(context)
    raise RuntimeError("commit cleanup was not reached")
name = {"prepared": "prepare_hook_publication", "manifest": "write_hook_manifest",
        "config": "atomic_write_text", "committed": "commit_hook_publication"}[phase]
original = getattr(codex, name)
def crash_after(*args, **kwargs):
    original(*args, **kwargs)
    os._exit(17)
setattr(codex, name, crash_after)
codex.CodexHarnessAdapter().install(context)
raise RuntimeError("crash boundary was not reached")
"""

UNRECORDED_CONFIG_INSTALLER = r"""
import os, sys
from pathlib import Path
from codex_plugin_scanner.guard.adapters import codex
from codex_plugin_scanner.guard.adapters.base import HarnessContext
home = Path(sys.argv[1])
context = HarnessContext(home_dir=home, guard_home=home / '.hol-guard', workspace_dir=None)
original = codex.atomic_write_text
def publish_without_record(*args, **kwargs):
    kwargs.pop('on_publish', None)
    original(*args, **kwargs)
    os._exit(17)
codex.atomic_write_text = publish_without_record
codex.CodexHarnessAdapter().install(context)
raise RuntimeError('unrecorded publication boundary was not reached')
"""


@pytest.fixture
def installed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    home = tmp_path / "home"
    (home / ".codex").mkdir(parents=True)
    config = home / ".codex/config.toml"
    config.write_text("[features]\nhooks = true\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    context = HarnessContext(home_dir=home, guard_home=home / ".hol-guard", workspace_dir=None)
    CodexHarnessAdapter().install(context)
    return context, config, hook_manifest_path(context.guard_home, config)


@pytest.mark.parametrize("operation", ["prepare", "recover", "commit"])
def test_hook_publication_cannot_join_pending_runtime_inverse(installed, operation):
    from codex_plugin_scanner.guard.runtime_transition import TransitionError

    context, config, manifest = installed
    home = context.guard_home
    before_config, before_manifest = config.read_bytes(), manifest.read_bytes()
    after_config, after_manifest = before_config + b"\n", before_manifest + b"\n"

    def prepare():
        codex_hook_recovery.prepare_hook_publication(
            home,
            config,
            before_config=before_config,
            before_manifest=before_manifest,
            after_config=after_config,
            after_manifest=after_manifest,
            key_created=False,
        )

    publication = home / "managed/codex/pending-hook-publication.json"
    journal = home / "managed/runtime-transition.json"
    with codex_install_transaction(home, config, actor="pending-inverse-fixture"):
        if operation != "prepare":
            prepare()
            config.write_bytes(after_config)
            manifest.write_bytes(after_manifest)
        snapshots = [path.read_bytes() if path.exists() else None for path in (config, manifest, publication)]
        journal.write_bytes(b"pending runtime fixture")
        journal.chmod(0o600)
        with pytest.raises(TransitionError, match="pending_transition"):
            if operation == "prepare":
                prepare()
            elif operation == "recover":
                codex_hook_recovery.recover_hook_publication(home)
            else:
                codex_hook_recovery.commit_hook_publication(home)
        assert [path.read_bytes() if path.exists() else None for path in (config, manifest, publication)] == snapshots
        assert journal.read_bytes() == b"pending runtime fixture"


def crash(context: HarnessContext, phase: str) -> None:
    result = subprocess.run(
        [sys.executable, "-c", CRASHING_INSTALLER, str(context.home_dir), phase],
        env={**os.environ, "HOME": str(context.home_dir), "USERPROFILE": str(context.home_dir)},
        capture_output=True,
        timeout=20,
    )
    assert result.returncode == 17, result.stderr.decode(errors="replace")


@pytest.mark.parametrize("substitution", ["edit", "symlink", "deleted", "matching_original", "matching_after"])
def test_live_conflict_preserves_every_participant_after_process_exit(installed, substitution):
    context, config, _manifest = installed
    foreign = config.parent / "foreign.toml"
    foreign.write_bytes(b"# competing config\n")
    script = r"""
import hashlib, json, os, sys
from pathlib import Path
from codex_plugin_scanner.guard import codex_hook_recovery as recovery
from codex_plugin_scanner.guard.adapters import codex
from codex_plugin_scanner.guard.adapters.base import HarnessContext
home, substitution = Path(sys.argv[1]), sys.argv[2]
config = home / '.codex/config.toml'
original_write = codex.atomic_write_text
def competing_write(*args, **kwargs):
    manifest = codex.hook_manifest_path(home / '.hol-guard', config)
    receipt = manifest.with_name(manifest.name.replace('.manifest.json', '.authority-receipt.json'))
    participants = [manifest, receipt, codex.hook_secret_path(home / '.hol-guard')]
    hashes = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in participants}
    snapshot = home / 'participant-digests.json'
    snapshot.write_text(json.dumps(hashes))
    snapshot.chmod(0o600)
    if substitution == 'symlink':
        config.unlink()
        config.symlink_to(config.parent / 'foreign.toml')
    elif substitution == 'deleted':
        config.unlink()
    elif substitution in ('matching_original', 'matching_after'):
        if substitution == 'matching_after':
            original_write(*args, **kwargs)
        replacement = config.parent / 'foreign-replacement.toml'
        replacement.write_bytes(config.read_bytes())
        replacement.chmod(0o600)
        replacement.replace(config)
    else:
        config.write_bytes(b'# competing config\n')
    raise OSError('injected publication failure')
codex.atomic_write_text = competing_write
original_record_write = recovery.atomic_write_bytes
def crash_after_conflict_record(*args, **kwargs):
    original_record_write(*args, **kwargs)
    if json.loads(args[1])['phase'] == 'config_conflict':
        os._exit(17)
recovery.atomic_write_bytes = crash_after_conflict_record
context = HarnessContext(home_dir=home, guard_home=home / '.hol-guard', workspace_dir=None)
codex.CodexHarnessAdapter().install(context)
raise RuntimeError('conflict record boundary was not reached')
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(context.home_dir), substitution],
        env={**os.environ, "HOME": str(context.home_dir), "USERPROFILE": str(context.home_dir)},
        capture_output=True,
        timeout=20,
    )
    assert result.returncode == 17, result.stderr.decode(errors="replace")
    pending = context.guard_home / "managed/codex/pending-hook-publication.json"
    assert json.loads(pending.read_bytes())["phase"] == "config_conflict"
    import hashlib

    snapshots = json.loads((context.home_dir / "participant-digests.json").read_bytes())
    snapshots[str(pending)] = hashlib.sha256(pending.read_bytes()).hexdigest()
    config_snapshot = config.read_bytes() if config.exists() else None
    with codex_install_transaction(context.guard_home, config, actor="recover-conflicted-owner"):
        with pytest.raises(CodexHookIntegrityError) as failure:
            recover_hook_publication(context.guard_home)
        assert failure.value.reason == "codex_hook_recovery_config_conflict"
    assert (config.read_bytes() if config.exists() else None) == config_snapshot
    assert config.is_symlink() is (substitution == "symlink")
    assert all(hashlib.sha256(Path(path).read_bytes()).hexdigest() == digest for path, digest in snapshots.items())
    assert pending.exists()


def test_new_owner_cannot_mark_config_conflict_for_old_preparation(installed):
    context, config, manifest = installed
    crash(context, "manifest")
    pending = context.guard_home / "managed/codex/pending-hook-publication.json"
    before = config.read_bytes(), manifest.read_bytes(), pending.read_bytes()
    with codex_install_transaction(context.guard_home, config, actor="different-owner"):
        with pytest.raises(CodexHookIntegrityError) as failure:
            codex_hook_recovery.mark_owned_hook_publication_conflict(context.guard_home, config)
        assert failure.value.reason == "codex_hook_recovery_conflict_owner_mismatch"
    assert (config.read_bytes(), manifest.read_bytes(), pending.read_bytes()) == before


def test_conflict_marker_refuses_competing_authentication_generation(installed):
    context, config, manifest = installed
    with codex_install_transaction(context.guard_home, config, actor="live-abort-owner"):
        codex_hook_recovery.prepare_hook_publication(
            context.guard_home,
            config,
            before_config=config.read_bytes(),
            before_manifest=manifest.read_bytes(),
            after_config=config.read_bytes() + b"\n",
            after_manifest=manifest.read_bytes() + b"\n",
            key_created=False,
        )
        config.write_bytes(b"# foreign configuration\n")
        manifest.write_bytes(b"foreign authentication generation\n")
        pending = context.guard_home / "managed/codex/pending-hook-publication.json"
        before = config.read_bytes(), manifest.read_bytes(), pending.read_bytes()
        with pytest.raises(CodexHookIntegrityError) as failure:
            codex_hook_recovery.mark_owned_hook_publication_conflict(context.guard_home, config)
        assert failure.value.reason == "codex_hook_recovery_generation_changed"
        assert (config.read_bytes(), manifest.read_bytes(), pending.read_bytes()) == before
        assert json.loads(pending.read_bytes())["phase"] == "prepared"


def test_successful_publication_retains_exact_authority_receipt(installed):
    import base64
    import hashlib

    from codex_plugin_scanner.guard.codex_hook_integrity import load_hook_secret
    from codex_plugin_scanner.guard.local_authority_integrity import verify_local_authority_payload

    context, config, manifest = installed
    receipt = manifest.with_name(manifest.name.replace(".manifest.json", ".authority-receipt.json"))
    payload = json.loads(receipt.read_bytes())
    assert receipt.stat().st_mode & 0o077 == 0
    assert payload["config_path"] == str(config.resolve())
    assert payload["config_sha256"] == hashlib.sha256(config.read_bytes()).hexdigest()
    assert base64.b64decode(payload["manifest"], validate=True) == manifest.read_bytes()
    authentication = payload.pop("authentication")
    secret = load_hook_secret(context.guard_home)
    assert (
        verify_local_authority_payload(
            payload,
            authentication,
            key=secret.key,
            key_id=secret.key_id,
            purpose="codex-hook-authority-receipt",
        ).status
        == "valid"
    )
    assert (
        verify_local_authority_payload(
            payload,
            authentication,
            key=secret.key,
            key_id=secret.key_id,
            purpose="codex-hook-publication-inverse",
        ).status
        != "valid"
    )


@pytest.mark.parametrize("phase", ["prepared", "manifest", "config"])
def test_killed_publisher_recovers_exact_previous_authenticated_pair(installed, phase: str):
    context, config, manifest = installed
    receipt = manifest.with_name(manifest.name.replace(".manifest.json", ".authority-receipt.json"))
    before = config.read_bytes(), manifest.read_bytes(), receipt.read_bytes()
    crash(context, phase)
    record = context.guard_home / "managed/codex/pending-hook-publication.json"
    assert record.exists()
    assert record.stat().st_mode & 0o077 == 0
    assert "hook-manifest.key" not in record.read_text()
    with codex_install_transaction(context.guard_home, config, actor="recovery"):
        assert recover_hook_publication(context.guard_home)
        assert not recover_hook_publication(context.guard_home)
    assert (config.read_bytes(), manifest.read_bytes(), receipt.read_bytes()) == before
    assert codex_native_hook_state(context)["protection_active"]
    assert not record.exists()


@pytest.mark.parametrize("phase", ["prepared", "manifest", "config"])
def test_recovery_preserves_same_byte_foreign_config_before_conflict_marker(installed, phase):
    context, config, manifest = installed
    crash(context, phase)
    record = context.guard_home / "managed/codex/pending-hook-publication.json"
    assert json.loads(record.read_bytes())["phase"] == "prepared"
    original = config.read_bytes()
    previous_inode = config.stat().st_ino
    # Keep the displaced inode alive so allocation cannot hide the substitution.
    config.rename(config.with_name("displaced-config.toml"))
    config.write_bytes(original)
    config.chmod(0o600)
    assert config.stat().st_ino != previous_inode
    receipt = manifest.with_name(manifest.name.replace(".manifest.json", ".authority-receipt.json"))
    participants = (config, manifest, receipt, hook_secret_path(context.guard_home), record)
    digests = {path: hashlib.sha256(path.read_bytes()).digest() for path in participants}
    with codex_install_transaction(context.guard_home, config, actor="recover-before-conflict-marker"):
        with pytest.raises(CodexHookIntegrityError) as failure:
            recover_hook_publication(context.guard_home)
        assert failure.value.reason == "codex_hook_recovery_generation_changed"
    assert all(
        path.exists() and hashlib.sha256(path.read_bytes()).digest() == digest for path, digest in digests.items()
    )


def test_unrecorded_published_inode_requires_recovery_without_restoring_participants(installed):
    context, config, manifest = installed
    result = subprocess.run(
        [sys.executable, "-c", UNRECORDED_CONFIG_INSTALLER, str(context.home_dir)],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 17, result.stderr
    record = context.guard_home / "managed/codex/pending-hook-publication.json"
    assert "after_config_identity" not in json.loads(record.read_bytes())
    receipt = manifest.with_name(manifest.name.replace(".manifest.json", ".authority-receipt.json"))
    participants = (config, manifest, receipt, hook_secret_path(context.guard_home), record)
    digests = {path: hashlib.sha256(path.read_bytes()).digest() for path in participants}
    with codex_install_transaction(context.guard_home, config, actor="recover-unrecorded-inode"):
        with pytest.raises(CodexHookIntegrityError) as failure:
            recover_hook_publication(context.guard_home)
        assert failure.value.reason == "codex_hook_recovery_generation_changed"
    assert all(
        path.exists() and hashlib.sha256(path.read_bytes()).digest() == digest for path, digest in digests.items()
    )


def test_new_owner_cannot_register_a_previous_publishers_config_inode(installed):
    context, config, _manifest = installed
    crash(context, "config")
    record = context.guard_home / "managed/codex/pending-hook-publication.json"
    before = record.read_bytes()
    identity = codex.rollback_file_identity(config)
    assert identity is not None
    with codex_install_transaction(context.guard_home, config, actor="foreign-publication-owner"):
        with pytest.raises(CodexHookIntegrityError) as failure:
            codex_hook_recovery.record_owned_hook_config_publication(context.guard_home, config, identity)
        assert failure.value.reason == "codex_hook_recovery_config_publication_owner_mismatch"
    assert record.read_bytes() == before


def test_exit_after_inverse_config_replacement_retains_unknown_inode_for_recovery(installed):
    context, config, manifest = installed
    config.write_text(config.read_text() + "\n# Preserve this original config comment during inverse.\n")
    crash(context, "config")
    inverse = r"""
import os, sys
from pathlib import Path
from codex_plugin_scanner.guard import codex_hook_recovery as recovery
from codex_plugin_scanner.guard.codex_install_transaction import codex_install_transaction
home, config = Path(sys.argv[1]), Path(sys.argv[2])
original = recovery.restore_private_file
def restore_then_exit(path, value):
    original(path, value)
    if path == config:
        os._exit(17)
recovery.restore_private_file = restore_then_exit
with codex_install_transaction(home, config, actor='interrupted-inverse'):
    recovery.recover_hook_publication(home)
raise RuntimeError('inverse config boundary was not reached')
"""
    result = subprocess.run(
        [sys.executable, "-c", inverse, str(context.guard_home), str(config)],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 17, result.stderr
    record = context.guard_home / "managed/codex/pending-hook-publication.json"
    receipt = manifest.with_name(manifest.name.replace(".manifest.json", ".authority-receipt.json"))
    participants = (config, manifest, receipt, hook_secret_path(context.guard_home), record)
    digests = {path: hashlib.sha256(path.read_bytes()).digest() for path in participants}
    with codex_install_transaction(context.guard_home, config, actor="resume-interrupted-inverse"):
        with pytest.raises(CodexHookIntegrityError) as failure:
            recover_hook_publication(context.guard_home)
        assert failure.value.reason == "codex_hook_recovery_generation_changed"
    assert all(
        path.exists() and hashlib.sha256(path.read_bytes()).digest() == digest for path, digest in digests.items()
    )


@pytest.mark.parametrize("phase", ["committed", "commit_cleanup"])
def test_committed_pair_is_not_undone_after_process_exit(installed, phase: str):
    context, config, manifest = installed
    before_manifest = manifest.read_bytes()
    crash(context, phase)
    assert manifest.read_bytes() != before_manifest
    with codex_install_transaction(context.guard_home, config, actor="recovery"):
        assert not recover_hook_publication(context.guard_home)
    assert codex_native_hook_state(context)["protection_active"]


def test_recovery_resumes_after_first_file_was_restored(installed, monkeypatch: pytest.MonkeyPatch):
    context, config, manifest = installed
    before = config.read_bytes(), manifest.read_bytes()
    crash(context, "config")
    original_restore = codex_hook_recovery.restore_private_file

    def interrupted_restore(target, payload):
        original_restore(target, payload)
        raise OSError("injected recovery interruption")

    with codex_install_transaction(context.guard_home, config, actor="recovery"):
        with monkeypatch.context() as patch:
            patch.setattr(codex_hook_recovery, "restore_private_file", interrupted_restore)
            with pytest.raises(OSError, match="interruption"):
                recover_hook_publication(context.guard_home)
        assert recover_hook_publication(context.guard_home)
    assert (config.read_bytes(), manifest.read_bytes()) == before
    assert codex_native_hook_state(context)["protection_active"]


def test_next_install_recovers_before_loading_manifest_baseline(installed):
    context, _config, _manifest = installed
    crash(context, "manifest")
    CodexHarnessAdapter().install(context)
    assert codex_native_hook_state(context)["protection_active"]
    assert not (context.guard_home / "managed/codex/pending-hook-publication.json").exists()


def test_preparation_failure_after_durable_write_uses_authenticated_inverse(installed, monkeypatch: pytest.MonkeyPatch):
    context, config, manifest = installed
    before = config.read_bytes(), manifest.read_bytes()
    original_prepare = codex.prepare_hook_publication

    def prepared_then_failed(*args, **kwargs):
        original_prepare(*args, **kwargs)
        raise OSError("injected preparation completion failure")

    monkeypatch.setattr(codex, "prepare_hook_publication", prepared_then_failed)
    with pytest.raises(OSError, match="completion failure"):
        CodexHarnessAdapter().install(context)
    assert (config.read_bytes(), manifest.read_bytes()) == before
    assert codex_native_hook_state(context)["protection_active"]
    assert not (context.guard_home / "managed/codex/pending-hook-publication.json").exists()


def test_recovery_without_ownership_cannot_read_or_create_state(tmp_path: Path):
    home = tmp_path / "guard-home"
    with pytest.raises(CodexHookIntegrityError) as failure:
        recover_hook_publication(home)
    assert failure.value.reason == "codex_hook_transaction_owner_missing"
    assert not home.exists()


def test_foreign_edit_during_preparation_is_preserved(installed, monkeypatch: pytest.MonkeyPatch):
    context, config, manifest = installed
    before_manifest = manifest.read_bytes()
    original_prepare = codex.prepare_hook_publication
    edited_config = config.read_bytes() + b"\n# edit while install is preparing\n"

    def prepare_after_edit(*args, **kwargs):
        config.write_bytes(edited_config)
        return original_prepare(*args, **kwargs)

    monkeypatch.setattr(codex, "prepare_hook_publication", prepare_after_edit)
    with pytest.raises(CodexHookIntegrityError) as failure:
        CodexHarnessAdapter().install(context)
    assert failure.value.reason == "codex_hook_recovery_generation_changed"
    assert config.read_bytes() == edited_config
    assert manifest.read_bytes() == before_manifest
    assert not (context.guard_home / "managed/codex/pending-hook-publication.json").exists()


@pytest.mark.parametrize("phase", ["prepared", "manifest", "config"])
def test_first_install_crash_restores_absence_without_retaining_new_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str
):
    home = tmp_path / "home"
    (home / ".codex").mkdir(parents=True)
    config = home / ".codex/config.toml"
    before_config = b"[features]\nhooks = true\n"
    config.write_bytes(before_config)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    context = HarnessContext(home_dir=home, guard_home=home / ".hol-guard", workspace_dir=None)
    crash(context, phase)
    with codex_install_transaction(context.guard_home, config, actor="recovery"):
        assert recover_hook_publication(context.guard_home)
    assert config.read_bytes() == before_config
    assert not hook_manifest_path(context.guard_home, config).exists()
    assert not codex_hook_recovery.hook_authority_receipt_path(context.guard_home, config).exists()
    assert not hook_secret_path(context.guard_home).exists()
    CodexHarnessAdapter().install(context)
    assert codex_native_hook_state(context)["protection_active"]


@pytest.mark.parametrize("edited", ["config", "receipt"])
def test_recovery_preserves_foreign_edit_before_restoring_either_file(installed, edited):
    context, config, manifest = installed
    crash(context, "manifest")
    receipt = codex_hook_recovery.hook_authority_receipt_path(context.guard_home, config)
    target = config if edited == "config" else receipt
    target.write_bytes(target.read_bytes() + b"\n# a later user edit\n")
    current = config.read_bytes(), manifest.read_bytes(), receipt.read_bytes()
    with (
        codex_install_transaction(context.guard_home, config, actor="recovery"),
        pytest.raises(CodexHookIntegrityError, match="needs recovery") as failure,
    ):
        recover_hook_publication(context.guard_home)
    assert failure.value.reason == "codex_hook_recovery_generation_changed"
    assert (config.read_bytes(), manifest.read_bytes(), receipt.read_bytes()) == current
    assert (context.guard_home / "managed/codex/pending-hook-publication.json").exists()


def test_uninstall_revokes_retained_authority_receipt(installed):
    context, config, _manifest = installed
    receipt = codex_hook_recovery.hook_authority_receipt_path(context.guard_home, config)
    assert receipt.exists()
    CodexHarnessAdapter().uninstall(context)
    assert not receipt.exists()


def test_tampered_inverse_cannot_choose_new_bytes_or_target(installed):
    context, config, manifest = installed
    crash(context, "manifest")
    current = config.read_bytes(), manifest.read_bytes()
    record = context.guard_home / "managed/codex/pending-hook-publication.json"
    payload = json.loads(record.read_text())
    payload["before_config"] = "ZXZpbA=="
    record.write_text(json.dumps(payload))
    with (
        codex_install_transaction(context.guard_home, config, actor="recovery"),
        pytest.raises(CodexHookIntegrityError) as failure,
    ):
        recover_hook_publication(context.guard_home)
    assert failure.value.reason == "codex_hook_recovery_authentication_invalid"
    assert (config.read_bytes(), manifest.read_bytes()) == current


@pytest.mark.parametrize("phase", ["config", "commit_cleanup"])
def test_legacy_signed_record_without_config_identity_preserves_participants(installed, phase):
    context, config, manifest = installed
    crash(context, phase)
    record = context.guard_home / "managed/codex/pending-hook-publication.json"
    payload = json.loads(record.read_bytes())
    payload.pop("authentication")
    payload.pop("before_config_identity")
    payload.pop("after_config_identity")
    secret = codex_hook_recovery.load_hook_secret(context.guard_home)
    payload["authentication"] = codex_hook_recovery.sign_local_authority_payload(
        payload,
        key=secret.key,
        key_id=secret.key_id,
        purpose="codex-hook-publication-inverse",
        signed_at=payload["operation_id"],
    )
    record.write_bytes(codex_hook_recovery.canonical_manifest_bytes(payload) + b"\n")
    receipt = manifest.with_name(manifest.name.replace(".manifest.json", ".authority-receipt.json"))
    participants = (config, manifest, receipt, hook_secret_path(context.guard_home), record)
    digests = {path: hashlib.sha256(path.read_bytes()).digest() for path in participants}
    with codex_install_transaction(context.guard_home, config, actor="recover-legacy-identity"):
        with pytest.raises(CodexHookIntegrityError) as failure:
            recover_hook_publication(context.guard_home)
        assert failure.value.reason == "codex_hook_recovery_config_identity_missing"
    assert all(
        path.exists() and hashlib.sha256(path.read_bytes()).digest() == digest for path, digest in digests.items()
    )
