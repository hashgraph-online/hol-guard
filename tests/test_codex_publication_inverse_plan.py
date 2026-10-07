from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from dataclasses import replace

import pytest

from codex_plugin_scanner.guard import codex_hook_file_integrity as integrity
from codex_plugin_scanner.guard import runtime_transition
from codex_plugin_scanner.guard.adapters.codex import _hook_manifest_spec
from codex_plugin_scanner.guard.codex_hook_file_integrity import CodexHookIntegrityError
from codex_plugin_scanner.guard.codex_hook_integrity import hook_secret_path
from codex_plugin_scanner.guard.codex_install_transaction import codex_install_transaction
from codex_plugin_scanner.guard.codex_publication_inverse_plan import prepare_authenticated_hook_publication_inverse
from codex_plugin_scanner.guard.runtime_transition import TransitionError

from .test_codex_hook_recovery import crash, installed  # noqa: F401 -- shared isolated fixture


def participant_digests(context, config, manifest):
    receipt = manifest.with_name(manifest.name.replace(".manifest.json", ".authority-receipt.json"))
    journal = context.guard_home / "managed/codex/pending-hook-publication.json"
    return {
        path: hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
        for path in (config, manifest, receipt, journal, hook_secret_path(context.guard_home))
    }


@pytest.mark.parametrize("conflicted", [False, True])
def test_inverse_plan_is_read_only_and_binds_foreign_config_for_review(installed, conflicted):  # noqa: F811
    context, config, manifest = installed
    predecessor = config.read_bytes(), manifest.read_bytes()
    if conflicted:
        script = r"""
import os, sys
from pathlib import Path
from codex_plugin_scanner.guard.adapters import codex
from codex_plugin_scanner.guard.adapters.base import HarnessContext
home = Path(sys.argv[1])
context = HarnessContext(home, None, home / '.hol-guard', home_override_explicit=True)
original = codex.mark_owned_hook_publication_conflict
def conflict_after_publication(*args, **kwargs):
    config = home / '.codex/config.toml'
    config.write_bytes(config.read_bytes() + b'\n# intervening writer\n')
    raise OSError('injected readback failure with foreign config')
def exit_after_signed_conflict(*args, **kwargs):
    original(*args, **kwargs)
    os._exit(17)
codex._require_hook_semantics_readback = conflict_after_publication
codex.mark_owned_hook_publication_conflict = exit_after_signed_conflict
codex.CodexHarnessAdapter().install(context)
raise RuntimeError('signed conflict boundary was not reached')
"""
        child = subprocess.run(
            [sys.executable, "-c", script, str(context.home_dir)],
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )
        assert child.returncode == 17, child.stderr
        journal = context.guard_home / "managed/codex/pending-hook-publication.json"
        assert json.loads(journal.read_bytes())["phase"] == "config_conflict"
    else:
        crash(context, "manifest")
    config.write_bytes(config.read_bytes() + b"\n# private fixture config marker\n")
    before = participant_digests(context, config, manifest)
    with codex_install_transaction(context.guard_home, config, actor="review-publication-inverse"):
        plan = prepare_authenticated_hook_publication_inverse(_hook_manifest_spec(context))
        plan.compare_before()
        assert plan.changes[0].after == predecessor[0]
        assert plan.changes[1].after == predecessor[1]
        assert plan.subject().startswith("codex-publication-inverse:")
        summary = plan.summary()
        assert summary["authorized"] is False and summary["verified"] is False
        assert "private fixture config marker" not in json.dumps(summary)
        assert "authentication" not in json.dumps(summary)
    assert participant_digests(context, config, manifest) == before


@pytest.mark.parametrize("target", ["config", "journal"])
def test_inverse_plan_rejects_same_byte_replacement_after_preparation(installed, target):  # noqa: F811
    context, config, _manifest = installed
    crash(context, "manifest")
    journal = context.guard_home / "managed/codex/pending-hook-publication.json"
    with codex_install_transaction(context.guard_home, config, actor="review-substituted-inverse"):
        plan = prepare_authenticated_hook_publication_inverse(_hook_manifest_spec(context))
        selected = config if target == "config" else journal
        value = selected.read_bytes()
        selected.rename(selected.with_name("displaced-" + selected.name))
        selected.write_bytes(value)
        selected.chmod(0o600)
        with pytest.raises(TransitionError) as failure:
            plan.compare_before()
        assert failure.value.reason == (
            "publication_inverse_generation_changed" if target == "config" else "publication_inverse_journal_changed"
        )
        assert selected.read_bytes() == value


def test_inverse_plan_preserves_competing_authority_generation(installed):  # noqa: F811
    context, config, manifest = installed
    crash(context, "manifest")
    manifest.write_bytes(b"competing fixture authority generation\n")
    before = participant_digests(context, config, manifest)
    with codex_install_transaction(context.guard_home, config, actor="review-competing-authority"):
        with pytest.raises(TransitionError) as failure:
            prepare_authenticated_hook_publication_inverse(_hook_manifest_spec(context))
        assert failure.value.reason == "publication_inverse_authority_generation_changed"
    assert participant_digests(context, config, manifest) == before


def test_inverse_plan_refuses_completed_publication(installed):  # noqa: F811
    context, config, manifest = installed
    crash(context, "commit_cleanup")
    before = participant_digests(context, config, manifest)
    with codex_install_transaction(context.guard_home, config, actor="review-committed-publication"):
        with pytest.raises(TransitionError) as failure:
            prepare_authenticated_hook_publication_inverse(_hook_manifest_spec(context))
        assert failure.value.reason == "publication_inverse_phase_invalid"
    assert participant_digests(context, config, manifest) == before


def test_inverse_plan_cannot_trust_tampered_journal(installed):  # noqa: F811
    context, config, manifest = installed
    crash(context, "manifest")
    journal = context.guard_home / "managed/codex/pending-hook-publication.json"
    payload = json.loads(journal.read_bytes())
    payload["before_config"] = "ZXZpbA=="
    journal.write_text(json.dumps(payload))
    before = participant_digests(context, config, manifest)
    with codex_install_transaction(context.guard_home, config, actor="review-tampered-publication"):
        with pytest.raises(CodexHookIntegrityError) as failure:
            prepare_authenticated_hook_publication_inverse(_hook_manifest_spec(context))
        assert failure.value.reason == "codex_hook_recovery_authentication_invalid"
    assert participant_digests(context, config, manifest) == before


def test_inverse_plan_requires_current_exclusive_owner(installed):  # noqa: F811
    context, config, manifest = installed
    crash(context, "manifest")
    spec = _hook_manifest_spec(context)
    before = participant_digests(context, config, manifest)
    with pytest.raises(CodexHookIntegrityError) as failure:
        prepare_authenticated_hook_publication_inverse(spec)
    assert failure.value.reason == "codex_hook_transaction_owner_missing"
    assert participant_digests(context, config, manifest) == before


def test_inverse_plan_preserves_original_validation_deadline(installed, monkeypatch):  # noqa: F811
    context, config, manifest = installed
    crash(context, "manifest")
    spec = _hook_manifest_spec(context)
    before = participant_digests(context, config, manifest)
    clock = [0.0]
    with codex_install_transaction(context.guard_home, config, actor="review-expired-inverse"):
        monkeypatch.setattr(integrity.time, "monotonic", lambda: clock[0])
        with pytest.raises(CodexHookIntegrityError) as failure, integrity.hook_validation_deadline(1.0):
            clock[0] = 2.0
            prepare_authenticated_hook_publication_inverse(spec)
        assert failure.value.reason == "codex_hook_validation_deadline_expired"
    assert participant_digests(context, config, manifest) == before


@pytest.mark.parametrize("alteration", ["inverse", "dependencies"])
def test_inverse_plan_revalidates_snapshots_and_dependencies_from_signed_journal(installed, alteration):  # noqa: F811
    context, config, manifest = installed
    crash(context, "manifest")
    before = participant_digests(context, config, manifest)
    with codex_install_transaction(context.guard_home, config, actor="review-altered-inverse"):
        plan = prepare_authenticated_hook_publication_inverse(_hook_manifest_spec(context))
        if alteration == "inverse":
            plan = replace(
                plan, changes=(replace(plan.changes[0], after=b"unauthorized fixture config"), *plan.changes[1:])
            )
        else:
            plan = replace(plan, dependencies=())
        with pytest.raises(TransitionError) as failure:
            plan.compare_before()
        assert failure.value.reason == (
            "publication_inverse_plan_invalid"
            if alteration == "inverse"
            else "publication_inverse_dependencies_invalid"
        )
    assert participant_digests(context, config, manifest) == before


def test_inverse_plan_forwards_original_deadline_to_artifact_comparison(installed, monkeypatch):  # noqa: F811
    context, config, manifest = installed
    crash(context, "manifest")
    before = participant_digests(context, config, manifest)
    with codex_install_transaction(context.guard_home, config, actor="review-artifact-deadline"):
        plan = prepare_authenticated_hook_publication_inverse(_hook_manifest_spec(context))
        clock = [0.0]
        monkeypatch.setattr(integrity.time, "monotonic", lambda: clock[0])

        def expires_during_digest(*_args, **_kwargs):
            clock[0] = 2.0
            runtime_transition._check_inverse_deadline()
            raise AssertionError("Original deadline was not forwarded to artifact hashing")

        monkeypatch.setattr(runtime_transition, "_artifact_digest", expires_during_digest)
        with pytest.raises(TransitionError) as failure, integrity.hook_validation_deadline(1.0):
            plan.compare_before()
        assert failure.value.reason == "deadline_exceeded"
    assert participant_digests(context, config, manifest) == before
