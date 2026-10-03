"""Codex authority preparation captures exact generations without enrollment."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import codex_hook_manifest as manifests
from codex_plugin_scanner.guard.adapters import codex as adapter
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.codex_hook_file_integrity import CodexHookIntegrityError
from codex_plugin_scanner.guard.codex_hook_integrity import hook_secret_path
from codex_plugin_scanner.guard.runtime_transition import TransitionError


def _context(tmp_path, monkeypatch):
    monkeypatch.setattr(adapter, "_post_tool_hook_timeout_seconds", lambda context: 35)
    return HarnessContext(home_dir=tmp_path / "home", guard_home=tmp_path / "guard-home", workspace_dir=None)


def _tree(root: Path):
    return {
        str(path.relative_to(root)): (
            path.stat().st_mode,
            path.stat().st_ino,
            path.stat().st_mtime_ns,
            hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None,
        )
        for path in root.rglob("*")
    }


def test_preparation_missing_authority_never_enrolls(tmp_path, monkeypatch):
    context = _context(tmp_path, monkeypatch)
    spec = adapter._hook_manifest_spec(context)
    before = _tree(tmp_path)
    with pytest.raises(CodexHookIntegrityError) as failure:
        manifests.prepare_authenticated_hook_publication(spec, rendered_config='model = "fixture"\n')
    assert failure.value.reason == "codex_hook_manifest_secret_missing"
    assert _tree(tmp_path) == before
    assert not hook_secret_path(context.guard_home).exists()


def test_enrolled_pair_preparation_preserves_files_and_authority(tmp_path, monkeypatch):
    context = _context(tmp_path, monkeypatch)
    adapter.CodexHarnessAdapter().install(context)
    spec = adapter._hook_manifest_spec(context)
    baseline = manifests.load_hook_manifest_baseline(spec)
    before = _tree(tmp_path)
    rendered = spec.config_path.read_text() + "\n# candidate revision\n"
    prepared = manifests.prepare_authenticated_hook_publication(
        spec, rendered_config=rendered, previous_manifest=baseline
    )
    assert _tree(tmp_path) == before
    assert prepared.config_change.after == rendered.encode()
    assert prepared.manifest["installation_id"] == baseline["installation_id"]
    assert prepared.authority_dependency.before is None
    assert prepared.authority_dependency.after is None
    assert len(prepared.authority_dependency.expected_digest) == 64


def test_preparation_does_not_repair_unsafe_authority_directory(tmp_path, monkeypatch):
    context = _context(tmp_path, monkeypatch)
    adapter.CodexHarnessAdapter().install(context)
    spec = adapter._hook_manifest_spec(context)
    baseline = manifests.load_hook_manifest_baseline(spec)
    hook_secret_path(context.guard_home).parent.chmod(0o755)
    before = _tree(tmp_path)
    with pytest.raises(CodexHookIntegrityError):
        manifests.prepare_authenticated_hook_publication(spec, rendered_config="", previous_manifest=baseline)
    assert _tree(tmp_path) == before


def test_foreign_config_during_identity_capture_is_preserved(tmp_path, monkeypatch):
    context = _context(tmp_path, monkeypatch)
    adapter.CodexHarnessAdapter().install(context)
    spec = adapter._hook_manifest_spec(context)
    baseline = manifests.load_hook_manifest_baseline(spec)
    real_build = manifests.build_authenticated_hook_manifest

    def intervening_write(*args, **kwargs):
        result = real_build(*args, **kwargs)
        spec.config_path.write_text("# foreign generation\n")
        return result

    monkeypatch.setattr(manifests, "build_authenticated_hook_manifest", intervening_write)
    with pytest.raises(TransitionError, match="generation_changed"):
        manifests.prepare_authenticated_hook_publication(spec, rendered_config="", previous_manifest=baseline)
    assert spec.config_path.read_text() == "# foreign generation\n"
    assert manifests.load_hook_manifest_baseline(spec) == baseline


def test_missing_manifest_rebind_cannot_enroll_with_existing_key(tmp_path, monkeypatch):
    context = _context(tmp_path, monkeypatch)
    adapter.CodexHarnessAdapter().install(context)
    spec = adapter._hook_manifest_spec(context)
    from codex_plugin_scanner.guard.codex_hook_integrity import hook_manifest_path

    hook_manifest_path(context.guard_home, spec.config_path).unlink()
    before = _tree(tmp_path)
    with pytest.raises(CodexHookIntegrityError):
        manifests.prepare_authenticated_hook_publication(spec, rendered_config="")
    assert _tree(tmp_path) == before


def test_foreign_key_during_identity_capture_is_preserved(tmp_path, monkeypatch):
    context = _context(tmp_path, monkeypatch)
    adapter.CodexHarnessAdapter().install(context)
    spec = adapter._hook_manifest_spec(context)
    baseline = manifests.load_hook_manifest_baseline(spec)
    config_before = spec.config_path.read_bytes()
    key_path = hook_secret_path(context.guard_home)
    real_build = manifests.build_authenticated_hook_manifest

    def intervening_write(*args, **kwargs):
        result = real_build(*args, **kwargs)
        key_path.write_text("foreign fixture authority")
        return result

    monkeypatch.setattr(manifests, "build_authenticated_hook_manifest", intervening_write)
    with pytest.raises(TransitionError, match="generation_changed"):
        manifests.prepare_authenticated_hook_publication(spec, rendered_config="", previous_manifest=baseline)
    assert key_path.read_text() == "foreign fixture authority"
    assert spec.config_path.read_bytes() == config_before
