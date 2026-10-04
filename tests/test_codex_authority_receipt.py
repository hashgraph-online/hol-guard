"""A retained receipt supplies exact authenticated bytes, never a repair grant."""

import json
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import codex_hook_manifest as manifests
from codex_plugin_scanner.guard import codex_hook_recovery as recovery
from codex_plugin_scanner.guard.adapters import codex as adapter
from codex_plugin_scanner.guard.codex_hook_file_integrity import CodexHookIntegrityError, hook_validation_deadline

from .test_codex_hook_recovery import installed  # noqa: F401 -- shared isolated fixture
from .test_codex_publication_preparation import _tree
from .test_frozen_codex_runtime import frozen_codex_contract  # noqa: F401 -- shared frozen fixture
from .test_runtime_transition import begin, transition  # noqa: F401 -- shared signed transition fixture


def test_read_missing_manifest_receipt_is_exact_and_read_only(installed):  # noqa: F811 -- shared pytest fixture
    context, config, manifest = installed
    expected = manifest.read_bytes()
    manifest.unlink()
    receipt_path = recovery.hook_authority_receipt_path(context.guard_home, config)
    before = receipt_path.read_bytes(), config.read_bytes()
    result = recovery.load_hook_authority_receipt(context.guard_home, config)
    assert result.manifest_bytes == expected
    assert result.receipt_bytes == before[0]
    assert result.config_bytes == before[1]
    assert not manifest.exists()
    assert (receipt_path.read_bytes(), config.read_bytes()) == before


@pytest.mark.parametrize("failure", ["tamper", "config", "symlink", "public", "oversized", "invalid_json", "nested"])
def test_receipt_refuses_changed_authority_or_config_without_mutation(
    installed,
    failure,  # noqa: F811 -- shared pytest fixture
):
    context, config, manifest = installed
    receipt = recovery.hook_authority_receipt_path(context.guard_home, config)
    if failure == "tamper":
        payload = json.loads(receipt.read_bytes())
        payload["config_sha256"] = "0" * 64
        receipt.write_text(json.dumps(payload))
    elif failure == "config":
        config.write_bytes(config.read_bytes() + b"\n# changed generation\n")
    elif failure == "symlink":
        saved = receipt.with_suffix(".fixture")
        receipt.rename(saved)
        receipt.symlink_to(saved)
    elif failure == "public":
        receipt.chmod(0o644)
    elif failure == "oversized":
        with receipt.open("wb") as handle:
            handle.truncate(4 * 1024 * 1024 + 1)
    elif failure == "nested":
        receipt.write_bytes(b"[" * 2000 + b"0" + b"]" * 2000)
    else:
        receipt.write_bytes(b"invalid JSON")

    def metadata():
        current = receipt.lstat()
        return (
            current.st_dev,
            current.st_ino,
            current.st_mode,
            current.st_size,
            current.st_mtime_ns,
            current.st_ctime_ns,
        )

    before = manifest.read_bytes(), config.read_bytes(), metadata()
    with pytest.raises(CodexHookIntegrityError):
        recovery.load_hook_authority_receipt(context.guard_home, config)
    assert (manifest.read_bytes(), config.read_bytes(), metadata()) == before


def test_expired_receipt_read_refuses_before_file_access(tmp_path: Path, monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("expired read accessed an authority file")

    monkeypatch.setattr(recovery, "read_private_regular_bytes", forbidden)
    with (
        pytest.raises(CodexHookIntegrityError, match="deadline"),
        hook_validation_deadline(time.monotonic() + 0.1),
    ):
        # Enter with a live parent budget, then expire it before the actual
        # callee. An already-expired context would refuse before this call.
        time.sleep(0.15)
        recovery.load_hook_authority_receipt(tmp_path / "absent-home", tmp_path / "config")
    assert not (tmp_path / "absent-home").exists()


@pytest.mark.parametrize("failure", ["inner_mac", "inner_target", "outer_target"])
def test_signed_receipt_does_not_authenticate_inconsistent_manifest(
    installed,
    failure,  # noqa: F811 -- shared pytest fixture
):
    from codex_plugin_scanner.guard.codex_hook_integrity import (
        canonical_manifest_bytes,
        load_hook_secret,
        sign_hook_manifest,
    )

    context, config, manifest = installed
    original = manifest.read_bytes()
    embedded = json.loads(original)
    embedded["config"]["target"] = str(config.with_name("other-config.toml"))
    if failure == "inner_target":
        embedded.pop("authentication")
        embedded = sign_hook_manifest(embedded, load_hook_secret(context.guard_home))
    encoded_manifest = original if failure == "outer_target" else canonical_manifest_bytes(embedded) + b"\n"
    encoded = recovery.build_hook_authority_receipt(
        context.guard_home,
        config.with_name("other-config.toml") if failure == "outer_target" else config,
        config_bytes=config.read_bytes(),
        manifest_bytes=encoded_manifest,
    )
    receipt = recovery.hook_authority_receipt_path(context.guard_home, config)
    receipt.write_bytes(encoded)
    with pytest.raises(CodexHookIntegrityError):
        recovery.load_hook_authority_receipt(context.guard_home, config)
    assert manifest.read_bytes() == original
    assert receipt.read_bytes() == encoded


def test_key_replacement_during_receipt_read_is_preserved_and_refused(
    installed,
    monkeypatch,
    tmp_path,  # noqa: F811 -- shared pytest fixture
):
    from codex_plugin_scanner.guard.codex_hook_integrity import hook_secret_path, load_or_create_hook_secret

    context, config, manifest = installed
    other_home = tmp_path / "other-generated-installation"
    replacement = load_or_create_hook_secret(other_home)
    original_authenticate = recovery.authenticate_hook_manifest_text

    def replace_after_authentication(*args, **kwargs):
        result = original_authenticate(*args, **kwargs)
        hook_secret_path(context.guard_home).write_bytes(hook_secret_path(other_home).read_bytes())
        return result

    monkeypatch.setattr(recovery, "authenticate_hook_manifest_text", replace_after_authentication)
    before = manifest.read_bytes(), config.read_bytes()
    with pytest.raises(CodexHookIntegrityError) as failure:
        recovery.load_hook_authority_receipt(context.guard_home, config)
    assert failure.value.reason == "codex_hook_recovery_receipt_generation_changed"
    assert recovery.load_hook_secret(context.guard_home) == replacement
    assert (manifest.read_bytes(), config.read_bytes()) == before


def test_missing_manifest_repair_preparation_pins_authority_without_publication(
    installed,
    tmp_path,  # noqa: F811 -- shared pytest fixture
):
    context, config, manifest = installed
    expected = manifest.read_bytes()
    manifest.unlink()
    before = _tree(tmp_path)
    prepared = manifests.prepare_authenticated_hook_manifest_repair(adapter._hook_manifest_spec(context))
    assert _tree(tmp_path) == before
    assert prepared.manifest_change.before is None
    assert prepared.manifest_change.after == expected
    dependencies = {change.path: change for change in prepared.files if change.expected_digest is not None}
    assert config.resolve() in dependencies
    assert recovery.hook_authority_receipt_path(context.guard_home, config).resolve() in dependencies
    assert all(change.before is None and change.after is None for change in dependencies.values())
    assert not manifest.exists()
    assert adapter.codex_native_hook_state(context)["protection_active"] is False


@pytest.mark.parametrize("failure", ["present", "version", "argv", "receipt", "config"])
def test_repair_plan_refuses_changed_or_incompatible_generation(
    installed,
    tmp_path,
    monkeypatch,
    failure,  # noqa: F811 -- shared pytest fixture
):
    from dataclasses import replace

    from codex_plugin_scanner.guard.runtime_transition import TransitionError

    context, config, manifest = installed
    spec = adapter._hook_manifest_spec(context)
    if failure != "present":
        manifest.unlink()
    if failure == "version":
        spec = replace(spec, package_version="unmatched-package-generation")
    elif failure == "argv":
        spec = replace(spec, fallback_argv=(*spec.fallback_argv, "unregistered-argument"))
    elif failure in {"receipt", "config"}:
        original_verify = manifests._verify_hook_manifest

        def changed_after_verification(*args, **kwargs):
            result = original_verify(*args, **kwargs)
            target = config if failure == "config" else recovery.hook_authority_receipt_path(context.guard_home, config)
            target.write_bytes(target.read_bytes() + b"\n# intervening generation\n")
            return result

        monkeypatch.setattr(manifests, "_verify_hook_manifest", changed_after_verification)
    with pytest.raises((CodexHookIntegrityError, TransitionError)):
        manifests.prepare_authenticated_hook_manifest_repair(spec)
    assert manifest.exists() is (failure == "present")
    if failure in {"config", "receipt"}:
        target = config if failure == "config" else recovery.hook_authority_receipt_path(context.guard_home, config)
        assert target.read_bytes().endswith(b"# intervening generation\n")


def test_prepared_repair_cannot_be_used_after_manifest_replacement(
    installed,  # noqa: F811 -- shared pytest fixture
):
    from codex_plugin_scanner.guard.runtime_transition import RuntimeTransition, TransitionError

    context, _config, manifest = installed
    manifest.unlink()
    prepared = manifests.prepare_authenticated_hook_manifest_repair(adapter._hook_manifest_spec(context))
    manifest.write_bytes(b"a later publisher's manifest")
    with pytest.raises(TransitionError, match="generation_changed"):
        RuntimeTransition._compare({"files": [change.payload() for change in prepared.files]}, "before")
    assert manifest.read_bytes() == b"a later publisher's manifest"


def test_signed_repair_file_inverse_restores_missing_manifest_state(
    installed,
    transition,  # noqa: F811 -- shared pytest fixtures
):
    from dataclasses import replace

    context, config, manifest = installed
    expected = manifest.read_bytes()
    receipt = recovery.hook_authority_receipt_path(context.guard_home, config)
    before = config.read_bytes(), receipt.read_bytes()
    manifest.unlink()
    prepared = manifests.prepare_authenticated_hook_manifest_repair(adapter._hook_manifest_spec(context))
    runtime, plan, _bindings, _pointer = transition
    plan = replace(plan, files=(*plan.files, *prepared.files))
    begin(runtime, plan)
    runtime.publish(plan.operation_id, "AuthorizedForExactTransition")
    runtime.publish(plan.operation_id, "HooksPrepared")
    assert manifest.read_bytes() == expected
    assert adapter.codex_native_hook_state(context)["protection_active"] is True
    runtime.restore_files(plan.operation_id, first_cause="fixture protected repair verification failed")
    assert not manifest.exists()
    assert adapter.codex_native_hook_state(context)["protection_active"] is False
    assert (config.read_bytes(), receipt.read_bytes()) == before


@pytest.fixture
def retained_installation(tmp_path, monkeypatch):
    from codex_plugin_scanner.guard.adapters.base import HarnessContext

    context = HarnessContext(
        home_dir=tmp_path / "home", guard_home=tmp_path / "guard-home", workspace_dir=None, home_override_explicit=True
    )
    monkeypatch.setenv("HOME", str(context.home_dir))
    monkeypatch.setenv("USERPROFILE", str(context.home_dir))
    source_root = Path(adapter.__file__).resolve().parents[3]
    adapter_relative = Path(adapter.__file__).relative_to(source_root)
    sources = {path for _role, path in adapter._hook_packaged_file_paths()} | {Path(adapter.__file__)}
    bridges = []
    for number in range(9):
        root = tmp_path / f"immutable-generation-{number}"
        for source in sources:
            destination = root / source.relative_to(source_root)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(source.read_bytes())
            destination.chmod(0o644)
        monkeypatch.setattr(adapter, "__file__", str(root / adapter_relative))
        adapter.CodexHarnessAdapter().install(context)
        bridges.append(Path(adapter._hook_command_parts(context)[2]))
    return context, bridges


def test_repair_plan_pins_all_eight_retained_artifact_generations(retained_installation):
    context, bridges = retained_installation
    config = context.home_dir / ".codex/config.toml"
    manifest = recovery.hook_manifest_path(context.guard_home, config)
    manifest.unlink()
    prepared = manifests.prepare_authenticated_hook_manifest_repair(adapter._hook_manifest_spec(context))
    dependencies = {change.path for change in prepared.files if change.expected_digest is not None}
    assert all(bridge in dependencies for bridge in bridges)
    assert len(prepared.files) <= 128


@pytest.mark.parametrize("boundary", ["before_preparation", "after_preparation"])
def test_retained_artifact_loss_refuses_repair_without_publishing(retained_installation, boundary):
    from codex_plugin_scanner.guard.runtime_transition import RuntimeTransition, TransitionError

    context, bridges = retained_installation
    config = context.home_dir / ".codex/config.toml"
    manifest = recovery.hook_manifest_path(context.guard_home, config)
    manifest.unlink()
    if boundary == "before_preparation":
        bridges[0].unlink()
        with pytest.raises((CodexHookIntegrityError, TransitionError)):
            manifests.prepare_authenticated_hook_manifest_repair(adapter._hook_manifest_spec(context))
    else:
        prepared = manifests.prepare_authenticated_hook_manifest_repair(adapter._hook_manifest_spec(context))
        bridges[0].write_bytes(bridges[0].read_bytes() + b"\n# foreign retained artifact\n")
        with pytest.raises(TransitionError):
            RuntimeTransition._compare({"files": [change.payload() for change in prepared.files]}, "before")
        assert bridges[0].read_bytes().endswith(b"# foreign retained artifact\n")
    assert not manifest.exists()


@pytest.mark.usefixtures("frozen_codex_contract")
def test_frozen_retained_repair_pins_both_physical_executables(tmp_path, monkeypatch):
    from codex_plugin_scanner.guard.adapters.base import HarnessContext
    from codex_plugin_scanner.guard.runtime_transition import RuntimeTransition, TransitionError

    context = HarnessContext(
        home_dir=tmp_path / "home", guard_home=tmp_path / "guard-home", workspace_dir=None, home_override_explicit=True
    )
    monkeypatch.setenv("HOME", str(context.home_dir))
    executables = []
    for number in range(2):
        executable = tmp_path / f"immutable-core-{number}"
        executable.write_bytes(b"generated frozen executable identity")
        executable.chmod(0o700)
        monkeypatch.setattr(adapter.sys, "executable", str(executable))
        adapter.CodexHarnessAdapter().install(context)
        executables.append(executable)
    config = context.home_dir / ".codex/config.toml"
    manifest = recovery.hook_manifest_path(context.guard_home, config)
    manifest.unlink()
    prepared = manifests.prepare_authenticated_hook_manifest_repair(adapter._hook_manifest_spec(context))
    for executable in executables:
        matches = [change for change in prepared.files if change.path == executable]
        assert len(matches) == 1
        assert matches[0].invocation_identity["path"] == str(executable)
    executables[0].unlink()
    with pytest.raises(TransitionError):
        RuntimeTransition._compare({"files": [change.payload() for change in prepared.files]}, "before")
    assert not manifest.exists()


def _replace_generated_receipt(context, config, payload):
    from codex_plugin_scanner.guard.codex_hook_integrity import (
        canonical_manifest_bytes,
        load_hook_secret,
        sign_hook_manifest,
    )

    payload.pop("authentication")
    signed = sign_hook_manifest(payload, load_hook_secret(context.guard_home))
    receipt = recovery.hook_authority_receipt_path(context.guard_home, config)
    receipt.write_bytes(
        recovery.build_hook_authority_receipt(
            context.guard_home,
            config,
            config_bytes=config.read_bytes(),
            manifest_bytes=canonical_manifest_bytes(signed) + b"\n",
        )
    )


@pytest.mark.parametrize("failure", ["argv", "context", "hash", "fallback", "transport"])
def test_signed_inconsistent_retained_generation_is_not_repaired(retained_installation, failure):
    context, _bridges = retained_installation
    config = context.home_dir / ".codex/config.toml"
    manifest = recovery.hook_manifest_path(context.guard_home, config)
    payload = json.loads(manifest.read_bytes())
    old = payload["retained_bridge_generations"][0]
    if failure == "argv":
        old["events"][0]["argv"].append("unregistered-argument")
    elif failure == "context":
        old["context"]["workspace_dir"] = "/unregistered-workspace"
    elif failure == "hash":
        payload["compatible_bridge_argv_sha256"][0] = "z" * 64
    elif failure == "fallback":
        old["fallback"]["argv"].append("unregistered-argument")
    else:
        old["transport"]["bridge"] = None
    _replace_generated_receipt(context, config, payload)
    manifest.unlink()
    with pytest.raises(CodexHookIntegrityError) as failure_result:
        manifests.prepare_authenticated_hook_manifest_repair(adapter._hook_manifest_spec(context))
    assert failure_result.value.reason == "codex_hook_repair_retained_identity_invalid"
    assert not manifest.exists()


def test_legacy_hash_only_receipt_does_not_infer_old_artifact_paths(retained_installation):
    context, bridges = retained_installation
    config = context.home_dir / ".codex/config.toml"
    manifest = recovery.hook_manifest_path(context.guard_home, config)
    payload = json.loads(manifest.read_bytes())
    payload.pop("retained_bridge_generations")
    _replace_generated_receipt(context, config, payload)
    manifest.unlink()
    prepared = manifests.prepare_authenticated_hook_manifest_repair(adapter._hook_manifest_spec(context))
    dependencies = {change.path for change in prepared.files if change.expected_digest is not None}
    assert bridges[-1] in dependencies
    assert all(bridge not in dependencies for bridge in bridges[:-1])
    assert not manifest.exists()
