from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import codex_hook_file_integrity as integrity
from codex_plugin_scanner.guard.codex_hook_file_integrity import CodexHookIntegrityError, validate_regular_file
from codex_plugin_scanner.guard.codex_hook_manifest import CodexHookManifestSpec
from tests import codex_hook_publication_helpers as publication_helpers
from tests.codex_hook_private_group_support import group_is_private_to_owner

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX ownership and permission semantics are required")


def _package_root(tmp_path: Path, package_dir: str = "site-packages") -> Path:
    return tmp_path / "venv" / "lib" / "python3.12" / package_dir


def _packaged_file(
    tmp_path: Path,
    *,
    package_dir: str = "site-packages",
    name: str = "codex_daemon_hook_bridge.py",
) -> tuple[Path, Path]:
    root = _package_root(tmp_path, package_dir)
    path = root / "codex_plugin_scanner" / "guard" / "adapters" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("# packaged fixture\n", encoding="utf-8")
    path.chmod(0o664)
    return root, path


def _assert_refused(path: Path) -> None:
    with pytest.raises(CodexHookIntegrityError, match="writable by another user") as error:
        validate_regular_file(path, role="bridge", executable_required=False)
    assert error.value.reason == "codex_hook_bridge_permissions_unsafe"


def _trust_package_root(monkeypatch: pytest.MonkeyPatch, root: Path) -> None:
    monkeypatch.setattr(integrity, "_python_package_roots", lambda: (root.resolve(strict=False),))


def test_packaged_bridge_accepts_private_group_write_in_site_packages(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, bridge = _packaged_file(tmp_path)
    _trust_package_root(monkeypatch, root)

    if not group_is_private_to_owner(bridge):
        _assert_refused(bridge)
        return
    metadata = validate_regular_file(bridge, role="bridge", executable_required=False)

    assert metadata.st_uid == os.getuid()
    assert stat.S_IMODE(metadata.st_mode) == 0o664


def test_packaged_bridge_accepts_files_under_imported_package_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Imported package tree is trusted even when sysconfig purelib differs."""

    root, bridge = _packaged_file(tmp_path)
    package_init = root / "codex_plugin_scanner" / "__init__.py"
    package_init.parent.mkdir(parents=True, exist_ok=True)
    package_init.write_text("# package\n", encoding="utf-8")
    fake_package = type(sys)("codex_plugin_scanner")
    fake_package.__file__ = str(package_init)
    monkeypatch.setitem(sys.modules, "codex_plugin_scanner", fake_package)
    # `sysconfig` is one module for the whole process, so a stub that takes no
    # scheme also fails the named-scheme call coverage makes while this test
    # runs. Only the integrity check's own schemeless call is answered here.
    real_get_paths = integrity.sysconfig.get_paths
    monkeypatch.setattr(
        integrity.sysconfig,
        "get_paths",
        lambda *scheme, **named: real_get_paths(*scheme, **named) if scheme or named else {},
    )
    monkeypatch.setattr(integrity.sys, "prefix", str(tmp_path / "other-prefix"))
    monkeypatch.setattr(integrity.sys, "exec_prefix", str(tmp_path / "other-prefix"))
    import site as site_module

    monkeypatch.setattr(site_module, "getsitepackages", lambda: [])
    monkeypatch.setattr(site_module, "getusersitepackages", lambda: "")

    canonical = bridge.resolve(strict=False)
    assert any(root in canonical.parents for root in integrity._python_package_roots())
    if not group_is_private_to_owner(bridge):
        _assert_refused(bridge)
        return
    metadata = validate_regular_file(bridge, role="bridge", executable_required=False)

    assert metadata.st_uid == os.getuid()


def test_packaged_bridge_accepts_private_group_write_in_dist_packages(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, bridge = _packaged_file(tmp_path, package_dir="dist-packages")
    _trust_package_root(monkeypatch, root)

    if not group_is_private_to_owner(bridge):
        _assert_refused(bridge)
        return
    metadata = validate_regular_file(bridge, role="bridge", executable_required=False)

    assert metadata.st_uid == os.getuid()
    assert stat.S_IMODE(metadata.st_mode) == 0o664


def test_named_site_packages_directory_is_not_enough_to_trust_group_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trusted_root = _package_root(tmp_path)
    _trust_package_root(monkeypatch, trusted_root)
    bridge = tmp_path / "home" / "site-packages" / "codex_daemon_hook_bridge.py"
    bridge.parent.mkdir(parents=True)
    bridge.write_text("# lookalike fixture\n", encoding="utf-8")
    bridge.chmod(0o664)

    with pytest.raises(CodexHookIntegrityError, match="writable by another user") as error:
        validate_regular_file(bridge, role="bridge", executable_required=False)

    assert error.value.reason == "codex_hook_bridge_permissions_unsafe"


def test_non_package_bridge_still_rejects_group_write_even_for_private_group(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trusted_root = _package_root(tmp_path)
    _trust_package_root(monkeypatch, trusted_root)
    bridge = tmp_path / "codex_daemon_hook_bridge.py"
    bridge.write_text("# unpackaged fixture\n", encoding="utf-8")
    bridge.chmod(0o664)

    with pytest.raises(CodexHookIntegrityError, match="writable by another user") as error:
        validate_regular_file(bridge, role="bridge", executable_required=False)

    assert error.value.reason == "codex_hook_bridge_permissions_unsafe"


def test_manifest_build_accepts_private_group_pipx_style_packaged_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The native builder trusts group write in a package root only when the
    owner's primary group is private; it reads the real group database, so the
    expectation follows the account running the test."""
    package_root = _package_root(tmp_path)
    _trust_package_root(monkeypatch, package_root)
    home_dir = tmp_path / "home"
    guard_home = home_dir / ".hol-guard"
    config_path = home_dir / ".codex" / "config.toml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text('model = "gpt-5"\n', encoding="utf-8")
    config_path.chmod(0o600)

    interpreter = tmp_path / "venv" / "bin" / "python"
    interpreter.parent.mkdir(parents=True)
    interpreter.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    interpreter.chmod(0o755)

    scanner_root = package_root / "codex_plugin_scanner"
    roles = (
        "bridge",
        "fallback_entrypoint",
        "daemon_entrypoint",
        "daemon_manager",
        "launch_runtime",
        "runtime_trust",
        "windows_job",
    )
    packaged_files: list[tuple[str, Path]] = []
    for role in roles:
        path = scanner_root / f"{role}.py"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"# {role}\n", encoding="utf-8")
        path.chmod(0o664)
        packaged_files.append((role, path))

    spec = CodexHookManifestSpec(
        guard_home=guard_home,
        home_dir=home_dir,
        runtime_guard_home=guard_home,
        workspace_dir=None,
        config_path=config_path,
        interpreter_path=interpreter,
        package_version="test",
        packaged_file_paths=tuple(packaged_files),
        fallback_argv=(str(interpreter), "-c", "pass"),
        daemon_start_argv=(str(interpreter), "-c", "pass"),
        event_bindings=(),
    )

    if not group_is_private_to_owner(packaged_files[0][1]):
        with pytest.raises(CodexHookIntegrityError) as error:
            publication_helpers.prepare_authenticated_hook_publication(
                spec, rendered_config='model = "gpt-5"\n', create_key=True
            )
        assert error.value.reason == "codex_hook_bridge_permissions_unsafe"
        return
    manifest = publication_helpers.prepare_authenticated_hook_publication(
        spec, rendered_config='model = "gpt-5"\n', create_key=True
    ).manifest

    identities = manifest["packaged_files"]
    assert isinstance(identities, list)
    assert len(identities) == len(roles)
    assert all(isinstance(identity, dict) and identity["mode"] == 0o664 for identity in identities)
