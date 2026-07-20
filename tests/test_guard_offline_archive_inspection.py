"""Offline archive-inspector behavior and failure-closed regressions."""

from __future__ import annotations

import hashlib
import io
import json
import subprocess
import tarfile
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import offline_archive_inspection as inspector
from codex_plugin_scanner.guard.runtime.offline_archive_inspection import inspect_archive_offline


def _archive_path(tmp_path: Path, entries: list[tuple[str, bytes]]) -> tuple[Path, str]:
    archive_path = tmp_path / "archive.tgz"
    with tarfile.open(archive_path, mode="w:gz") as archive:
        for name, payload in entries:
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    archive_path.chmod(0o400)
    digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    return archive_path, digest


def _archive_with_members(tmp_path: Path, members: list[tuple[tarfile.TarInfo, bytes | None]]) -> tuple[Path, str]:
    archive_path = tmp_path / "custom-archive.tgz"
    with tarfile.open(archive_path, mode="w:gz") as archive:
        for info, payload in members:
            archive.addfile(info, None if payload is None else io.BytesIO(payload))
    archive_path.chmod(0o400)
    digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    return archive_path, digest


def test_offline_archive_inspector_accepts_clean_digest_bound_archive(tmp_path: Path) -> None:
    package_json = json.dumps({"name": "safe-package", "version": "1.0.0"}).encode()
    archive_path, digest = _archive_path(tmp_path, [("package/package.json", package_json)])

    result = inspect_archive_offline(archive_path, expected_sha256=digest)

    assert result.status == "clean"
    assert result.code == "external_archive_inspection_clean"
    assert result.sha256 == digest


def test_offline_archive_inspector_blocks_parent_path_member(tmp_path: Path) -> None:
    archive_path, digest = _archive_path(tmp_path, [("../escape.sh", b"echo unsafe")])

    result = inspect_archive_offline(archive_path, expected_sha256=digest)

    assert result.status == "blocked"
    assert result.code == "tarball_zip_slip"


def test_offline_archive_inspector_blocks_install_script_without_executing_it(tmp_path: Path) -> None:
    marker = tmp_path / "marker"
    package_json = json.dumps(
        {
            "name": "unsafe-package",
            "scripts": {"postinstall": f"touch {marker}"},
        }
    ).encode()
    archive_path, digest = _archive_path(tmp_path, [("package/package.json", package_json)])

    result = inspect_archive_offline(archive_path, expected_sha256=digest)

    assert result.status == "blocked"
    assert result.code == "tarball_install_script"
    assert marker.exists() is False


@pytest.mark.parametrize("lifecycle", ("prepublish", "preprepare", "postprepare"))
def test_offline_archive_inspector_blocks_all_npm_install_lifecycle_scripts(
    lifecycle: str,
    tmp_path: Path,
) -> None:
    package_json = json.dumps(
        {
            "name": "unsafe-package",
            "scripts": {lifecycle: "echo must-not-run"},
        }
    ).encode()
    archive_path, digest = _archive_path(tmp_path, [("package/package.json", package_json)])

    result = inspect_archive_offline(archive_path, expected_sha256=digest)

    assert result.status == "blocked"
    assert result.code == "tarball_install_script"


def test_offline_archive_inspector_blocks_python_sdist_execution_without_running_it(tmp_path: Path) -> None:
    marker = tmp_path / "python-build-marker"
    setup_py = f'import os\nos.system("touch {marker}")\n'.encode()
    archive_path, digest = _archive_path(tmp_path, [("demo/setup.py", setup_py)])

    result = inspect_archive_offline(archive_path, expected_sha256=digest)

    assert result.status == "blocked"
    assert result.code == "python_build_script_risk"
    assert marker.exists() is False


def test_offline_archive_inspector_treats_every_setup_py_as_executable_build_metadata(tmp_path: Path) -> None:
    archive_path, digest = _archive_path(tmp_path, [("demo/setup.py", b"from setuptools import setup\nsetup()\n")])

    result = inspect_archive_offline(archive_path, expected_sha256=digest)

    assert result.status == "blocked"
    assert result.code == "python_build_script_risk"


def test_offline_archive_inspector_blocks_project_local_python_build_backend(tmp_path: Path) -> None:
    pyproject = b'[build-system]\nrequires=[]\nbuild-backend="backend"\nbackend-path=["."]\n'
    archive_path, digest = _archive_path(tmp_path, [("demo/pyproject.toml", pyproject)])

    result = inspect_archive_offline(archive_path, expected_sha256=digest)

    assert result.status == "blocked"
    assert result.code == "python_build_backend_risk"


def test_offline_archive_inspector_blocks_remote_python_build_requirement(tmp_path: Path) -> None:
    pyproject = b'[build-system]\nrequires=["evil @ https://packages.example.com/backend.whl"]\nbuild-backend="evil"\n'
    archive_path, digest = _archive_path(tmp_path, [("demo/pyproject.toml", pyproject)])

    result = inspect_archive_offline(archive_path, expected_sha256=digest)

    assert result.status == "blocked"
    assert result.code == "python_build_backend_risk"


def test_offline_archive_inspector_blocks_implicit_node_gyp_install_lifecycle(tmp_path: Path) -> None:
    package_json = json.dumps({"name": "native-package", "version": "1.0.0"}).encode()
    binding_gyp = json.dumps(
        {
            "targets": [
                {
                    "target_name": "unsafe",
                    "actions": [{"action": ["sh", "-c", "echo must-not-run"]}],
                }
            ]
        }
    ).encode()
    archive_path, digest = _archive_path(
        tmp_path,
        [("package/package.json", package_json), ("package/binding.gyp", binding_gyp)],
    )

    result = inspect_archive_offline(archive_path, expected_sha256=digest)

    assert result.status == "blocked"
    assert result.code == "node_gyp_implicit_install_script"


@pytest.mark.parametrize(
    "specifier",
    (
        "https://evil.example/payload.tgz",
        "file:./payload.tgz",
        "attacker/repository#main",
        "npm:evil@https://evil.example/payload.tgz",
        "exec:./generator.js",
        "jsr:@scope/payload@1.0.0",
        "unknown-protocol:payload",
    ),
)
def test_offline_archive_inspector_blocks_unbound_nested_source_dependencies(
    specifier: str,
    tmp_path: Path,
) -> None:
    package_json = json.dumps(
        {
            "name": "outer-package",
            "dependencies": {"nested-package": specifier},
        }
    ).encode()
    archive_path, digest = _archive_path(
        tmp_path,
        [("package/package.json", package_json), ("package/payload.tgz", b"nested bytes")],
    )

    result = inspect_archive_offline(archive_path, expected_sha256=digest)

    assert result.status == "blocked"
    assert result.code == "external_archive_nested_source_dependency"


@pytest.mark.parametrize("specifier", ("^1.2.3", "latest", "npm:safe-package@^1.2.3", "npm:@scope/safe@latest"))
def test_offline_archive_inspector_allows_registry_only_dependency_specifiers(
    specifier: str,
    tmp_path: Path,
) -> None:
    package_json = json.dumps(
        {
            "name": "outer-package",
            "dependencies": {"safe-package": specifier},
        }
    ).encode()
    archive_path, digest = _archive_path(tmp_path, [("package/package.json", package_json)])

    result = inspect_archive_offline(archive_path, expected_sha256=digest)

    assert result.status == "clean"


def test_offline_archive_inspector_blocks_digest_mismatch(tmp_path: Path) -> None:
    archive_path, _digest = _archive_path(tmp_path, [("package/readme.txt", b"safe")])

    result = inspect_archive_offline(archive_path, expected_sha256="0" * 64)

    assert result.status == "blocked"
    assert result.code == "external_archive_digest_mismatch"


def test_offline_archive_inspector_fails_closed_when_subprocess_is_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path, digest = _archive_path(tmp_path, [("package/readme.txt", b"safe")])

    def unavailable(*_args: object, **_kwargs: object) -> object:
        raise OSError("subprocess disabled")

    monkeypatch.setattr(inspector.subprocess, "run", unavailable)

    result = inspect_archive_offline(archive_path, expected_sha256=digest)

    assert result.status == "incomplete"
    assert result.code == "external_archive_sandbox_unavailable"


def test_offline_archive_inspector_rejects_symlink_blob(tmp_path: Path) -> None:
    archive_path, digest = _archive_path(tmp_path, [("package/readme.txt", b"safe")])
    symlink_path = tmp_path / "archive-link.tgz"
    symlink_path.symlink_to(archive_path)

    result = inspect_archive_offline(symlink_path, expected_sha256=digest)

    assert result.status == "blocked"
    assert result.code == "external_archive_blob_rejected"


def test_offline_archive_inspector_accepts_regular_blob_below_symlinked_temp_root(tmp_path: Path) -> None:
    real_root = tmp_path / "real-temp"
    real_root.mkdir()
    alias_root = tmp_path / "temp-alias"
    alias_root.symlink_to(real_root, target_is_directory=True)
    archive_path, digest = _archive_path(alias_root, [("package/readme.txt", b"safe")])

    result = inspect_archive_offline(archive_path, expected_sha256=digest)

    assert result.status == "clean"
    assert result.sha256 == digest


@pytest.mark.parametrize("member_type", (tarfile.SYMTYPE, tarfile.LNKTYPE))
def test_offline_archive_inspector_blocks_escaping_links(tmp_path: Path, member_type: bytes) -> None:
    link = tarfile.TarInfo("package/link")
    link.type = member_type
    link.linkname = "../../outside"
    archive_path, digest = _archive_with_members(tmp_path, [(link, None)])

    result = inspect_archive_offline(archive_path, expected_sha256=digest)

    assert result.status == "blocked"
    assert result.code == "tarball_zip_slip"


def test_offline_archive_inspector_blocks_special_device_member(tmp_path: Path) -> None:
    device = tarfile.TarInfo("package/device")
    device.type = tarfile.CHRTYPE
    device.devmajor = 1
    device.devminor = 3
    archive_path, digest = _archive_with_members(tmp_path, [(device, None)])

    result = inspect_archive_offline(archive_path, expected_sha256=digest)

    assert result.status == "blocked"
    assert result.code == "tarball_zip_slip"


def test_offline_archive_inspector_blocks_duplicate_member_path(tmp_path: Path) -> None:
    first = tarfile.TarInfo("package/value.txt")
    first.size = 3
    second = tarfile.TarInfo("package/./value.txt")
    second.size = 3
    archive_path, digest = _archive_with_members(tmp_path, [(first, b"one"), (second, b"two")])

    result = inspect_archive_offline(archive_path, expected_sha256=digest)

    assert result.status == "blocked"
    assert result.code == "external_archive_path_conflict"


def test_offline_archive_inspector_blocks_portable_case_collisions(tmp_path: Path) -> None:
    first = tarfile.TarInfo("package/value.txt")
    first.size = 3
    second = tarfile.TarInfo("PACKAGE/VALUE.TXT")
    second.size = 3
    archive_path, digest = _archive_with_members(tmp_path, [(first, b"one"), (second, b"two")])

    result = inspect_archive_offline(archive_path, expected_sha256=digest)

    assert result.status == "blocked"
    assert result.code == "external_archive_path_conflict"


def test_offline_archive_inspector_accepts_root_relative_hardlink_target(tmp_path: Path) -> None:
    target = tarfile.TarInfo("package/target.txt")
    target.size = 4
    hardlink = tarfile.TarInfo("package/nested/link.txt")
    hardlink.type = tarfile.LNKTYPE
    hardlink.linkname = "package/target.txt"
    archive_path, digest = _archive_with_members(tmp_path, [(target, b"safe"), (hardlink, None)])

    result = inspect_archive_offline(archive_path, expected_sha256=digest)

    assert result.status == "clean"
    assert result.code == "external_archive_inspection_clean"


def test_offline_archive_inspector_blocks_linked_package_manifest(tmp_path: Path) -> None:
    manifest_payload = json.dumps({"scripts": {"postinstall": "echo unsafe"}}).encode()
    manifest = tarfile.TarInfo("package/manifest.json")
    manifest.size = len(manifest_payload)
    linked_package_json = tarfile.TarInfo("package/package.json")
    linked_package_json.type = tarfile.SYMTYPE
    linked_package_json.linkname = "manifest.json"
    archive_path, digest = _archive_with_members(
        tmp_path,
        [(manifest, manifest_payload), (linked_package_json, None)],
    )

    result = inspect_archive_offline(archive_path, expected_sha256=digest)

    assert result.status == "blocked"
    assert result.code == "external_archive_manifest_link"


def test_offline_archive_inspector_enforces_decompression_ratio(tmp_path: Path) -> None:
    archive_path, digest = _archive_path(tmp_path, [("package/repeated.txt", b"A" * 16_384)])

    result = inspect_archive_offline(
        archive_path,
        expected_sha256=digest,
        max_decompression_ratio=2.0,
    )

    assert result.status == "blocked"
    assert result.code == "external_archive_decompression_ratio_limit"


def test_offline_archive_inspector_rejects_unsupported_bzip2_before_tar_parsing(tmp_path: Path) -> None:
    archive_path = tmp_path / "archive.tar.bz2"
    with tarfile.open(archive_path, mode="w:bz2") as archive:
        payload = b"safe"
        info = tarfile.TarInfo("package/readme.txt")
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    archive_path.chmod(0o400)
    digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()

    result = inspect_archive_offline(archive_path, expected_sha256=digest)

    assert result.status == "blocked"
    assert result.code == "external_archive_unsupported_format"


def test_offline_archive_inspector_enforces_file_count_and_nested_archive_limits(tmp_path: Path) -> None:
    archive_path, digest = _archive_path(
        tmp_path,
        [("package/one.txt", b"one"), ("package/inner.tgz", b"not really nested")],
    )

    file_count_result = inspect_archive_offline(archive_path, expected_sha256=digest, max_files=1)
    nesting_result = inspect_archive_offline(archive_path, expected_sha256=digest, max_nested_archives=0)

    assert file_count_result.status == "blocked"
    assert file_count_result.code == "tarball_file_count_limit"
    assert nesting_result.status == "blocked"
    assert nesting_result.code == "external_archive_nesting_limit"


def test_offline_archive_inspector_fails_closed_on_malformed_archive(tmp_path: Path) -> None:
    archive_path = tmp_path / "malformed.tgz"
    archive_path.write_bytes(b"not a tar archive")
    archive_path.chmod(0o400)
    digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()

    result = inspect_archive_offline(archive_path, expected_sha256=digest)

    assert result.status == "incomplete"
    assert result.code == "external_archive_inspection_incomplete"


def test_offline_archive_inspector_fails_closed_on_timeout_or_child_crash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path, digest = _archive_path(tmp_path, [("package/readme.txt", b"safe")])

    def timed_out(*_args: object, **_kwargs: object) -> object:
        raise subprocess.TimeoutExpired(["inspector"], 0.01)

    monkeypatch.setattr(inspector.subprocess, "run", timed_out)
    timeout_result = inspect_archive_offline(archive_path, expected_sha256=digest)
    monkeypatch.setattr(
        inspector.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(["inspector"], 9, stdout=b"", stderr=b""),
    )
    crash_result = inspect_archive_offline(archive_path, expected_sha256=digest)

    assert timeout_result.status == "incomplete"
    assert timeout_result.code == "external_archive_inspection_timeout"
    assert crash_result.status == "incomplete"
    assert crash_result.code == "external_archive_inspection_incomplete"


def test_offline_archive_inspector_child_denies_socket_creation() -> None:
    completed = subprocess.run(
        inspector._isolated_child_command(["--child-network-probe"]),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=2,
    )

    assert completed.returncode == 0
    assert completed.stdout == b"denied"


def test_isolated_child_command_derives_root_from_installed_package(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package_file = tmp_path / "site-packages" / "codex_plugin_scanner" / "__init__.py"
    package_file.parent.mkdir(parents=True)
    package_file.write_text("", encoding="utf-8")
    monkeypatch.setattr(inspector.codex_plugin_scanner, "__file__", str(package_file))

    command = inspector._isolated_child_command(["--child-network-probe"])

    assert Path(command[6]) == package_file.parent.parent
