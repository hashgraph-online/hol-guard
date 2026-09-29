"""Onedir (v2 manifest) Desktop Core installs."""

from __future__ import annotations

import json
import os
import zipfile
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli import update_desktop_core
from codex_plugin_scanner.guard.cli.update_desktop_core import DesktopCoreUpdateError

VERSION = "3.0.0a200"
TARGET = "aarch64-apple-darwin"
TAG = f"alpha/v{VERSION}"
ARTIFACT = f"hol-guard-core-{VERSION}-{TARGET}"


def _v1_manifest(*, sha256: str, size: int, minimum: str = "0.1.0") -> dict[str, object]:
    return {
        "schema": update_desktop_core.UPDATE_SCHEMA,
        "channel": "alpha",
        "version": VERSION,
        "sourceCommit": "a" * 40,
        "sourceTag": TAG,
        "target": TARGET,
        "artifact": ARTIFACT,
        "sha256": sha256,
        "size": size,
        "bootstrapSchema": update_desktop_core.BOOTSTRAP_SCHEMA,
        "minimumDesktopVersion": minimum,
        "publishedAt": "2026-09-29T00:00:00Z",
    }


def _v2_manifest(
    *, archive: bytes, launcher_sha256: str, file_count: int, minimum: str = "3.0.113"
) -> dict[str, object]:
    return {
        "schema": update_desktop_core.ONEDIR_UPDATE_SCHEMA,
        "channel": "alpha",
        "version": VERSION,
        "sourceCommit": "a" * 40,
        "sourceTag": TAG,
        "target": TARGET,
        "format": "onedir-zip",
        "artifact": f"{ARTIFACT}.onedir.zip",
        "sha256": update_desktop_core._sha256_hex(archive),
        "size": len(archive),
        "launcher": "hol-guard/hol-guard",
        "launcherSha256": launcher_sha256,
        "fileCount": file_count,
        "bootstrapSchema": update_desktop_core.BOOTSTRAP_SCHEMA,
        "minimumDesktopVersion": minimum,
        "publishedAt": "2026-09-29T00:00:00Z",
    }


def _onedir_zip(tmp_path: Path, launcher: bytes = b"launcher-bytes") -> bytes:
    archive = tmp_path / "core.zip"
    with zipfile.ZipFile(archive, "w") as zipped:
        info = zipfile.ZipInfo("hol-guard/hol-guard")
        info.external_attr = 0o755 << 16
        zipped.writestr(info, launcher)
        zipped.writestr("hol-guard/Info.plist", "<plist/>")
        zipped.writestr("hol-guard/_CodeSignature/CodeResources", "<resources/>")
        zipped.writestr("hol-guard/_internal/a.txt", "data")
    return archive.read_bytes()


def _apply_mocks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update_desktop_core.sys, "platform", "darwin")
    monkeypatch.setattr(update_desktop_core, "platform_target", lambda: TARGET)
    monkeypatch.setattr(update_desktop_core, "desktop_core_root", lambda: tmp_path / "core")
    monkeypatch.setattr(update_desktop_core, "_macos_signing_team", lambda _path: "TEAMID")
    monkeypatch.setattr(update_desktop_core, "_macos_codesign_ok", lambda _path: True)
    monkeypatch.setattr(update_desktop_core, "_verify_onedir_tree_signatures", lambda *_a, **_k: None)
    monkeypatch.setattr(update_desktop_core, "_require_sealed_onedir", lambda _launcher: None)
    monkeypatch.setattr(
        update_desktop_core,
        "_extract_onedir_zip",
        update_desktop_core._extract_onedir_zip_portable,
    )


class TestParseOnedirManifest:
    def _raw(self, tmp_path: Path) -> bytes:
        archive = _onedir_zip(tmp_path)
        manifest = _v2_manifest(
            archive=archive,
            launcher_sha256=update_desktop_core._sha256_hex(b"launcher-bytes"),
            file_count=2,
        )
        return json.dumps(manifest).encode("utf-8")

    def _parse(self, raw: bytes):
        return update_desktop_core._parse_onedir_manifest(
            raw,
            expected_version=VERSION,
            expected_tag=TAG,
            expected_target=TARGET,
            expected_artifact=f"{ARTIFACT}.onedir.zip",
            expected_channel="alpha",
        )

    def test_happy_path(self, tmp_path: Path) -> None:
        parsed = self._parse(self._raw(tmp_path))
        assert parsed["launcher_sha256"] == update_desktop_core._sha256_hex(b"launcher-bytes")
        assert parsed["file_count"] == 2

    @pytest.mark.parametrize(
        "field,value",
        [
            ("schema", "hol-guard-core-update.v1"),
            ("format", "onefile"),
            ("launcher", "hol-guard/other"),
            ("artifact", "other.zip"),
            ("sha256", "zz" + "0" * 62),
            ("size", update_desktop_core._MAX_BINARY_BYTES + 1),
            ("fileCount", 0),
        ],
    )
    def test_rejected_fields(self, tmp_path: Path, field: str, value: object) -> None:
        manifest = json.loads(self._raw(tmp_path))
        manifest[field] = value
        with pytest.raises(DesktopCoreUpdateError) as error:
            self._parse(json.dumps(manifest).encode("utf-8"))
        assert error.value.reason_code == "desktop_core_manifest_invalid"


class TestTryApplyOnedirFallback:
    def test_missing_manifest_falls_back(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def fetch(url: str, limit: int) -> bytes:
            raise DesktopCoreUpdateError("desktop_core_asset_missing")

        assert (
            update_desktop_core._try_apply_onedir(
                fetch,
                tag=TAG,
                artifact=ARTIFACT,
                channel="alpha",
                expected_version=VERSION,
                expected_target=TARGET,
            )
            is None
        )

    def test_desktop_too_old_falls_back(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HOL_GUARD_DESKTOP_VERSION", "3.0.112")
        archive = _onedir_zip(tmp_path)
        manifest = _v2_manifest(
            archive=archive,
            launcher_sha256=update_desktop_core._sha256_hex(b"launcher-bytes"),
            file_count=2,
        )

        def fetch(url: str, limit: int) -> bytes:
            return json.dumps(manifest).encode("utf-8")

        assert (
            update_desktop_core._try_apply_onedir(
                fetch,
                tag=TAG,
                artifact=ARTIFACT,
                channel="alpha",
                expected_version=VERSION,
                expected_target=TARGET,
            )
            is None
        )

    def test_other_download_errors_propagate(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def fetch(url: str, limit: int) -> bytes:
            raise DesktopCoreUpdateError("desktop_core_download_failed")

        with pytest.raises(DesktopCoreUpdateError) as error:
            update_desktop_core._try_apply_onedir(
                fetch,
                tag=TAG,
                artifact=ARTIFACT,
                channel="alpha",
                expected_version=VERSION,
                expected_target=TARGET,
            )
        assert error.value.reason_code == "desktop_core_download_failed"


class TestApplyOnedir:
    def _fetcher(
        self, tmp_path: Path, *, launcher: bytes = b"launcher-bytes", tampered_zip: bool = False
    ) -> tuple[dict[str, bytes], object]:
        archive = _onedir_zip(tmp_path, launcher=launcher)
        v2 = _v2_manifest(
            archive=archive,
            launcher_sha256=update_desktop_core._sha256_hex(launcher),
            file_count=2,
        )
        if tampered_zip:
            archive = archive + b"tamper"
        urls = {
            update_desktop_core._release_url(TAG, f"{ARTIFACT}.json"): json.dumps(
                _v1_manifest(sha256=update_desktop_core._sha256_hex(b"legacy"), size=len(b"legacy"))
            ).encode("utf-8"),
            update_desktop_core._release_url(TAG, f"{ARTIFACT}.onedir.json"): json.dumps(v2).encode("utf-8"),
            update_desktop_core._release_url(TAG, f"{ARTIFACT}.onedir.zip"): archive,
            update_desktop_core._release_url(TAG, ARTIFACT): b"legacy",
        }

        def fetch(url: str, limit: int) -> bytes:
            _ = limit
            if url in urls:
                return urls[url]
            raise DesktopCoreUpdateError("desktop_core_asset_missing")

        return urls, fetch

    def test_installs_onedir_tree(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _apply_mocks(tmp_path, monkeypatch)
        monkeypatch.setenv("HOL_GUARD_DESKTOP_VERSION", "3.0.113")
        _urls, fetch = self._fetcher(tmp_path)

        result = update_desktop_core.apply_desktop_core_update(
            current_version="3.0.0a138",
            target_version=VERSION,
            include_alpha=True,
            fetch_bytes=fetch,
        )

        assert result.changed is True
        installed = tmp_path / "core" / "versions" / VERSION
        assert result.executable == installed / "hol-guard"
        assert result.executable.is_file()
        assert (installed / "_internal" / "a.txt").is_file()
        pointer = json.loads((tmp_path / "core" / "current.json").read_text(encoding="utf-8"))
        assert pointer["schema"] == update_desktop_core.INSTALL_SCHEMA
        assert pointer["relativePath"] == f"versions/{VERSION}/hol-guard"
        assert pointer["sha256"] == update_desktop_core._sha256_hex(b"launcher-bytes")
        assert pointer["installedAt"].endswith("Z")

    def test_replaces_existing_version_dir(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _apply_mocks(tmp_path, monkeypatch)
        monkeypatch.setenv("HOL_GUARD_DESKTOP_VERSION", "3.0.113")
        existing = tmp_path / "core" / "versions" / VERSION
        existing.mkdir(parents=True)
        (existing / "hol-guard").write_bytes(b"old-onefile")
        _urls, fetch = self._fetcher(tmp_path)

        update_desktop_core.apply_desktop_core_update(
            current_version="3.0.0a138",
            target_version=VERSION,
            include_alpha=True,
            fetch_bytes=fetch,
        )

        assert (existing / "hol-guard").read_bytes() == b"launcher-bytes"
        assert (existing / "_internal" / "a.txt").is_file()

    def test_zip_integrity_mismatch(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _apply_mocks(tmp_path, monkeypatch)
        _urls, fetch = self._fetcher(tmp_path, tampered_zip=True)
        with pytest.raises(DesktopCoreUpdateError) as error:
            update_desktop_core.apply_desktop_core_update(
                current_version="3.0.0a138",
                target_version=VERSION,
                include_alpha=True,
                fetch_bytes=fetch,
            )
        assert error.value.reason_code == "desktop_core_integrity_mismatch"

    def test_launcher_digest_mismatch(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _apply_mocks(tmp_path, monkeypatch)
        archive = _onedir_zip(tmp_path, launcher=b"launcher-bytes")
        v2 = _v2_manifest(
            archive=archive,
            launcher_sha256=update_desktop_core._sha256_hex(b"different"),
            file_count=2,
        )
        urls = {
            update_desktop_core._release_url(TAG, f"{ARTIFACT}.json"): json.dumps(
                _v1_manifest(sha256=update_desktop_core._sha256_hex(b"legacy"), size=len(b"legacy"))
            ).encode("utf-8"),
            update_desktop_core._release_url(TAG, f"{ARTIFACT}.onedir.json"): json.dumps(v2).encode("utf-8"),
            update_desktop_core._release_url(TAG, f"{ARTIFACT}.onedir.zip"): archive,
        }

        def fetch(url: str, limit: int) -> bytes:
            _ = limit
            if url in urls:
                return urls[url]
            raise DesktopCoreUpdateError("desktop_core_asset_missing")

        with pytest.raises(DesktopCoreUpdateError) as error:
            update_desktop_core.apply_desktop_core_update(
                current_version="3.0.0a138",
                target_version=VERSION,
                include_alpha=True,
                fetch_bytes=fetch,
            )
        assert error.value.reason_code == "desktop_core_integrity_mismatch"

    def test_missing_onedir_manifest_uses_legacy(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _apply_mocks(tmp_path, monkeypatch)
        binary = b"legacy-onefile"
        urls = {
            update_desktop_core._release_url(TAG, f"{ARTIFACT}.json"): json.dumps(
                _v1_manifest(sha256=update_desktop_core._sha256_hex(binary), size=len(binary))
            ).encode("utf-8"),
            update_desktop_core._release_url(TAG, ARTIFACT): binary,
        }

        def fetch(url: str, limit: int) -> bytes:
            _ = limit
            if url in urls:
                return urls[url]
            raise DesktopCoreUpdateError("desktop_core_asset_missing")

        result = update_desktop_core.apply_desktop_core_update(
            current_version="3.0.0a138",
            target_version=VERSION,
            include_alpha=True,
            fetch_bytes=fetch,
        )

        installed = tmp_path / "core" / "versions" / VERSION / "hol-guard"
        assert result.executable == installed
        assert installed.read_bytes() == binary


class TestExtractOnedirZipPortable:
    def test_rejects_traversal_members(self, tmp_path: Path) -> None:
        archive = tmp_path / "bad.zip"
        with zipfile.ZipFile(archive, "w") as zipped:
            zipped.writestr("../escape", "x")
        destination = tmp_path / "out"
        destination.mkdir()
        with pytest.raises(DesktopCoreUpdateError):
            update_desktop_core._extract_onedir_zip_portable(archive, destination)

    def test_rejects_absolute_members(self, tmp_path: Path) -> None:
        archive = tmp_path / "bad.zip"
        with zipfile.ZipFile(archive, "w") as zipped:
            zipped.writestr("/abs/path", "x")
        destination = tmp_path / "out"
        destination.mkdir()
        with pytest.raises(DesktopCoreUpdateError):
            update_desktop_core._extract_onedir_zip_portable(archive, destination)

    def test_restores_exec_bit(self, tmp_path: Path) -> None:
        archive = tmp_path / "good.zip"
        with zipfile.ZipFile(archive, "w") as zipped:
            info = zipfile.ZipInfo("hol-guard/hol-guard")
            info.external_attr = 0o755 << 16
            zipped.writestr(info, b"launcher")
        destination = tmp_path / "out"
        destination.mkdir()
        update_desktop_core._extract_onedir_zip_portable(archive, destination)
        launcher = destination / "hol-guard" / "hol-guard"
        assert launcher.stat().st_mode & 0o111


class TestValidateOnedirZipMembers:
    def _zip(self, tmp_path: Path, members: list[tuple[str, bytes, int]]) -> Path:
        archive = tmp_path / "check.zip"
        with zipfile.ZipFile(archive, "w") as zipped:
            for name, data, mode in members:
                info = zipfile.ZipInfo(name)
                info.external_attr = mode << 16
                zipped.writestr(info, data)
        return archive

    def _good(self, tmp_path: Path) -> Path:
        return self._zip(
            tmp_path,
            [
                ("hol-guard/hol-guard", b"launcher", 0o755),
                ("hol-guard/Info.plist", b"<plist/>", 0o644),
                ("hol-guard/_CodeSignature/CodeResources", b"<resources/>", 0o644),
                ("hol-guard/_internal/a.txt", b"data", 0o644),
            ],
        )

    def test_accepts_sealed_zip(self, tmp_path: Path) -> None:
        update_desktop_core._validate_onedir_zip_members(self._good(tmp_path))

    @pytest.mark.parametrize(
        "member",
        [
            "/abs/path",
            "hol-guard/../escape",
            "sibling/x",
            "hol-guard/._launcher",
            "hol-guard/__MACOSX/x",
        ],
    )
    def test_rejects_unsafe_members(self, tmp_path: Path, member: str) -> None:
        archive = tmp_path / "bad.zip"
        good = self._good(tmp_path)
        archive.write_bytes(good.read_bytes())
        with zipfile.ZipFile(archive, "a") as zipped:
            zipped.writestr(member, b"x")
        with pytest.raises(DesktopCoreUpdateError) as error:
            update_desktop_core._validate_onedir_zip_members(archive)
        assert error.value.reason_code == "desktop_core_install_failed"

    def test_rejects_symlink_member(self, tmp_path: Path) -> None:
        archive = tmp_path / "bad.zip"
        good = self._good(tmp_path)
        archive.write_bytes(good.read_bytes())
        with zipfile.ZipFile(archive, "a") as zipped:
            info = zipfile.ZipInfo("hol-guard/_internal/link")
            info.external_attr = 0o120777 << 16
            zipped.writestr(info, b"target")
        with pytest.raises(DesktopCoreUpdateError) as error:
            update_desktop_core._validate_onedir_zip_members(archive)
        assert error.value.reason_code == "desktop_core_install_failed"

    @pytest.mark.parametrize(
        "missing",
        [
            "hol-guard/hol-guard",
            "hol-guard/Info.plist",
            "hol-guard/_CodeSignature/CodeResources",
            "hol-guard/_internal/a.txt",
        ],
    )
    def test_rejects_missing_required_member(self, tmp_path: Path, missing: str) -> None:
        archive = tmp_path / "bad.zip"
        with zipfile.ZipFile(archive, "w") as zipped:
            for name in (
                "hol-guard/hol-guard",
                "hol-guard/Info.plist",
                "hol-guard/_CodeSignature/CodeResources",
                "hol-guard/_internal/a.txt",
            ):
                if name != missing:
                    zipped.writestr(name, b"x")
        with pytest.raises(DesktopCoreUpdateError) as error:
            update_desktop_core._validate_onedir_zip_members(archive)
        assert error.value.reason_code == "desktop_core_install_failed"

    def test_validation_runs_before_extraction(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _apply_mocks(tmp_path, monkeypatch)
        calls: list[Path] = []

        def spy_extract(archive: Path, destination: Path) -> None:
            calls.append(archive)

        monkeypatch.setattr(update_desktop_core, "_extract_onedir_zip", spy_extract)
        archive = tmp_path / "bad.zip"
        with zipfile.ZipFile(archive, "w") as zipped:
            zipped.writestr("hol-guard/../escape", b"x")
            zipped.writestr("hol-guard/hol-guard", b"launcher")
            zipped.writestr("hol-guard/Info.plist", b"<plist/>")
            zipped.writestr("hol-guard/_CodeSignature/CodeResources", b"<resources/>")
            zipped.writestr("hol-guard/_internal/a.txt", b"data")
        zip_bytes = archive.read_bytes()
        v2 = _v2_manifest(
            archive=zip_bytes,
            launcher_sha256=update_desktop_core._sha256_hex(b"launcher"),
            file_count=4,
        )
        urls = {
            update_desktop_core._release_url(TAG, f"{ARTIFACT}.json"): json.dumps(
                _v1_manifest(sha256="0" * 64, size=1)
            ).encode("utf-8"),
            update_desktop_core._release_url(TAG, f"{ARTIFACT}.onedir.json"): json.dumps(v2).encode("utf-8"),
            update_desktop_core._release_url(TAG, f"{ARTIFACT}.onedir.zip"): zip_bytes,
        }

        def fetch(url: str, limit: int) -> bytes:
            _ = limit
            if url in urls:
                return urls[url]
            raise DesktopCoreUpdateError("desktop_core_asset_missing")

        with pytest.raises(DesktopCoreUpdateError) as error:
            update_desktop_core._try_apply_onedir(
                fetch,
                tag=TAG,
                artifact=ARTIFACT,
                channel="alpha",
                expected_version=VERSION,
                expected_target=TARGET,
            )
        assert error.value.reason_code == "desktop_core_install_failed"
        assert calls == []


class TestRequireSealedOnedir:
    SEALED_DISPLAY = (
        "Executable=/x/hol-guard\n"
        "Format=app bundle with Mach-O thin (arm64)\n"
        "Sealed Resources version=2 rules=10 files=148\n"
        "TeamIdentifier=TEAMID\n"
    )

    def _launcher(self, tmp_path: Path) -> Path:
        tree = tmp_path / "hol-guard"
        (tree / "_CodeSignature").mkdir(parents=True)
        (tree / "_CodeSignature" / "CodeResources").write_text("<resources/>", encoding="utf-8")
        launcher = tree / "hol-guard"
        launcher.write_bytes(b"launcher")
        return launcher

    def _fake_codesign(self, monkeypatch: pytest.MonkeyPatch, stderr: str) -> None:
        result = type("Result", (), {"returncode": 0, "stderr": stderr, "stdout": ""})()
        monkeypatch.setattr(update_desktop_core.subprocess, "run", lambda *a, **k: result)

    def test_passes_with_sealed_bundle(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(update_desktop_core.sys, "platform", "darwin")
        self._fake_codesign(monkeypatch, self.SEALED_DISPLAY)
        update_desktop_core._require_sealed_onedir(self._launcher(tmp_path))

    def test_fails_without_sealed_resources_line(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(update_desktop_core.sys, "platform", "darwin")
        self._fake_codesign(monkeypatch, "Format=app bundle with Mach-O thin (arm64)\n")
        with pytest.raises(DesktopCoreUpdateError) as error:
            update_desktop_core._require_sealed_onedir(self._launcher(tmp_path))
        assert error.value.reason_code == "desktop_core_signature_invalid"

    def test_fails_with_macho_only_format(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(update_desktop_core.sys, "platform", "darwin")
        self._fake_codesign(monkeypatch, "Format=Mach-O thin (arm64)\nSealed Resources version=2 rules=10 files=1\n")
        with pytest.raises(DesktopCoreUpdateError) as error:
            update_desktop_core._require_sealed_onedir(self._launcher(tmp_path))
        assert error.value.reason_code == "desktop_core_signature_invalid"

    def test_fails_without_code_resources(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(update_desktop_core.sys, "platform", "darwin")
        launcher = self._launcher(tmp_path)
        (launcher.parent / "_CodeSignature" / "CodeResources").unlink()
        with pytest.raises(DesktopCoreUpdateError) as error:
            update_desktop_core._require_sealed_onedir(launcher)
        assert error.value.reason_code == "desktop_core_signature_invalid"


class TestPartialInstallCleanup:
    def _manifest(self) -> dict[str, object]:
        return {
            "version": VERSION,
            "source_commit": "a" * 40,
            "target": TARGET,
            "artifact": f"{ARTIFACT}.onedir.zip",
            "sha256": "0" * 64,
            "size": 1,
            "launcher_sha256": update_desktop_core._sha256_hex(b"launcher-bytes"),
            "file_count": 2,
            "minimum_desktop_version": "3.0.113",
        }

    def _tree(self, tmp_path: Path) -> Path:
        tree = tmp_path / "tree" / "hol-guard"
        (tree / "_internal").mkdir(parents=True)
        (tree / "hol-guard").write_bytes(b"launcher-bytes")
        (tree / "_internal" / "a.txt").write_text("data", encoding="utf-8")
        return tree

    def test_failed_verify_removes_partial_and_keeps_version_dir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(update_desktop_core.sys, "platform", "darwin")
        monkeypatch.setattr(update_desktop_core, "desktop_core_root", lambda: tmp_path / "core")
        monkeypatch.setattr(update_desktop_core, "_macos_signing_team", lambda _p: "TEAMID")

        def boom(_path: Path, **_kwargs: object) -> None:
            raise DesktopCoreUpdateError("desktop_core_integrity_mismatch")

        monkeypatch.setattr(update_desktop_core, "_verify_candidate", boom)
        existing = tmp_path / "core" / "versions" / VERSION
        existing.mkdir(parents=True)
        (existing / "hol-guard").write_bytes(b"old-onefile")

        with pytest.raises(DesktopCoreUpdateError) as error:
            update_desktop_core._install_managed_core_onedir(self._tree(tmp_path), self._manifest(), TARGET)
        assert error.value.reason_code == "desktop_core_integrity_mismatch"
        versions = tmp_path / "core" / "versions"
        assert list(versions.glob("*.partial-*")) == []
        assert (existing / "hol-guard").read_bytes() == b"old-onefile"

    def test_failed_seal_check_removes_partial_and_restores_version_dir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(update_desktop_core.sys, "platform", "darwin")
        monkeypatch.setattr(update_desktop_core, "desktop_core_root", lambda: tmp_path / "core")
        monkeypatch.setattr(update_desktop_core, "_macos_signing_team", lambda _p: "TEAMID")
        monkeypatch.setattr(update_desktop_core, "_verify_candidate", lambda _p, **_k: None)

        def boom(_path: Path) -> None:
            raise DesktopCoreUpdateError("desktop_core_signature_invalid")

        monkeypatch.setattr(update_desktop_core, "_require_sealed_onedir", boom)
        existing = tmp_path / "core" / "versions" / VERSION
        existing.mkdir(parents=True)
        (existing / "hol-guard").write_bytes(b"old-onefile")

        with pytest.raises(DesktopCoreUpdateError) as error:
            update_desktop_core._install_managed_core_onedir(self._tree(tmp_path), self._manifest(), TARGET)
        assert error.value.reason_code == "desktop_core_signature_invalid"
        versions = tmp_path / "core" / "versions"
        assert list(versions.glob("*.partial-*")) == []
        assert (existing / "hol-guard").read_bytes() == b"old-onefile"


SEALED_FIXTURE = Path(os.environ.get("HOL_GUARD_SEALED_ONEDIR_FIXTURE", "") or "/nonexistent")


@pytest.mark.skipif(
    update_desktop_core.sys.platform != "darwin" or not Path("/usr/bin/codesign").is_file(),
    reason="requires macOS codesign",
)
class TestRealCodesignSeal:
    def test_sealed_tree_strict_verifies_and_tamper_fails(self, tmp_path: Path) -> None:
        if not SEALED_FIXTURE.is_dir():
            pytest.skip("local sealed fixture is unavailable")
        import shutil
        import subprocess

        launcher = SEALED_FIXTURE / "hol-guard"
        assert update_desktop_core.verified_macos_signing_team(launcher) is None
        verified = subprocess.run(
            ["/usr/bin/codesign", "--verify", "--strict", str(launcher)],
            check=False,
            capture_output=True,
        )
        assert verified.returncode == 0
        update_desktop_core._require_sealed_onedir(launcher)

        tampered = tmp_path / "tampered"
        shutil.copytree(SEALED_FIXTURE, tampered, symlinks=True)
        with (tampered / "_internal" / "base_library.zip").open("ab") as handle:
            handle.write(b"X")
        broken = subprocess.run(
            ["/usr/bin/codesign", "--verify", "--strict", str(tampered / "hol-guard")],
            check=False,
            capture_output=True,
        )
        assert broken.returncode != 0

        unsealed = tmp_path / "unsealed"
        shutil.copytree(SEALED_FIXTURE, unsealed, symlinks=True)
        shutil.rmtree(unsealed / "_CodeSignature")
        with pytest.raises(DesktopCoreUpdateError) as error:
            update_desktop_core._require_sealed_onedir(unsealed / "hol-guard")
        assert error.value.reason_code == "desktop_core_signature_invalid"
