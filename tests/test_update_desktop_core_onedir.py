"""Onedir (v2 manifest) Desktop Core installs."""

from __future__ import annotations

import json
import os
import sys
import zipfile
from pathlib import Path

import pytest
from packaging.version import Version

from codex_plugin_scanner.guard.cli import update_desktop_core
from codex_plugin_scanner.guard.cli.update_desktop_core import DesktopCoreUpdateError

VERSION = "3.0.0a200"
TARGET = "aarch64-apple-darwin"
TAG = f"alpha/v{VERSION}"
ARTIFACT = f"hol-guard-core-{VERSION}-{TARGET}"


@pytest.fixture(autouse=True)
def _no_installed_desktop_app(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update_desktop_core, "installed_desktop_app_version", lambda: None)
    monkeypatch.setattr(update_desktop_core, "_onedir_unpack_available", lambda: True)


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
    monkeypatch.setenv("HOL_GUARD_DESKTOP_VERSION", "3.0.113")
    monkeypatch.setattr(update_desktop_core.sys, "platform", "darwin")
    monkeypatch.setattr(update_desktop_core, "platform_target", lambda: TARGET)
    monkeypatch.setattr(update_desktop_core, "desktop_core_root", lambda: tmp_path / "core")
    monkeypatch.setattr(update_desktop_core, "_macos_signing_team", lambda _path: "TEAMID")
    monkeypatch.setattr(update_desktop_core, "_macos_codesign_ok", lambda _path: True)
    monkeypatch.setattr(update_desktop_core, "_verify_onedir_tree_signatures", lambda *_a, **_k: None)
    monkeypatch.setattr(update_desktop_core, "_require_sealed_onedir", lambda _launcher: None)
    monkeypatch.setattr(update_desktop_core, "_unpack_onedir", _fake_unpack)


def _tree_file_count(extracted: Path) -> int:
    return sum(1 for entry in extracted.rglob("*") if entry.is_symlink() or not entry.is_dir())


def _fake_unpack(archive: Path, destination: Path, *, file_count: int) -> None:
    """The native unpack for a plain archive: extract it, then check the launcher and the count."""
    with zipfile.ZipFile(archive) as zipped:
        zipped.extractall(destination)
    launcher = destination / "hol-guard" / "hol-guard"
    if not launcher.is_file() or _tree_file_count(destination) != file_count:
        raise DesktopCoreUpdateError("desktop_core_install_failed")
    launcher.chmod(0o755)


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
        monkeypatch.setenv("HOL_GUARD_DESKTOP_VERSION", "3.0.113")

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

    def test_unknown_desktop_version_skips_onedir_manifest(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("HOL_GUARD_DESKTOP_VERSION", raising=False)
        requested: list[str] = []

        def fetch(url: str, limit: int) -> bytes:
            requested.append(url)
            raise DesktopCoreUpdateError("desktop_core_download_failed")

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
        assert requested == []

    def test_terminal_run_reads_the_installed_desktop_app(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("HOL_GUARD_DESKTOP_VERSION", raising=False)
        monkeypatch.setattr(update_desktop_core.sys, "platform", "darwin")
        monkeypatch.setattr(update_desktop_core, "installed_desktop_app_version", lambda: Version("3.0.145"))
        requested: list[str] = []

        def fetch(url: str, limit: int) -> bytes:
            requested.append(url)
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
        assert requested == [update_desktop_core._release_url(TAG, f"{ARTIFACT}.onedir.json")]

    def test_terminal_run_with_an_old_desktop_app_falls_back(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("HOL_GUARD_DESKTOP_VERSION", raising=False)
        monkeypatch.setattr(update_desktop_core.sys, "platform", "darwin")
        monkeypatch.setattr(update_desktop_core, "installed_desktop_app_version", lambda: Version("3.0.50"))
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

    def test_a_runtime_without_onedir_unpacking_falls_back(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HOL_GUARD_DESKTOP_VERSION", "3.0.113")
        monkeypatch.setattr(update_desktop_core, "_onedir_unpack_available", lambda: False)
        fetched: list[str] = []

        def fetch(url: str, limit: int) -> bytes:
            _ = limit
            fetched.append(url)
            raise DesktopCoreUpdateError("desktop_core_download_failed")

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
        assert fetched == []

    def test_other_download_errors_propagate(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HOL_GUARD_DESKTOP_VERSION", "3.0.113")

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
        self,
        tmp_path: Path,
        *,
        launcher: bytes = b"launcher-bytes",
        tampered_zip: bool = False,
        file_count: int = 4,
    ) -> tuple[dict[str, bytes], object]:
        archive = _onedir_zip(tmp_path, launcher=launcher)
        v2 = _v2_manifest(
            archive=archive,
            launcher_sha256=update_desktop_core._sha256_hex(launcher),
            file_count=file_count,
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

    def test_file_count_mismatch(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _apply_mocks(tmp_path, monkeypatch)
        _urls, fetch = self._fetcher(tmp_path, file_count=5)
        with pytest.raises(DesktopCoreUpdateError) as error:
            update_desktop_core.apply_desktop_core_update(
                current_version="3.0.0a138",
                target_version=VERSION,
                include_alpha=True,
                fetch_bytes=fetch,
            )
        assert error.value.reason_code == "desktop_core_install_failed"
        assert not (tmp_path / "core" / "current.json").exists()

    def test_pointer_failure_restores_previous_tree(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _apply_mocks(tmp_path, monkeypatch)
        existing = tmp_path / "core" / "versions" / VERSION
        existing.mkdir(parents=True)
        (existing / "hol-guard").write_bytes(b"old-onefile")
        _urls, fetch = self._fetcher(tmp_path)
        original_replace = Path.replace

        def failing_replace(self: Path, target: Path) -> Path:
            if Path(target).name == "current.json":
                raise OSError("pointer write failed")
            return original_replace(self, target)

        monkeypatch.setattr(Path, "replace", failing_replace)
        with pytest.raises(DesktopCoreUpdateError) as error:
            update_desktop_core.apply_desktop_core_update(
                current_version="3.0.0a138",
                target_version=VERSION,
                include_alpha=True,
                fetch_bytes=fetch,
            )
        assert error.value.reason_code == "desktop_core_install_failed"
        assert (existing / "hol-guard").read_bytes() == b"old-onefile"
        assert not (existing / "_internal").exists()
        versions = tmp_path / "core" / "versions"
        assert sorted(entry.name for entry in versions.iterdir()) == [VERSION]
        assert not (tmp_path / "core" / "current.json").exists()

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
            file_count=4,
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


class TestUnpackOnedir:
    def test_asks_the_native_runtime(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        calls: list[tuple[str, str, dict[str, object]]] = []

        def answer(
            feature: str, command: str, request: dict[str, object], *, output_limit: int, timeout_seconds: float
        ) -> dict[str, object]:
            _ = (output_limit, timeout_seconds)
            calls.append((feature, command, request))
            return {"unpacked": True}

        monkeypatch.setattr("codex_plugin_scanner.guard.mdm.runtime_request.runtime_answer", answer)
        update_desktop_core._unpack_onedir(tmp_path / "core.zip", tmp_path / "tree", file_count=6)
        assert calls == [
            (
                "native-desktop-core-onedir-v1",
                "desktop-core-onedir",
                {
                    "schema": "desktop-core-onedir.v1",
                    "archive": str(tmp_path / "core.zip"),
                    "destination": str(tmp_path / "tree"),
                    "file_count": 6,
                },
            )
        ]

    @pytest.mark.parametrize("answer", [None, {}, {"unpacked": False}, {"unpacked": "true"}])
    def test_anything_but_unpacked_fails_the_install(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, answer: dict[str, object] | None
    ) -> None:
        monkeypatch.setattr("codex_plugin_scanner.guard.mdm.runtime_request.runtime_answer", lambda *_a, **_k: answer)
        with pytest.raises(DesktopCoreUpdateError) as error:
            update_desktop_core._unpack_onedir(tmp_path / "core.zip", tmp_path / "tree", file_count=6)
        assert error.value.reason_code == "desktop_core_install_failed"


@pytest.mark.skipif(sys.platform != "darwin", reason="real link extraction needs ditto")
class TestInstallFrameworkLinks:
    """End-to-end install of a framework-style tree through real ditto extraction."""

    def _archive(self, tmp_path: Path) -> bytes:
        archive = tmp_path / "links.zip"
        with zipfile.ZipFile(archive, "w") as zipped:
            for name, data, mode in [
                ("hol-guard/hol-guard", b"launcher-bytes", 0o755),
                ("hol-guard/Info.plist", b"<plist/>", 0o644),
                ("hol-guard/_CodeSignature/CodeResources", b"<resources/>", 0o644),
                ("hol-guard/_internal/a.txt", b"data", 0o644),
                ("hol-guard/_internal/Python.framework/Versions/3.12/Python", b"py", 0o755),
            ]:
                info = zipfile.ZipInfo(name)
                info.external_attr = mode << 16
                zipped.writestr(info, data)
            for name, target in [
                ("hol-guard/_internal/Python", b"Python.framework/Versions/3.12/Python"),
                ("hol-guard/_internal/Python.framework/Versions/Current", b"3.12"),
            ]:
                info = zipfile.ZipInfo(name)
                info.external_attr = 0o120777 << 16
                zipped.writestr(info, target)
        return archive.read_bytes()

    def test_installs_tree_with_links_preserved(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import subprocess

        _apply_mocks(tmp_path, monkeypatch)

        def ditto_unpack(archive: Path, destination: Path, *, file_count: int) -> None:
            subprocess.run(
                ["/usr/bin/ditto", "-x", "-k", str(archive), str(destination)],
                check=True,
            )
            assert _tree_file_count(destination) == file_count

        monkeypatch.setattr(update_desktop_core, "_unpack_onedir", ditto_unpack)
        archive_bytes = self._archive(tmp_path)
        v2 = _v2_manifest(
            archive=archive_bytes,
            launcher_sha256=update_desktop_core._sha256_hex(b"launcher-bytes"),
            file_count=7,
        )
        urls = {
            update_desktop_core._release_url(TAG, f"{ARTIFACT}.json"): json.dumps(
                _v1_manifest(sha256="0" * 64, size=1)
            ).encode("utf-8"),
            update_desktop_core._release_url(TAG, f"{ARTIFACT}.onedir.json"): json.dumps(v2).encode("utf-8"),
            update_desktop_core._release_url(TAG, f"{ARTIFACT}.onedir.zip"): archive_bytes,
        }

        def fetch(url: str, limit: int) -> bytes:
            _ = limit
            if url in urls:
                return urls[url]
            raise DesktopCoreUpdateError("desktop_core_asset_missing")

        result = update_desktop_core._try_apply_onedir(
            fetch,
            tag=TAG,
            artifact=ARTIFACT,
            channel="alpha",
            expected_version=VERSION,
            expected_target=TARGET,
        )

        installed = tmp_path / "core" / "versions" / VERSION
        assert result == installed / "hol-guard"
        python_link = installed / "_internal" / "Python"
        assert python_link.is_symlink()
        assert os.readlink(python_link) == "Python.framework/Versions/3.12/Python"
        current_link = installed / "_internal" / "Python.framework" / "Versions" / "Current"
        assert current_link.is_symlink()
        assert os.readlink(current_link) == "3.12"


class TestVerifyOnedirTreeSignatures:
    """The runtime's first failing Mach-O decides the reason code."""

    def test_a_tree_the_runtime_accepts_passes(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        calls: list[tuple[Path, str]] = []

        def failure(tree: Path, *, expected_team: str) -> str | None:
            calls.append((tree, expected_team))
            return None

        monkeypatch.setattr(update_desktop_core, "macos_tree_signature_failure", failure)
        update_desktop_core._verify_onedir_tree_signatures(tmp_path, expected_team="TEAMID")
        assert calls == [(tmp_path, "TEAMID")]

    @pytest.mark.parametrize(
        "reason",
        ["desktop_core_signature_mismatch", "desktop_core_signature_invalid", "desktop_core_install_failed"],
    )
    def test_the_runtime_failure_is_the_reason(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reason: str
    ) -> None:
        monkeypatch.setattr(update_desktop_core, "macos_tree_signature_failure", lambda *_a, **_k: reason)
        with pytest.raises(DesktopCoreUpdateError) as error:
            update_desktop_core._verify_onedir_tree_signatures(tmp_path, expected_team="TEAMID")
        assert error.value.reason_code == reason


class TestRequireSealedOnedir:
    def test_passes_with_sealed_bundle(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(update_desktop_core.sys, "platform", "darwin")
        monkeypatch.setattr(update_desktop_core, "macos_bundle_sealed", lambda _launcher: True)
        update_desktop_core._require_sealed_onedir(tmp_path / "hol-guard")

    def test_fails_without_a_sealed_bundle(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(update_desktop_core.sys, "platform", "darwin")
        monkeypatch.setattr(update_desktop_core, "macos_bundle_sealed", lambda _launcher: False)
        with pytest.raises(DesktopCoreUpdateError) as error:
            update_desktop_core._require_sealed_onedir(tmp_path / "hol-guard")
        assert error.value.reason_code == "desktop_core_signature_invalid"

    def test_other_platforms_need_no_seal(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(update_desktop_core.sys, "platform", "linux")

        def unexpected(_launcher: Path) -> bool:
            raise AssertionError("the seal is a macOS check")

        monkeypatch.setattr(update_desktop_core, "macos_bundle_sealed", unexpected)
        update_desktop_core._require_sealed_onedir(tmp_path / "hol-guard")


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
