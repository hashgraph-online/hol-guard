"""Onedir sidecar feed helpers: manifest, marker suffix, sealing, and signing verification."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import zipfile
from pathlib import Path
from types import ModuleType
from unittest.mock import MagicMock

import pytest

ROOT = Path(__file__).resolve().parents[1]
FEED = ROOT / "scripts" / "release" / "desktop_core_alpha_feed.py"
SEALER = ROOT / "scripts" / "release" / "seal_pyinstaller_native_manifest.py"
SIGNING = ROOT / "scripts" / "release" / "verify_pyinstaller_macos_signing.py"
NATIVE = ROOT / "scripts" / "release" / "verify_pyinstaller_native_runtime.py"
ATTEST = ROOT / "scripts" / "release" / "verify_desktop_core_attestation.py"
CONTRACT = ROOT / "scripts" / "release" / "verify_onedir_activation_under_load.py"
MACHO64 = b"\xcf\xfa\xed\xfe"

CODESIGN_SAMPLE = """\
Executable=/opt/example/hol-guard/hol-guard
Identifier=hol-guard-55554944ff4c9db32c6d920dbb6c6c5356defc59
Format=Mach-O thin (arm64)
CodeDirectory v=20500 size=139219 flags=0x10002(adhoc,runtime) hashes=4339+7 location=embedded
VersionPlatform=1
Hash type=sha256 size=32
CandidateCDHash sha256=2d61886a56d6c7ee29b1527eb5039f390d37af52
TeamIdentifier=not set
Signature=adhoc
"""

CODESIGN_SAMPLE_NO_RUNTIME = """\
Executable=/opt/example/tool
Identifier=tool-55554944ff4c9db32c6d920dbb6c6c5356defc59
Format=Mach-O thin (arm64)
CodeDirectory v=20500 size=139 flags=0x2(adhoc) hashes=4+7 location=embedded
TeamIdentifier=ABCDEF1234
Signature=adhoc
"""


def _load(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _feed() -> ModuleType:
    return _load(FEED, "desktop_core_alpha_feed")


def _tree(root: Path) -> Path:
    tree = root / "dist"
    launcher = tree / "hol-guard" / "hol-guard"
    launcher.parent.mkdir(parents=True)
    launcher.write_bytes(MACHO64 + b"launcher")
    internal = tree / "hol-guard" / "_internal" / "lib"
    internal.mkdir(parents=True)
    (internal / "libx.dylib").write_bytes(MACHO64 + b"lib")
    return tree


def _sealed_zip(path: Path, *, extra: list[tuple[str, bytes, int]] | None = None) -> Path:
    """Build a minimal onedir zip with the sealed-bundle members the feed requires."""
    members = [
        ("hol-guard/hol-guard", MACHO64 + b"launcher", 0o755),
        ("hol-guard/Info.plist", b"<plist/>", 0o644),
        ("hol-guard/_CodeSignature/CodeResources", b"<resources/>", 0o644),
        ("hol-guard/_internal/libx.dylib", MACHO64 + b"lib", 0o644),
    ]
    if extra:
        members.extend(extra)
    with zipfile.ZipFile(path, "w") as zipped:
        for name, data, mode in members:
            info = zipfile.ZipInfo(name)
            info.external_attr = mode << 16
            zipped.writestr(info, data)
    return path


def _identity() -> dict[str, str]:
    return {
        "version": "3.0.7",
        "source_commit": "a" * 40,
        "source_tag": "v3.0.7",
        "target": "aarch64-apple-darwin",
        "minimum_desktop_version": "3.0.113",
    }


class TestInspectAssets:
    def test_no_assets_means_build(self, tmp_path: Path, capsys) -> None:
        namespace = _feed()
        assets = tmp_path / "assets.txt"
        assets.write_text("", encoding="utf-8")
        namespace.inspect_assets(assets, "hol-guard-core-3.0.7-aarch64-apple-darwin")
        output = capsys.readouterr().out
        assert "mode=build" in output
        assert "onedir=true" in output

    def test_legacy_only_means_verify_existing_without_onedir(self, tmp_path: Path, capsys) -> None:
        namespace = _feed()
        base = "hol-guard-core-3.0.7-aarch64-apple-darwin"
        assets = tmp_path / "assets.txt"
        assets.write_text(f"{base}\n{base}.json\n{base}.attested.json\n", encoding="utf-8")
        namespace.inspect_assets(assets, base)
        output = capsys.readouterr().out
        assert "mode=verify_existing" in output
        assert "onedir=false" in output

    def test_full_set_means_verify_existing_with_onedir(self, tmp_path: Path, capsys) -> None:
        namespace = _feed()
        base = "hol-guard-core-3.0.7-aarch64-apple-darwin"
        assets = tmp_path / "assets.txt"
        assets.write_text(
            f"{base}\n{base}.json\n{base}.attested.json\n"
            f"{base}.onedir.zip\n{base}.onedir.json\n{base}.onedir.attested.json\n",
            encoding="utf-8",
        )
        namespace.inspect_assets(assets, base)
        output = capsys.readouterr().out
        assert "mode=verify_existing" in output
        assert "onedir=true" in output

    def test_partial_sets_are_refused(self, tmp_path: Path) -> None:
        namespace = _feed()
        base = "hol-guard-core-3.0.7-aarch64-apple-darwin"
        assets = tmp_path / "assets.txt"
        assets.write_text(f"{base}\n{base}.json\n{base}.attested.json\n{base}.onedir.zip\n", encoding="utf-8")
        with pytest.raises(SystemExit, match="partial or ambiguous"):
            namespace.inspect_assets(assets, base)
        assets.write_text(f"{base}.onedir.zip\n{base}.onedir.json\n{base}.onedir.attested.json\n", encoding="utf-8")
        with pytest.raises(SystemExit, match="partial or ambiguous"):
            namespace.inspect_assets(assets, base)


class TestOnedirManifest:
    def test_create_and_validate_round_trip(self, tmp_path: Path) -> None:
        namespace = _feed()
        tree = _tree(tmp_path)
        archive = _sealed_zip(tmp_path / "hol-guard-core-3.0.7-aarch64-apple-darwin.onedir.zip")
        manifest = tmp_path / "core.onedir.json"
        namespace.create_onedir_manifest(archive, tree, manifest, **_identity())
        namespace.validate_onedir_manifest(archive, tree, manifest, **_identity())
        payload = json.loads(manifest.read_text(encoding="utf-8"))
        assert payload["schema"] == "hol-guard-core-update.v2"
        assert payload["format"] == "onedir-zip"
        assert payload["launcher"] == "hol-guard/hol-guard"
        assert payload["launcherSha256"] == hashlib.sha256((tree / "hol-guard" / "hol-guard").read_bytes()).hexdigest()
        assert payload["fileCount"] == 2
        assert payload["minimumDesktopVersion"] == "3.0.113"

    def test_validate_rejects_mismatch(self, tmp_path: Path) -> None:
        namespace = _feed()
        tree = _tree(tmp_path)
        archive = _sealed_zip(tmp_path / "core.onedir.zip")
        manifest = tmp_path / "core.onedir.json"
        namespace.create_onedir_manifest(archive, tree, manifest, **_identity())
        _sealed_zip(archive, extra=[("hol-guard/_internal/added.txt", b"x", 0o644)])
        with pytest.raises(SystemExit, match="Onedir manifest mismatch"):
            namespace.validate_onedir_manifest(archive, tree, manifest, **_identity())

    def test_missing_launcher_refused(self, tmp_path: Path) -> None:
        namespace = _feed()
        tree = tmp_path / "dist"
        (tree / "hol-guard" / "_internal").mkdir(parents=True)
        archive = _sealed_zip(tmp_path / "core.onedir.zip")
        with pytest.raises(SystemExit, match="missing its launcher"):
            namespace.create_onedir_manifest(archive, tree, tmp_path / "m.json", **_identity())


class TestOnedirZipMembers:
    def test_accepts_sealed_zip(self, tmp_path: Path) -> None:
        namespace = _feed()
        archive = _sealed_zip(tmp_path / "core.onedir.zip")
        namespace.validate_onedir_zip_members(archive)

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
        namespace = _feed()
        archive = _sealed_zip(tmp_path / "core.onedir.zip", extra=[(member, b"x", 0o644)])
        with pytest.raises(SystemExit):
            namespace.validate_onedir_zip_members(archive)

    def test_rejects_symlink_member(self, tmp_path: Path) -> None:
        namespace = _feed()
        archive = _sealed_zip(tmp_path / "core.onedir.zip", extra=[("hol-guard/_internal/link", b"target", 0o120777)])
        with pytest.raises(SystemExit, match="symlink"):
            namespace.validate_onedir_zip_members(archive)

    @pytest.mark.parametrize(
        "missing",
        [
            "hol-guard/hol-guard",
            "hol-guard/Info.plist",
            "hol-guard/_CodeSignature/CodeResources",
            "hol-guard/_internal/libx.dylib",
        ],
    )
    def test_rejects_missing_required_member(self, tmp_path: Path, missing: str) -> None:
        namespace = _feed()
        archive = tmp_path / "core.onedir.zip"
        members = [
            ("hol-guard/hol-guard", MACHO64 + b"launcher"),
            ("hol-guard/Info.plist", b"<plist/>"),
            ("hol-guard/_CodeSignature/CodeResources", b"<resources/>"),
            ("hol-guard/_internal/libx.dylib", MACHO64 + b"lib"),
        ]
        with zipfile.ZipFile(archive, "w") as zipped:
            for name, data in members:
                if name != missing:
                    zipped.writestr(name, data)
        with pytest.raises(SystemExit, match="missing required member"):
            namespace.validate_onedir_zip_members(archive)


class TestOnedirMarker:
    def test_base_suffix_binds_zip_and_onedir_manifest(self, tmp_path: Path) -> None:
        namespace = _feed()
        base = tmp_path / "core"
        zip_path = Path(f"{base}.onedir.zip")
        manifest = Path(f"{base}.onedir.json")
        marker = Path(f"{base}.onedir.attested.json")
        zip_path.write_bytes(b"zip-subject")
        manifest.write_bytes(b"manifest-subject")
        common = dict(
            version="3.0.7",
            source_commit="a" * 40,
            source_tag="v3.0.7",
            target="aarch64-apple-darwin",
            apple_signing_identity="Developer ID Application: HOL",
            apple_team_id="TEAMID",
        )
        namespace.create_marker(base, marker, workflow_run="9", base_suffix=".onedir", **common)
        namespace.validate_marker(base, marker, base_suffix=".onedir", **common)
        payload = json.loads(marker.read_text(encoding="utf-8"))
        assert payload["binarySha256"] == hashlib.sha256(b"zip-subject").hexdigest()
        assert payload["manifestSha256"] == hashlib.sha256(b"manifest-subject").hexdigest()

    def test_base_suffix_detects_tampering(self, tmp_path: Path) -> None:
        namespace = _feed()
        base = tmp_path / "core"
        zip_path = Path(f"{base}.onedir.zip")
        manifest = Path(f"{base}.onedir.json")
        marker = Path(f"{base}.onedir.attested.json")
        zip_path.write_bytes(b"zip-subject")
        manifest.write_bytes(b"manifest-subject")
        common = dict(
            version="3.0.7",
            source_commit="a" * 40,
            source_tag="v3.0.7",
            target="aarch64-apple-darwin",
            apple_signing_identity="Developer ID Application: HOL",
            apple_team_id="TEAMID",
        )
        namespace.create_marker(base, marker, workflow_run="9", base_suffix=".onedir", **common)
        zip_path.write_bytes(b"tampered")
        with pytest.raises(SystemExit, match="Marker hash mismatch"):
            namespace.validate_marker(base, marker, base_suffix=".onedir", **common)


class TestSealOnedir:
    def _native_dir(self, tmp_path: Path) -> Path:
        native = tmp_path / "tree" / "_internal" / "codex_plugin_scanner" / "_native"
        native.mkdir(parents=True)
        (native / "hol-guard-runtime").write_bytes(b"runtime-bytes")
        (native / "runtime-manifest.json").write_text(
            json.dumps({"schema": "hol-guard-native-runtime.v1", "runtime_sha256": "0" * 64, "runtime_size": 1}),
            encoding="utf-8",
        )
        return native

    def test_reseal_updates_manifest(self, tmp_path: Path) -> None:
        module = _load(SEALER, "seal_pyinstaller_native_manifest")
        native = self._native_dir(tmp_path)
        module.seal_onedir(tmp_path / "tree")
        payload = json.loads((native / "runtime-manifest.json").read_text(encoding="utf-8"))
        runtime = (native / "hol-guard-runtime").read_bytes()
        assert payload["runtime_sha256"] == hashlib.sha256(runtime).hexdigest()
        assert payload["runtime_size"] == len(runtime)

    def test_matching_manifest_is_left_untouched(self, tmp_path: Path) -> None:
        module = _load(SEALER, "seal_pyinstaller_native_manifest")
        native = self._native_dir(tmp_path)
        runtime = (native / "hol-guard-runtime").read_bytes()
        manifest = native / "runtime-manifest.json"
        manifest.write_text(
            json.dumps(
                {
                    "schema": "hol-guard-native-runtime.v1",
                    "runtime_sha256": hashlib.sha256(runtime).hexdigest(),
                    "runtime_size": len(runtime),
                }
            ),
            encoding="utf-8",
        )
        before = manifest.read_bytes()
        module.seal_onedir(tmp_path / "tree")
        assert manifest.read_bytes() == before

    def test_missing_files_raise(self, tmp_path: Path) -> None:
        module = _load(SEALER, "seal_pyinstaller_native_manifest")
        (tmp_path / "tree").mkdir()
        with pytest.raises(module.NativeManifestSealError):
            module.seal_onedir(tmp_path / "tree")


class TestSignatureInfo:
    def test_parses_team_and_runtime_flag(self, monkeypatch: pytest.MonkeyPatch) -> None:
        module = _load(SIGNING, "verify_pyinstaller_macos_signing")
        completed = MagicMock(returncode=0, stderr=CODESIGN_SAMPLE, stdout="")
        monkeypatch.setattr(module.subprocess, "run", lambda *a, **k: completed)
        team, flags = module._signature_info(Path("/opt/example/hol-guard/hol-guard"))
        assert team == "not set"
        assert flags & 0x10002 == 0x10002

    def test_parses_signed_without_runtime(self, monkeypatch: pytest.MonkeyPatch) -> None:
        module = _load(SIGNING, "verify_pyinstaller_macos_signing")
        completed = MagicMock(returncode=0, stderr=CODESIGN_SAMPLE_NO_RUNTIME, stdout="")
        monkeypatch.setattr(module.subprocess, "run", lambda *a, **k: completed)
        team, flags = module._signature_info(Path("/opt/example/tool"))
        assert team == "ABCDEF1234"
        assert flags & 0x10000 == 0


class TestVerifyOnedirSigning:
    def _tree(self, tmp_path: Path) -> Path:
        tree = tmp_path / "tree"
        (tree / "_internal").mkdir(parents=True)
        (tree / "_CodeSignature").mkdir()
        (tree / "_CodeSignature" / "CodeResources").write_text("<resources/>", encoding="utf-8")
        (tree / "hol-guard").write_bytes(MACHO64 + b"launcher")
        (tree / "_internal" / "libx.dylib").write_bytes(MACHO64 + b"lib")
        (tree / "_internal" / "data.txt").write_text("not macho", encoding="utf-8")
        return tree

    def _pass_seal(self, module: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(module, "require_onedir_seal", lambda _tree: None)

    def test_all_matching_team_and_runtime_passes(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        module = _load(SIGNING, "verify_pyinstaller_macos_signing")
        self._pass_seal(module, monkeypatch)
        monkeypatch.setattr(module, "_signature_info", lambda _path: ("TEAMID", 0x10000))
        module.verify_onedir(self._tree(tmp_path), "TEAMID")

    def test_mixed_team_names_relative_path(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        module = _load(SIGNING, "verify_pyinstaller_macos_signing")
        self._pass_seal(module, monkeypatch)

        def fake_info(path: Path) -> tuple[str, int]:
            if path.name == "libx.dylib":
                return ("OTHERTEAM", 0x10000)
            return ("TEAMID", 0x10000)

        monkeypatch.setattr(module, "_signature_info", fake_info)
        with pytest.raises(ValueError, match=r"_internal/libx\.dylib"):
            module.verify_onedir(self._tree(tmp_path), "TEAMID")

    def test_missing_runtime_flag_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        module = _load(SIGNING, "verify_pyinstaller_macos_signing")
        self._pass_seal(module, monkeypatch)
        monkeypatch.setattr(module, "_signature_info", lambda _path: ("TEAMID", 0x0))
        with pytest.raises(ValueError, match="hardened-runtime"):
            module.verify_onedir(self._tree(tmp_path), "TEAMID")

    def test_no_macho_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        module = _load(SIGNING, "verify_pyinstaller_macos_signing")
        self._pass_seal(module, monkeypatch)
        tree = tmp_path / "tree"
        tree.mkdir()
        (tree / "data.txt").write_text("plain", encoding="utf-8")
        with pytest.raises(ValueError, match="no Mach-O"):
            module.verify_onedir(tree, "TEAMID")

    def test_fails_without_app_bundle_format(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        module = _load(SIGNING, "verify_pyinstaller_macos_signing")
        display = MagicMock(returncode=0, stderr="Format=Mach-O thin (arm64)\nTeamIdentifier=TEAMID\n", stdout="")
        monkeypatch.setattr(module.subprocess, "run", lambda *a, **k: display)
        with pytest.raises(ValueError, match="not sealed as an app bundle"):
            module.verify_onedir(self._tree(tmp_path), "TEAMID")

    def test_fails_without_sealed_resources_line(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        module = _load(SIGNING, "verify_pyinstaller_macos_signing")
        display = MagicMock(
            returncode=0,
            stderr="Format=app bundle with Mach-O thin (arm64)\nTeamIdentifier=TEAMID\n",
            stdout="",
        )
        monkeypatch.setattr(module.subprocess, "run", lambda *a, **k: display)
        with pytest.raises(ValueError, match="does not declare sealed resources"):
            module.verify_onedir(self._tree(tmp_path), "TEAMID")

    def test_fails_when_verify_strict_rejects_seal(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        module = _load(SIGNING, "verify_pyinstaller_macos_signing")
        display = MagicMock(
            returncode=0,
            stderr="Format=app bundle with Mach-O thin (arm64)\nSealed Resources version=2 rules=10 files=2\n",
            stdout="",
        )
        bad_verify = MagicMock(returncode=1, stderr="a sealed resource is missing or invalid", stdout="")
        calls = iter((display, bad_verify))
        monkeypatch.setattr(module.subprocess, "run", lambda *a, **k: next(calls))
        with pytest.raises(ValueError, match="failed sealed-resource verification"):
            module.verify_onedir(self._tree(tmp_path), "TEAMID")

    def test_fails_without_code_resources(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        module = _load(SIGNING, "verify_pyinstaller_macos_signing")
        display = MagicMock(returncode=0, stderr="Format=app bundle\nSealed Resources version=2\n", stdout="")
        monkeypatch.setattr(module.subprocess, "run", lambda *a, **k: display)
        tree = self._tree(tmp_path)
        (tree / "_CodeSignature" / "CodeResources").unlink()
        with pytest.raises(ValueError, match="CodeResources"):
            module.verify_onedir(tree, "TEAMID")


class TestVerifyOnedirNativeRuntime:
    def _native_dir(self, tmp_path: Path) -> Path:
        native = tmp_path / "tree" / "_internal" / "codex_plugin_scanner" / "_native"
        native.mkdir(parents=True)
        runtime = b"runtime-bytes"
        (native / "hol-guard-runtime").write_bytes(runtime)
        (native / "runtime-manifest.json").write_text(
            json.dumps(
                {
                    "schema": "hol-guard-native-runtime.v1",
                    "runtime_sha256": hashlib.sha256(runtime).hexdigest(),
                    "runtime_size": len(runtime),
                }
            ),
            encoding="utf-8",
        )
        return native

    def test_good_pair_passes(self, tmp_path: Path) -> None:
        module = _load(NATIVE, "verify_pyinstaller_native_runtime")
        self._native_dir(tmp_path)
        module.verify_onedir(tmp_path / "tree")

    def test_tampered_runtime_fails(self, tmp_path: Path) -> None:
        module = _load(NATIVE, "verify_pyinstaller_native_runtime")
        native = self._native_dir(tmp_path)
        (native / "hol-guard-runtime").write_bytes(b"other-bytes")
        with pytest.raises(ValueError, match="digest does not match"):
            module.verify_onedir(tmp_path / "tree")

    def test_missing_pair_fails(self, tmp_path: Path) -> None:
        module = _load(NATIVE, "verify_pyinstaller_native_runtime")
        (tmp_path / "tree").mkdir()
        with pytest.raises(ValueError, match="native runtime pair"):
            module.verify_onedir(tmp_path / "tree")


class TestVerifyArchiveAttestation:
    def _fixture(self, tmp_path: Path) -> tuple[Path, Path, Path]:
        tree = tmp_path / "extract-src"
        launcher = tree / "hol-guard" / "hol-guard"
        native = tree / "hol-guard" / "_internal" / "codex_plugin_scanner" / "_native"
        native.mkdir(parents=True)
        launcher.parent.mkdir(parents=True, exist_ok=True)
        launcher.write_bytes(b"launcher-bytes")
        (native / "hol-guard-runtime").write_bytes(b"runtime")
        archive = tmp_path / "core.onedir.zip"
        with zipfile.ZipFile(archive, "w") as zipped:
            for file in tree.rglob("*"):
                if file.is_file():
                    zipped.write(file, file.relative_to(tree).as_posix())
        manifest = tmp_path / "core.onedir.json"
        marker = tmp_path / "core.onedir.attested.json"
        manifest.write_text(
            json.dumps(
                {
                    "schema": "hol-guard-core-update.v2",
                    "channel": "stable",
                    "version": "3.0.7",
                    "sourceCommit": "a" * 40,
                    "sourceTag": "v3.0.7",
                    "target": "aarch64-apple-darwin",
                    "format": "onedir-zip",
                    "artifact": archive.name,
                    "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                    "size": archive.stat().st_size,
                    "launcher": "hol-guard/hol-guard",
                    "launcherSha256": hashlib.sha256(b"launcher-bytes").hexdigest(),
                    "fileCount": 2,
                    "bootstrapSchema": "guard-desktop-bootstrap.v1",
                    "minimumDesktopVersion": "3.0.113",
                }
            ),
            encoding="utf-8",
        )
        marker.write_text(
            json.dumps(
                {
                    "schema": "hol-guard-core-attestation.v3",
                    "version": "3.0.7",
                    "sourceCommit": "a" * 40,
                    "sourceTag": "v3.0.7",
                    "target": "aarch64-apple-darwin",
                    "binarySha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                    "manifestSha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
                    "appleSigningIdentity": "Developer ID Application: HOL",
                    "appleTeamId": "TEAMID",
                    "workflowRun": "9",
                    "attestedAt": "2026-09-29T00:00:00Z",
                }
            ),
            encoding="utf-8",
        )
        return archive, manifest, marker

    def _stub_verifier(self, module: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
        verifier = MagicMock()
        signing = MagicMock()
        signing._team_id = lambda _path: "TEAMID"
        signing.require_onedir_seal = lambda _tree: None
        verifier._load_signing_module = lambda: signing
        verifier.verify_onedir = lambda _tree, expected_team_id=None: None
        monkeypatch.setattr(module, "_native_verifier", lambda: verifier)

    def _common(self) -> dict[str, str]:
        return {
            "version": "3.0.7",
            "source_commit": "a" * 40,
            "source_tag": "v3.0.7",
            "target": "aarch64-apple-darwin",
            "expected_team_id": "TEAMID",
        }

    def test_happy_path(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        module = _load(ATTEST, "verify_desktop_core_attestation")
        self._stub_verifier(module, monkeypatch)
        archive, manifest, marker = self._fixture(tmp_path)
        evidence = module.verify_archive(archive, manifest, marker, **self._common())
        assert evidence["post_sign_verified"] is True
        assert evidence["binary"]["name"] == archive.name

    def test_manifest_mismatch(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        module = _load(ATTEST, "verify_desktop_core_attestation")
        self._stub_verifier(module, monkeypatch)
        archive, manifest, marker = self._fixture(tmp_path)
        payload = json.loads(manifest.read_text(encoding="utf-8"))
        payload["version"] = "3.0.8"
        manifest.write_text(json.dumps(payload), encoding="utf-8")
        with pytest.raises(module.DesktopAttestationError, match="manifest mismatch"):
            module.verify_archive(archive, manifest, marker, **self._common())

    def test_launcher_digest_mismatch(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        module = _load(ATTEST, "verify_desktop_core_attestation")
        self._stub_verifier(module, monkeypatch)
        archive, manifest, marker = self._fixture(tmp_path)
        payload = json.loads(manifest.read_text(encoding="utf-8"))
        payload["launcherSha256"] = "0" * 64
        manifest.write_text(json.dumps(payload), encoding="utf-8")
        payload_marker = json.loads(marker.read_text(encoding="utf-8"))
        payload_marker["manifestSha256"] = hashlib.sha256(manifest.read_bytes()).hexdigest()
        marker.write_text(json.dumps(payload_marker), encoding="utf-8")
        with pytest.raises(module.DesktopAttestationError, match="launcher digest mismatch"):
            module.verify_archive(archive, manifest, marker, **self._common())

    def test_linux_target_refused(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        module = _load(ATTEST, "verify_desktop_core_attestation")
        self._stub_verifier(module, monkeypatch)
        archive, manifest, marker = self._fixture(tmp_path)
        common = self._common()
        common["target"] = "x86_64-unknown-linux-gnu"
        with pytest.raises(module.DesktopAttestationError, match="macOS-only"):
            module.verify_archive(archive, manifest, marker, **common)


class TestContractTestHelpers:
    def test_parse_gk_events(self) -> None:
        module = _load(CONTRACT, "verify_onedir_activation_under_load")
        lines = [
            "2026-09-29 12:00:00.000 syspolicyd[1]: GK performScan: PST: (path: abc), (team: X), (id: hol-guard)",
            "2026-09-29 12:00:01.000 syspolicyd[1]: "
            "GK evaluateScanResult: 0, PST: (path: def), (team: X), (id: hol-guard)",
            "2026-09-29 12:00:02.000 syspolicyd[1]: GK evaluateScanResult: 0, PST: (path: ghi), (team: Y), (id: other)",
            "unrelated log line",
        ]
        counts = module.parse_gk_events(lines)
        assert counts == {"gk_perform_scan": 1, "gk_evaluate_launcher": 1}

    def test_budget_boundary(self) -> None:
        module = _load(CONTRACT, "verify_onedir_activation_under_load")
        assert module.decide_within_budget(149.9, 150.0) is True
        assert module.decide_within_budget(150.0, 150.0) is False
        assert module.decide_within_budget(200.0, 150.0) is False

    def test_markdown_summary_includes_verdict(self) -> None:
        module = _load(CONTRACT, "verify_onedir_activation_under_load")
        record = {
            "warm_seconds": 0.2,
            "activation_seconds": 7.3,
            "budget_seconds": 150.0,
            "within_budget": True,
            "noise_processes": 8,
            "gk_perform_scan": 120,
            "gk_evaluate_launcher": 3,
            "gk_check": "ok",
            "core_version": "3.8.0",
            "verdict": "pass",
        }
        rendered = module.format_markdown_summary(record)
        assert "Onedir activation under onefile load" in rendered
        assert "| verdict | pass |" in rendered
        assert "| activation_seconds | 7.3 |" in rendered
