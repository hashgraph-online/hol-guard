"""Native wheel selection, verification, and update wiring for alpha and stable releases."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import subprocess
import tempfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from codex_plugin_scanner.guard.cli import native_wheel_sources as sources
from codex_plugin_scanner.guard.cli import update_commands
from codex_plugin_scanner.guard.cli import update_native_wheel as native
from codex_plugin_scanner.guard.cli.native_wheel_sources import NativeWheelError, parse_provenance_subjects
from codex_plugin_scanner.guard.cli.update_native_wheel import (
    download_native_wheel,
    plan_native_wheel_update,
    select_native_wheel,
)
from tests.update_context_test_support import (
    LegacyWheelArtifact,
    build_legacy_status_distribution,
    build_legacy_update_context,
)

VERSION = "3.43.0a1"
MAC_ARM = "macosx_11_0_arm64"
MAC_INTEL = "macosx_13_0_x86_64"
LINUX = "manylinux_2_17_x86_64"
WINDOWS = "win_amd64"
WINDOWS_ARM = "win_arm64"
WHEEL_BYTES = {
    platform: f"native wheel for {platform}".encode() for platform in (MAC_ARM, MAC_INTEL, LINUX, WINDOWS, WINDOWS_ARM)
}
STABLE = "3.44.0"


def _wheel_name(platform: str, version: str = VERSION) -> str:
    return f"hol_guard-{version}-py3-none-{platform}.whl"


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _subjects(version: str = VERSION, platforms: tuple[str, ...] = tuple(WHEEL_BYTES)) -> dict[str, str]:
    subjects = {f"hol_guard-{version}-py3-none-any.whl": _sha(b"pure wheel"), f"hol_guard-{version}.tar.gz": "a" * 64}
    for platform in platforms:
        subjects[_wheel_name(platform, version)] = _sha(WHEEL_BYTES[platform])
    return subjects


def _bundle(
    subjects: dict[str, str],
    *,
    repository: str = "https://github.com/hashgraph-online/hol-guard",
    path: str = ".github/workflows/publish.yml",
) -> bytes:
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": name, "digest": {"sha256": digest}} for name, digest in subjects.items()],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {"externalParameters": {"workflow": {"repository": repository, "path": path}}}
        },
    }
    envelope = {
        "payloadType": "application/vnd.in-toto+json",
        "payload": base64.b64encode(json.dumps(statement).encode()).decode(),
        "signatures": [{"sig": "x"}],
    }
    return json.dumps({"mediaType": "bundle", "dsseEnvelope": envelope}).encode()


class _Response(io.BytesIO):
    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


class FakeRelease:
    """URL-keyed fake opener that records every request."""

    def __init__(self, files: dict[str, bytes]) -> None:
        self.files = files
        self.requested: list[str] = []

    def __call__(self, request: urllib.request.Request) -> _Response:
        url = request.full_url
        self.requested.append(url)
        name = url.rsplit("/", 1)[-1]
        if name not in self.files:
            raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)  # type: ignore[arg-type]
        return _Response(self.files[name])


def _release_files(
    version: str = VERSION,
    *,
    subjects: dict[str, str] | None = None,
    bodies: dict[str, bytes] | None = None,
) -> dict[str, bytes]:
    files = {sources.provenance_name(version): _bundle(subjects if subjects is not None else _subjects(version))}
    for platform, body in (bodies or WHEEL_BYTES).items():
        files[_wheel_name(platform, version)] = body
    return files


def test_provenance_subjects_parse_and_validate() -> None:
    assert parse_provenance_subjects(_bundle(_subjects())) == _subjects()
    for bad in (
        _bundle(_subjects(), repository="https://github.com/someone/else"),
        _bundle(_subjects(), path=".github/workflows/other.yml"),
        _bundle({"hol_guard-1.whl": "not-a-digest"}),
        b"not json",
        b"",
    ):
        with pytest.raises(NativeWheelError) as error:
            parse_provenance_subjects(bad)
        assert error.value.reason_code == "native_wheel_provenance_invalid"


@pytest.mark.parametrize(
    ("tags", "expected"),
    [
        ([MAC_ARM, "macosx_10_9_universal2"], MAC_ARM),
        ([MAC_INTEL], MAC_INTEL),
        (["manylinux_2_28_x86_64", LINUX], LINUX),
        ([WINDOWS], WINDOWS),
    ],
)
def test_select_native_wheel_matches_running_platform(tags: list[str], expected: str) -> None:
    name, digest = select_native_wheel(_subjects(), VERSION, tags=tags)

    assert name == _wheel_name(expected)
    assert digest == _sha(WHEEL_BYTES[expected])


def test_select_native_wheel_never_picks_the_pure_wheel_or_other_versions() -> None:
    subjects = _subjects(platforms=(MAC_ARM,))
    subjects[_wheel_name(LINUX, "3.43.0a2")] = "b" * 64

    with pytest.raises(NativeWheelError) as unsupported:
        select_native_wheel(subjects, VERSION, tags=[LINUX])
    assert unsupported.value.reason_code == "native_wheel_platform_unsupported"

    with pytest.raises(NativeWheelError) as missing:
        select_native_wheel(_subjects(platforms=()), VERSION, tags=[MAC_ARM])
    assert missing.value.reason_code == "native_wheel_asset_missing"


def test_download_verifies_digest_and_returns_private_wheel() -> None:
    release = FakeRelease(_release_files())

    download = download_native_wheel(VERSION, opener=release, tags=[LINUX])
    try:
        assert download.path.name == _wheel_name(LINUX)
        assert download.path.read_bytes() == WHEEL_BYTES[LINUX]
        assert download.sha256 == _sha(WHEEL_BYTES[LINUX])
        assert all(url.startswith(sources.RELEASE_DOWNLOAD_PREFIX + "alpha%2Fv3.43.0a1/") for url in release.requested)
    finally:
        download.cleanup()
    assert not download.directory.exists()


def test_download_rejects_digest_mismatch_and_removes_the_download(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(scratch))
    release = FakeRelease(_release_files(bodies={LINUX: b"tampered"}))

    with pytest.raises(NativeWheelError) as error:
        download_native_wheel(VERSION, opener=release, tags=[LINUX])

    assert error.value.reason_code == "native_wheel_digest_mismatch"
    assert list(scratch.iterdir()) == []


@pytest.mark.parametrize("missing", ["provenance", "wheel"])
def test_download_fails_closed_when_release_assets_are_gone(missing: str) -> None:
    files = _release_files()
    del files[sources.provenance_name(VERSION) if missing == "provenance" else _wheel_name(LINUX)]

    with pytest.raises(NativeWheelError) as error:
        download_native_wheel(VERSION, opener=FakeRelease(files), tags=[LINUX])

    assert error.value.reason_code == "native_wheel_release_unavailable"


def test_download_rejects_invalid_or_unsafe_versions_without_network() -> None:
    release = FakeRelease(_release_files())
    for version in ("not-a-version", "../3.43.0a1", "3.43.0a1/../../x"):
        with pytest.raises(NativeWheelError):
            download_native_wheel(version, opener=release, tags=[LINUX])
    assert release.requested == []


def test_plan_covers_upgrade_repair_and_stable() -> None:
    def plan(**overrides: Any) -> Any:
        arguments: dict[str, Any] = {
            "include_alpha": True,
            "current_version": "3.43.0a1",
            "target_version": None,
            "runtime_missing": False,
            "platform_supported": True,
        }
        arguments.update(overrides)
        return plan_native_wheel_update(**arguments)

    assert plan(include_alpha=False, target_version="3.43.0a2", runtime_missing=True) is None
    assert plan(target_version="3.43.0a2") == native.NativeWheelPlan("3.43.0a2", "upgrade")
    assert plan(target_version="3.44.0") is None
    assert plan() is None
    assert plan(runtime_missing=True) == native.NativeWheelPlan("3.43.0a1", "repair")
    assert plan(runtime_missing=True, platform_supported=False) is None
    assert plan(current_version="3.43.0", runtime_missing=True) == native.NativeWheelPlan("3.43.0", "repair")
    assert plan(include_alpha=False, current_version="3.43.0", target_version="3.44.0", runtime_missing=True) is None
    assert plan(include_alpha=False, target_version="3.44.0", github_only=True) == native.NativeWheelPlan(
        "3.44.0", "upgrade"
    )
    assert plan(target_version="3.44.0", github_only=True, platform_supported=False) is None


def test_bundled_runtime_detection(tmp_path: Path) -> None:
    runtime = tmp_path / "hol-guard-runtime"
    assert native.bundled_native_runtime_missing(runtime) is True
    runtime.write_bytes(b"binary")
    assert native.bundled_native_runtime_missing(runtime) is False


def test_marker_binds_only_the_recorded_digest(tmp_path: Path) -> None:
    assert native.native_wheel_install_recorded(tmp_path, archive_sha256="a" * 64) is False
    native.record_native_wheel_install(tmp_path, version=VERSION, sha256="a" * 64)
    assert native.native_wheel_install_recorded(tmp_path, archive_sha256="a" * 64) is True
    assert native.native_wheel_install_recorded(tmp_path, archive_sha256="b" * 64) is False
    assert native.native_wheel_install_recorded(tmp_path, archive_sha256=None) is False


class UpdateHarness:
    def __init__(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        *,
        current: str,
        latest_alpha: str,
        runtime_missing: bool,
        release: FakeRelease,
        tags: list[str] | None = None,
    ) -> None:
        self.commands: list[list[str]] = []
        self.release = release
        self.installed = current
        self.guard_home = tmp_path / "guard-home"
        self.guard_home.mkdir()
        self.scratch = tmp_path / "scratch"
        self.scratch.mkdir()
        self.staged = tmp_path / "staged"
        self.staged.mkdir()
        monkeypatch.setattr(tempfile, "tempdir", str(self.scratch))
        monkeypatch.setattr(update_commands, "build_trusted_update_context", build_legacy_update_context)
        monkeypatch.setattr(update_commands, "_status_installed_distribution", build_legacy_status_distribution)
        monkeypatch.setattr(update_commands, "stage_trusted_wheel", self._stage)
        monkeypatch.setattr(update_commands, "_current_version", lambda: self.installed)
        monkeypatch.setattr(update_commands, "_current_version_from_subprocess", lambda *_a, **_k: self.installed)
        monkeypatch.setattr(update_commands, "_direct_url_payload", lambda: None)
        monkeypatch.setattr(update_commands, "_installer_kind", lambda: "uv")
        monkeypatch.setattr(update_commands, "_latest_alpha_version_from_pypi", lambda _current: latest_alpha)
        monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "3.42.0")
        monkeypatch.setattr(update_commands, "_retire_native_resident_before_update", lambda _home: True)
        monkeypatch.setattr(update_commands, "_refresh_package_shims_after_update", lambda **_: (None, None))
        monkeypatch.setattr(update_commands, "_repair_supported_harnesses", lambda **_: ([], []))
        monkeypatch.setattr(update_commands, "bundled_native_runtime_missing", lambda: runtime_missing)
        monkeypatch.setattr(native, "_platform_tags", lambda: tags or [LINUX])
        monkeypatch.setattr(native, "default_opener", lambda _policy: release)
        monkeypatch.setattr(update_commands.subprocess, "run", self._run)

    def _stage(self, source: Path, **_kwargs: object) -> LegacyWheelArtifact:
        version = source.name.split("-")[1]
        staged = self.staged / source.name
        staged.write_bytes(source.read_bytes())
        return LegacyWheelArtifact(staged_path=staged, version=version, sha256=_sha(staged.read_bytes()))

    def _run(self, command: list[str], *_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        if command[0] != "uv":
            return subprocess.CompletedProcess(command, 0, "", "")
        self.commands.append(list(command))
        wheel = next((Path(part) for part in command if part.endswith(".whl")), None)
        if wheel is not None:
            self.installed = wheel.name.split("-")[1]
            self.installed_wheel_bytes = wheel.read_bytes()
        return subprocess.CompletedProcess(command, 0, "installed", "")

    def run(
        self, *, dry_run: bool = False, include_alpha: bool = True, native_repair_only: bool = False
    ) -> tuple[dict[str, Any], int]:
        return update_commands._run_guard_update_unlocked(
            dry_run=dry_run,
            include_alpha=include_alpha,
            guard_home=self.guard_home,
            native_repair_only=native_repair_only,
        )


def test_alpha_update_installs_verified_native_wheel_not_the_pypi_pin(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    release = FakeRelease(_release_files("3.43.0a2"))
    harness = UpdateHarness(
        monkeypatch, tmp_path, current="3.43.0a1", latest_alpha="3.43.0a2", runtime_missing=True, release=release
    )

    payload, exit_code = harness.run()

    assert exit_code == 0
    assert payload["status"] == "updated"
    assert payload["upgrade_source"] == "github_alpha_release"
    assert payload["wheel_sha256"] == _sha(WHEEL_BYTES[LINUX])
    assert len(harness.commands) == 1
    command = harness.commands[0]
    assert command[:4] == ["uv", "tool", "install", "--force"]
    assert Path(command[-1]).name == _wheel_name(LINUX, "3.43.0a2")
    assert not any(part.startswith("hol-guard==") for part in command)
    assert harness.installed_wheel_bytes == WHEEL_BYTES[LINUX]
    assert list(harness.scratch.iterdir()) == []
    assert native.native_wheel_install_recorded(harness.guard_home, archive_sha256=_sha(WHEEL_BYTES[LINUX]))


def test_alpha_update_self_heals_pure_wheel_at_the_target_version(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    release = FakeRelease(_release_files())
    harness = UpdateHarness(
        monkeypatch, tmp_path, current=VERSION, latest_alpha=VERSION, runtime_missing=True, release=release
    )

    payload, exit_code = harness.run()

    assert exit_code == 0
    assert payload["status"] == "updated"
    assert payload["native_wheel_reason"] == "repair"
    assert Path(harness.commands[0][-1]).name == _wheel_name(LINUX)
    assert payload["resulting_version"] == VERSION


def test_alpha_update_is_current_when_native_runtime_is_present(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    release = FakeRelease(_release_files())
    harness = UpdateHarness(
        monkeypatch, tmp_path, current=VERSION, latest_alpha=VERSION, runtime_missing=False, release=release
    )

    payload, exit_code = harness.run()

    assert exit_code == 0
    assert payload["status"] == "current"
    assert harness.commands == []
    assert release.requested == []


def test_alpha_check_reports_missing_native_runtime_and_names_the_fix(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    release = FakeRelease(_release_files())
    harness = UpdateHarness(
        monkeypatch, tmp_path, current=VERSION, latest_alpha=VERSION, runtime_missing=True, release=release
    )

    payload, exit_code = harness.run(dry_run=True)

    assert exit_code == 0
    assert payload["status"] == "planned"
    assert payload["changed"] is False
    runtime = payload["native_runtime"]
    assert runtime["status"] == "missing"
    assert runtime["fix"] == "hol-guard update --alpha"
    assert "hol-guard update --alpha" in runtime["message"]
    assert "hol-guard update --alpha" in payload["message"]
    assert release.requested == []
    assert harness.commands == []


def test_stable_update_makes_no_github_calls_and_keeps_the_pypi_command(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    release = FakeRelease(_release_files())
    harness = UpdateHarness(
        monkeypatch, tmp_path, current="3.41.0", latest_alpha="3.43.0a1", runtime_missing=True, release=release
    )

    payload, exit_code = harness.run(include_alpha=False)

    assert exit_code == 0
    assert release.requested == []
    assert "native_runtime" not in payload
    assert payload["upgrade_source"] == "pypi"
    assert harness.commands[0][-1] == "hol-guard==3.42.0"


def test_alpha_update_fails_closed_on_digest_mismatch_without_installing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    release = FakeRelease(_release_files("3.43.0a2", bodies={LINUX: b"tampered"}))
    harness = UpdateHarness(
        monkeypatch, tmp_path, current="3.43.0a1", latest_alpha="3.43.0a2", runtime_missing=True, release=release
    )

    payload, exit_code = harness.run()

    assert exit_code == 1
    assert payload["status"] == "failed"
    assert payload["reason_code"] == "native_wheel_digest_mismatch"
    assert harness.commands == []
    assert list(harness.scratch.iterdir()) == []


def test_alpha_update_fails_closed_without_matching_platform_asset(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    release = FakeRelease(_release_files("3.43.0a2", subjects=_subjects("3.43.0a2", platforms=(MAC_ARM,))))
    harness = UpdateHarness(
        monkeypatch,
        tmp_path,
        current="3.43.0a1",
        latest_alpha="3.43.0a2",
        runtime_missing=True,
        release=release,
        tags=[LINUX],
    )

    payload, exit_code = harness.run()

    assert exit_code == 1
    assert payload["reason_code"] == "native_wheel_platform_unsupported"
    assert harness.commands == []


def test_alpha_update_fails_closed_when_the_prerelease_was_retracted(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    harness = UpdateHarness(
        monkeypatch,
        tmp_path,
        current="3.43.0a1",
        latest_alpha="3.43.0a2",
        runtime_missing=True,
        release=FakeRelease({}),
    )

    payload, exit_code = harness.run()

    assert exit_code == 1
    assert payload["reason_code"] == "native_wheel_release_unavailable"
    assert harness.commands == []


def test_repair_of_a_retracted_alpha_leaves_the_install_alone(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    harness = UpdateHarness(
        monkeypatch,
        tmp_path,
        current=VERSION,
        latest_alpha=VERSION,
        runtime_missing=True,
        release=FakeRelease({}),
    )

    payload, exit_code = harness.run()

    assert exit_code == 0
    assert payload["status"] == "current"
    assert harness.commands == []
    assert any("Could not repair the native runtime" in note for note in payload["notes"])


@pytest.mark.parametrize("recorded", [True, False])
def test_native_wheel_install_stays_updatable_only_when_this_updater_recorded_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, recorded: bool
) -> None:
    release = FakeRelease(_release_files("3.43.0a2"))
    harness = UpdateHarness(
        monkeypatch, tmp_path, current="3.43.0a1", latest_alpha="3.43.0a2", runtime_missing=False, release=release
    )
    digest = _sha(WHEEL_BYTES[LINUX])
    monkeypatch.setattr(
        update_commands,
        "_direct_url_payload",
        lambda: {
            "url": f"file:///private/gone/{_wheel_name(LINUX)}",
            "archive_info": {"hashes": {"sha256": digest}},
        },
    )
    if recorded:
        native.record_native_wheel_install(harness.guard_home, version=VERSION, sha256=digest)

    payload, exit_code = harness.run()

    assert exit_code == 0
    if recorded:
        assert payload["status"] == "updated"
        assert payload["upgrade_source"] == "github_alpha_release"
    else:
        assert payload["status"] == "skipped"
        assert harness.commands == []


def _recorded_native_install(
    monkeypatch: pytest.MonkeyPatch, harness: UpdateHarness, version: str = VERSION, *, runtime_missing: bool = False
) -> None:
    digest = _sha(WHEEL_BYTES[LINUX])
    native.record_native_wheel_install(harness.guard_home, version=version, sha256=digest)
    monkeypatch.setattr(
        update_commands,
        "_direct_url_payload",
        lambda: {
            "url": f"file:///private/gone/{_wheel_name(LINUX)}",
            "archive_info": {"hashes": {"sha256": digest}},
        },
    )
    monkeypatch.setattr(update_commands, "bundled_native_runtime_missing", lambda: runtime_missing)


def test_recorded_native_alpha_with_runtime_present_is_current_and_never_reinstalled(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    release = FakeRelease(_release_files())
    harness = UpdateHarness(
        monkeypatch, tmp_path, current=VERSION, latest_alpha=VERSION, runtime_missing=False, release=release
    )
    _recorded_native_install(monkeypatch, harness)

    payload, exit_code = harness.run()

    assert exit_code == 0
    assert payload["status"] == "current"
    assert harness.commands == []
    assert release.requested == []


def test_unavailable_repair_of_a_recorded_native_alpha_runs_no_installer(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    harness = UpdateHarness(
        monkeypatch, tmp_path, current=VERSION, latest_alpha=VERSION, runtime_missing=True, release=FakeRelease({})
    )
    _recorded_native_install(monkeypatch, harness, runtime_missing=True)

    payload, exit_code = harness.run()

    assert exit_code == 0
    assert payload["status"] == "current"
    assert payload["changed"] is False
    assert harness.commands == []
    assert any("Could not repair the native runtime" in note for note in payload["notes"])


def test_alpha_upgrade_on_a_platform_without_a_native_wheel_keeps_the_pypi_alpha(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    release = FakeRelease(_release_files("3.43.0a2"))
    harness = UpdateHarness(
        monkeypatch,
        tmp_path,
        current="3.43.0a1",
        latest_alpha="3.43.0a2",
        runtime_missing=True,
        release=release,
        tags=["manylinux_2_17_aarch64"],
    )

    payload, exit_code = harness.run()

    assert exit_code == 0
    assert release.requested == []
    assert payload["upgrade_source"] != "github_alpha_release"
    assert harness.commands[0][-1] == "hol-guard==3.43.0a2"
    assert "native_runtime" not in payload


def test_status_does_not_block_a_recorded_native_alpha_install(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    harness = UpdateHarness(
        monkeypatch, tmp_path, current=VERSION, latest_alpha=VERSION, runtime_missing=False, release=FakeRelease({})
    )
    _recorded_native_install(monkeypatch, harness)
    monkeypatch.setattr(update_commands, "load_guard_config", lambda _home: SimpleNamespace(update_channel="alpha"))

    def status() -> dict[str, object]:
        return update_commands.build_guard_update_status_payload(guard_home=harness.guard_home)

    recorded = status()
    (harness.guard_home / "alpha-native-wheel.json").unlink()
    unrecorded = status()

    assert recorded["auto_updatable"] is True
    assert recorded["blocked_reason"] is None
    assert unrecorded["auto_updatable"] is False


def _manifest(version: str = STABLE, platforms: tuple[str, ...] = tuple(WHEEL_BYTES)) -> bytes:
    wheels = {_wheel_name(platform, version): _sha(WHEEL_BYTES[platform]) for platform in platforms}
    return json.dumps({"schema": sources.NATIVE_WHEEL_MANIFEST_SCHEMA, "version": version, "wheels": wheels}).encode()


def _pure_wheel(manifest: bytes | None) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("codex_plugin_scanner/__init__.py", "")
        if manifest is not None:
            archive.writestr(sources.NATIVE_WHEEL_MANIFEST_MEMBER, manifest)
    return buffer.getvalue()


def _stable_release_files(
    version: str = STABLE,
    *,
    manifest: bytes | None = None,
    pure_url_prefix: str = "https://files.pythonhosted.org/packages/ab/cd/",
    pure_digest: str | None = None,
) -> dict[str, bytes]:
    pure = _pure_wheel(manifest if manifest is not None else _manifest(version))
    pure_name = f"hol_guard-{version}-py3-none-any.whl"
    pypi = {
        "urls": [
            {
                "filename": pure_name,
                "url": pure_url_prefix + pure_name,
                "digests": {"sha256": pure_digest or _sha(pure)},
            }
        ]
    }
    files = {"json": json.dumps(pypi).encode(), pure_name: pure}
    for platform in (MAC_INTEL, WINDOWS_ARM):
        files[_wheel_name(platform, version)] = WHEEL_BYTES[platform]
    return files


def test_native_wheel_manifest_parses_and_rejects_bad_documents() -> None:
    assert sources.parse_native_wheel_manifest(_manifest(), STABLE) == {
        _wheel_name(platform, STABLE): _sha(WHEEL_BYTES[platform]) for platform in WHEEL_BYTES
    }
    good = json.loads(_manifest())
    for bad in (
        {**good, "schema": "other"},
        {**good, "version": "3.44.1"},
        {**good, "wheels": {}},
        {**good, "wheels": {_wheel_name(LINUX, STABLE): "not-a-digest"}},
        {**good, "wheels": {f"hol_guard-{STABLE}-py3-none-any.whl": "a" * 64}},
        {**good, "wheels": {_wheel_name(LINUX, "3.44.1"): "a" * 64}},
    ):
        with pytest.raises(NativeWheelError) as error:
            sources.parse_native_wheel_manifest(json.dumps(bad).encode(), STABLE)
        assert error.value.reason_code == "native_wheel_manifest_invalid"
    with pytest.raises(NativeWheelError):
        sources.parse_native_wheel_manifest(b"not json", STABLE)


def test_github_only_platforms_are_intel_mac_and_windows_arm() -> None:
    assert native.github_only_platform([WINDOWS_ARM]) is True
    assert native.github_only_platform([MAC_INTEL]) is True
    assert native.github_only_platform([MAC_ARM, "macosx_10_9_universal2"]) is False
    assert native.github_only_platform([LINUX]) is False
    assert native.github_only_platform(["manylinux_2_17_aarch64"]) is False
    assert native.native_platform_supported([WINDOWS_ARM]) is True


def test_stable_repair_trusts_the_installed_manifest_and_uses_the_stable_tag(tmp_path: Path) -> None:
    (tmp_path / sources.NATIVE_WHEEL_MANIFEST_NAME).write_bytes(_manifest())
    release = FakeRelease(_stable_release_files())

    download = native.download_native_wheel(STABLE, opener=release, tags=[WINDOWS_ARM], package_root=tmp_path)
    try:
        assert download.path.read_bytes() == WHEEL_BYTES[WINDOWS_ARM]
        assert release.requested == [sources.RELEASE_DOWNLOAD_PREFIX + f"v{STABLE}/{_wheel_name(WINDOWS_ARM, STABLE)}"]
    finally:
        download.cleanup()


def test_stable_upgrade_reads_digests_from_the_pypi_pure_wheel(tmp_path: Path) -> None:
    release = FakeRelease(_stable_release_files())

    download = native.download_native_wheel(STABLE, opener=release, tags=[MAC_INTEL], package_root=tmp_path)
    try:
        assert download.sha256 == _sha(WHEEL_BYTES[MAC_INTEL])
        assert release.requested[0] == f"https://pypi.org/pypi/hol-guard/{STABLE}/json"
        assert release.requested[1].startswith("https://files.pythonhosted.org/")
        assert release.requested[2].startswith(sources.RELEASE_DOWNLOAD_PREFIX + f"v{STABLE}/")
    finally:
        download.cleanup()


@pytest.mark.parametrize(
    ("files", "reason"),
    [
        (_stable_release_files(pure_digest="0" * 64), "native_wheel_digest_mismatch"),
        (_stable_release_files(pure_url_prefix="https://example.com/"), "native_wheel_manifest_invalid"),
        (_stable_release_files(manifest=b"{}"), "native_wheel_manifest_invalid"),
        (
            {**_stable_release_files(), _wheel_name(WINDOWS_ARM, STABLE): b"tampered"},
            "native_wheel_digest_mismatch",
        ),
    ],
)
def test_stable_download_fails_closed_without_pypi_backed_digests(
    tmp_path: Path, files: dict[str, bytes], reason: str
) -> None:
    with pytest.raises(NativeWheelError) as error:
        native.download_native_wheel(STABLE, opener=FakeRelease(files), tags=[WINDOWS_ARM], package_root=tmp_path)

    assert error.value.reason_code == reason


def test_stable_pure_wheel_without_a_manifest_is_invalid(tmp_path: Path) -> None:
    files = _stable_release_files()
    pure_name = f"hol_guard-{STABLE}-py3-none-any.whl"
    files[pure_name] = _pure_wheel(None)
    files["json"] = json.dumps(
        {
            "urls": [
                {
                    "filename": pure_name,
                    "url": "https://files.pythonhosted.org/p/" + pure_name,
                    "digests": {"sha256": _sha(files[pure_name])},
                }
            ]
        }
    ).encode()

    with pytest.raises(NativeWheelError) as error:
        native.download_native_wheel(STABLE, opener=FakeRelease(files), tags=[WINDOWS_ARM], package_root=tmp_path)

    assert error.value.reason_code == "native_wheel_manifest_invalid"


def test_manual_install_command_names_the_release_wheel_for_this_host() -> None:
    url = sources.RELEASE_DOWNLOAD_PREFIX + f"v{STABLE}/{_wheel_name(WINDOWS_ARM, STABLE)}"
    assert native.manual_install_command(STABLE, tags=[WINDOWS_ARM]) == (
        f'{native._manual_installer_prefix("pip")} --force-reinstall --no-deps "{url}"'
    )
    assert native.manual_install_command(STABLE, tags=[WINDOWS_ARM], installer="pipx") == (
        f'pipx runpip hol-guard install --force-reinstall --no-deps "{url}"'
    )
    assert "alpha%2Fv3.43.0a1/" in str(native.manual_install_command(VERSION, tags=[LINUX]))
    assert native.manual_install_command(STABLE, tags=["manylinux_2_17_aarch64"]) is None
    assert native.manual_install_command("../x", tags=[LINUX]) is None


def test_stable_update_on_a_github_only_platform_installs_the_release_wheel(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    release = FakeRelease(_stable_release_files("3.42.0"))
    harness = UpdateHarness(
        monkeypatch,
        tmp_path,
        current="3.41.0",
        latest_alpha="3.43.0a1",
        runtime_missing=False,
        release=release,
        tags=[WINDOWS_ARM],
    )

    payload, exit_code = harness.run(include_alpha=False)

    assert exit_code == 0, payload
    assert payload["status"] == "updated"
    assert payload["upgrade_source"] == "github_release"
    assert payload["release_channel"] == "stable"
    assert Path(harness.commands[0][-1]).name == _wheel_name(WINDOWS_ARM, "3.42.0")
    assert harness.installed_wheel_bytes == WHEEL_BYTES[WINDOWS_ARM]


def test_stable_update_failure_prints_the_manual_install_command(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    release = FakeRelease({"json": b"not json"})
    harness = UpdateHarness(
        monkeypatch,
        tmp_path,
        current="3.41.0",
        latest_alpha="3.43.0a1",
        runtime_missing=False,
        release=release,
        tags=[WINDOWS_ARM],
    )

    payload, exit_code = harness.run(include_alpha=False)

    assert exit_code == 1
    assert payload["status"] == "failed"
    assert harness.commands == []
    manual = payload["manual_install"]
    assert _wheel_name(WINDOWS_ARM, "3.42.0") in manual
    assert manual in payload["message"]


def test_stable_upgrade_waits_when_the_github_release_is_not_published_yet(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    release = FakeRelease({})
    harness = UpdateHarness(
        monkeypatch,
        tmp_path,
        current="3.41.0",
        latest_alpha="3.43.0a1",
        runtime_missing=False,
        release=release,
        tags=[WINDOWS_ARM],
    )

    payload, exit_code = harness.run(include_alpha=False)

    assert exit_code == 0
    assert payload["status"] == "current"
    assert payload["resulting_version"] == "3.41.0"
    assert harness.commands == []
    assert "GitHub release is not available yet" in str(payload["message"])


def test_github_only_host_uses_pypi_when_pypi_has_its_native_wheel(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    listing = json.dumps({"urls": [{"filename": _wheel_name(MAC_INTEL, "3.42.0")}]}).encode()
    release = FakeRelease({"json": listing})
    harness = UpdateHarness(
        monkeypatch,
        tmp_path,
        current="3.41.0",
        latest_alpha="3.43.0a1",
        runtime_missing=False,
        release=release,
        tags=[MAC_INTEL],
    )

    harness.run(include_alpha=False)

    assert all("releases/download" not in url for url in release.requested)
    assert harness.commands


def test_native_repair_only_reinstalls_the_current_stable_and_never_upgrades(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    package_root = tmp_path / "package"
    package_root.mkdir()
    (package_root / sources.NATIVE_WHEEL_MANIFEST_NAME).write_bytes(_manifest("3.41.0"))
    monkeypatch.setattr(sources, "_installed_package_root", lambda: package_root)
    release = FakeRelease(_stable_release_files("3.41.0"))
    harness = UpdateHarness(
        monkeypatch,
        tmp_path,
        current="3.41.0",
        latest_alpha="3.43.0a1",
        runtime_missing=True,
        release=release,
        tags=[WINDOWS_ARM],
    )

    installed: list[str] = []

    def install_payload(wheel: Path) -> None:
        installed.append(wheel.name)
        monkeypatch.setattr(update_commands, "bundled_native_runtime_missing", lambda: False)

    monkeypatch.setattr(update_commands, "install_native_payload", install_payload)

    payload, exit_code = harness.run(include_alpha=False, native_repair_only=True)

    assert exit_code == 0, payload
    assert payload["native_wheel_reason"] == "repair"
    assert payload["status"] == "updated"
    assert payload["resulting_version"] == "3.41.0"
    assert installed == [_wheel_name(WINDOWS_ARM, "3.41.0")]
    # The running package is never reinstalled; only its runtime files are added.
    assert harness.commands == []
    assert release.requested == [sources.RELEASE_DOWNLOAD_PREFIX + f"v3.41.0/{_wheel_name(WINDOWS_ARM, '3.41.0')}"]


def test_native_repair_only_is_a_no_op_when_the_runtime_is_present(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    release = FakeRelease({})
    harness = UpdateHarness(
        monkeypatch,
        tmp_path,
        current="3.41.0",
        latest_alpha="3.43.0a1",
        runtime_missing=False,
        release=release,
        tags=[WINDOWS_ARM],
    )

    payload, exit_code = harness.run(include_alpha=False, native_repair_only=True)

    assert exit_code == 0
    assert payload["status"] == "current"
    assert harness.commands == []
    assert release.requested == []


def test_runtime_repair_helper_reinstalls_a_native_wheel_this_updater_recorded(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(update_commands, "run_guard_update", lambda **kwargs: calls.append(kwargs) or ({}, 0))
    monkeypatch.setattr(native, "_platform_tags", lambda: [WINDOWS_ARM])
    monkeypatch.setattr(update_commands, "_is_desktop_managed_runtime", lambda: False)
    monkeypatch.setattr(update_commands, "bundled_native_runtime_missing", lambda: True)
    monkeypatch.setattr(update_commands, "_direct_url_payload", lambda: {"url": "file:///tmp/hol_guard.whl"})
    monkeypatch.setattr(update_commands, "_direct_url_archive_sha256", lambda _payload: "a" * 64)
    native.record_native_wheel_install(tmp_path, version=STABLE, sha256="a" * 64)

    result = update_commands.repair_native_runtime_if_missing(
        context=None, store=None, workspace=None, now=None, guard_home=tmp_path
    )

    assert result == ({}, 0)
    assert calls[0]["native_repair_only"] is True


def test_runtime_repair_helper_skips_desktop_present_runtime_and_non_index_installs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(update_commands, "run_guard_update", lambda **kwargs: calls.append(kwargs) or ({}, 0))
    monkeypatch.setattr(native, "_platform_tags", lambda: [WINDOWS_ARM])

    def repair() -> object:
        return update_commands.repair_native_runtime_if_missing(
            context=None, store=None, workspace=None, now=None, guard_home=None
        )

    scenarios = (
        (True, True, None),
        (False, False, None),
        (False, True, {"url": "file:///tmp/hol_guard.whl"}),
    )
    for desktop, missing, direct_url in scenarios:
        monkeypatch.setattr(update_commands, "_is_desktop_managed_runtime", lambda value=desktop: value)
        monkeypatch.setattr(update_commands, "bundled_native_runtime_missing", lambda value=missing: value)
        monkeypatch.setattr(update_commands, "_direct_url_payload", lambda value=direct_url: value)
        assert repair() is None
    assert calls == []

    monkeypatch.setattr(update_commands, "_is_desktop_managed_runtime", lambda: False)
    monkeypatch.setattr(update_commands, "bundled_native_runtime_missing", lambda: True)
    monkeypatch.setattr(update_commands, "_direct_url_payload", lambda: None)
    assert repair() == ({}, 0)
    assert calls[0]["native_repair_only"] is True
    assert calls[0]["dry_run"] is False


def test_doctor_report_names_the_fix_and_the_manual_command(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(native, "_platform_tags", lambda: [WINDOWS_ARM])
    monkeypatch.setattr(update_commands, "_is_desktop_managed_runtime", lambda: False)
    monkeypatch.setattr(update_commands, "bundled_native_runtime_missing", lambda: True)
    monkeypatch.setattr(update_commands, "_current_version", lambda: STABLE)

    report = update_commands.bundled_native_runtime_report()

    assert report is not None
    assert report["status"] == "missing"
    assert report["fix"] == "hol-guard update"
    assert _wheel_name(WINDOWS_ARM, STABLE) in str(report["manual_install"])
    monkeypatch.setattr(update_commands, "_is_desktop_managed_runtime", lambda: True)
    assert update_commands.bundled_native_runtime_report() is None


@pytest.mark.parametrize("reason_code", ["native_wheel_download_failed", "update_lock_unavailable"])
def test_install_stops_before_wiring_hooks_when_the_runtime_cannot_be_fetched(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str], reason_code: str
) -> None:
    from codex_plugin_scanner.guard.adapters.base import HarnessContext
    from codex_plugin_scanner.guard.cli import commands_dispatch_local as dispatch

    failure = {"status": "failed", "reason_code": reason_code, "message": "run pip by hand"}
    monkeypatch.setattr(dispatch, "repair_native_runtime_if_missing", lambda **_kwargs: (failure, 1))
    monkeypatch.setattr(dispatch, "_migrate_legacy_macos_secrets", lambda _store: None)
    monkeypatch.setattr(
        dispatch, "apply_managed_install", lambda *_args, **_kwargs: pytest.fail("hooks must not be installed")
    )
    context = HarnessContext(home_dir=tmp_path, workspace_dir=None, guard_home=tmp_path / "guard")
    args = SimpleNamespace(dry_run=False, harness="codex", all=False, json=False)

    exit_code = dispatch._run_guard_install_command(args, context=context, store=object())  # type: ignore[arg-type]

    assert exit_code == 1
    assert "run pip by hand" in capsys.readouterr().err


@pytest.mark.parametrize("installer", ["pip", "pipx"])
def test_wheel_reinstall_of_the_same_version_leaves_dependencies_alone(installer: str) -> None:
    wheel = Path("hol_guard-3.41.0-py3-none-win_arm64.whl")

    flags = update_commands._wheel_install_flags("3.41.0", "3.41.0", native_repair=True)
    reinstall = update_commands._update_command(installer, wheel_path=wheel, wheel_flags=flags)
    upgrade = update_commands._update_command(installer, wheel_path=wheel)

    assert reinstall[-3:] == ["--force-reinstall", "--no-deps", str(wheel)]
    assert upgrade[-2:] == ["install", str(wheel)]


def test_same_version_local_wheel_still_installs_its_dependencies() -> None:
    assert update_commands._wheel_install_flags("3.41.0", "3.41.0", native_repair=False) == ("--force-reinstall",)
    assert update_commands._wheel_install_flags("3.42.0", "3.41.0", native_repair=False) == ()
    assert update_commands._wheel_install_flags(None, "3.41.0", native_repair=True) == ()


@pytest.mark.parametrize(("current", "reinstall"), [("3.41.0", True), ("3.40.0", False)])
def test_native_wheel_plan_reinstalls_without_dependencies_only_for_the_installed_version(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, current: str, reinstall: bool
) -> None:
    package_root = tmp_path / "package"
    package_root.mkdir()
    (package_root / sources.NATIVE_WHEEL_MANIFEST_NAME).write_bytes(_manifest(current))
    monkeypatch.setattr(sources, "_installed_package_root", lambda: package_root)
    harness = UpdateHarness(
        monkeypatch,
        tmp_path,
        current=current,
        latest_alpha="3.43.0a1",
        runtime_missing=True,
        release=FakeRelease(_stable_release_files("3.41.0")),
        tags=[WINDOWS_ARM],
    )
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "3.41.0")
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pip")

    payload, _exit_code = harness.run(dry_run=True, include_alpha=False)

    assert payload["command"][-1] == "hol_guard-3.41.0-py3-none-<platform>.whl"
    assert ("--no-deps" in payload["command"]) is reinstall
    assert ("--force-reinstall" in payload["command"]) is reinstall


def test_manual_install_command_targets_the_python_running_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(native.sys, "executable", "/opt/guard venv/bin/python")
    monkeypatch.setattr(native.os, "name", "posix")

    assert native._manual_installer_prefix("pip") == '"/opt/guard venv/bin/python" -m pip install'
    assert native._manual_installer_prefix("uv") == 'uv pip install --python "/opt/guard venv/bin/python"'
    assert native.manual_install_command(STABLE, tags=[WINDOWS_ARM], installer="uv").startswith(  # type: ignore[union-attr]
        'uv pip install --python "/opt/guard venv/bin/python" --reinstall-package hol-guard --no-deps "'
    )


def test_manual_install_command_runs_a_quoted_interpreter_in_powershell(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(native.sys, "executable", r"C:\Users\Jane Doe\venv\Scripts\python.exe")
    monkeypatch.setattr(native.os, "name", "nt")
    monkeypatch.setattr(native, "_windows_short_path", lambda path: path)

    assert native._manual_installer_prefix("pip") == r'& "C:\Users\Jane Doe\venv\Scripts\python.exe" -m pip install'


def test_manual_install_command_prefers_the_windows_short_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(native.sys, "executable", r"C:\Users\Jane Doe\venv\Scripts\python.exe")
    monkeypatch.setattr(native.os, "name", "nt")
    monkeypatch.setattr(native, "_windows_short_path", lambda _path: r"C:\Users\JANEDO~1\venv\Scripts\python.exe")

    assert native._manual_installer_prefix("pip") == r"C:\Users\JANEDO~1\venv\Scripts\python.exe -m pip install"


def test_native_repair_leaves_dependencies_alone_after_downloading_the_wheel(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    package_root = tmp_path / "package"
    package_root.mkdir()
    (package_root / sources.NATIVE_WHEEL_MANIFEST_NAME).write_bytes(_manifest("3.41.0"))
    monkeypatch.setattr(sources, "_installed_package_root", lambda: package_root)
    harness = UpdateHarness(
        monkeypatch,
        tmp_path,
        current="3.41.0",
        latest_alpha="3.43.0a1",
        runtime_missing=True,
        release=FakeRelease(_stable_release_files("3.41.0")),
        tags=[WINDOWS_ARM],
    )
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "3.41.0")
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pip")

    payload, _exit_code = harness.run(include_alpha=False)

    command = cast(list[str], payload["command"])
    assert command[-1].endswith("-win_arm64.whl")
    assert command[-3:-1] == ["--force-reinstall", "--no-deps"]


def _native_wheel_archive(
    path: Path, files: dict[str, bytes], *, record_override: dict[str, str] | None = None
) -> Path:
    rows = []
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in files.items():
            info = zipfile.ZipInfo(name)
            info.external_attr = (0o755 if name.endswith("hol-guard-runtime") else 0o644) << 16
            archive.writestr(info, data)
            digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
            rows.append(f"{name},{(record_override or {}).get(name, 'sha256=' + digest)},{len(data)}")
        rows.append("hol_guard-3.41.0.dist-info/RECORD,,")
        archive.writestr("hol_guard-3.41.0.dist-info/RECORD", "\n".join(rows) + "\n")
    return path


def test_native_payload_adds_runtime_files_and_records_them(tmp_path: Path) -> None:
    site = tmp_path / "site"
    package_root = site / "codex_plugin_scanner"
    package_root.mkdir(parents=True)
    dist_info = site / "hol_guard-3.41.0.dist-info"
    dist_info.mkdir()
    (dist_info / "RECORD").write_text("codex_plugin_scanner/__init__.py,sha256=x,1\n", encoding="utf-8")
    wheel = _native_wheel_archive(
        tmp_path / "native.whl",
        {
            "codex_plugin_scanner/__init__.py": b"changed",
            "codex_plugin_scanner/_native/hol-guard-runtime": b"runtime",
            "codex_plugin_scanner/_native/runtime-manifest.json": b"{}",
        },
    )

    native.install_native_payload(wheel, package_root=package_root)

    runtime = package_root / "_native" / "hol-guard-runtime"
    assert runtime.read_bytes() == b"runtime"
    if os.name != "nt":
        assert runtime.stat().st_mode & 0o111
    # Files outside _native are left to the installed package.
    assert not (package_root / "__init__.py").exists()
    record = (dist_info / "RECORD").read_text(encoding="utf-8")
    assert "codex_plugin_scanner/_native/hol-guard-runtime,sha256=" in record
    assert record.startswith("codex_plugin_scanner/__init__.py,sha256=x,1\n")


def test_native_payload_rejects_files_that_do_not_match_the_record(tmp_path: Path) -> None:
    package_root = tmp_path / "site" / "codex_plugin_scanner"
    package_root.mkdir(parents=True)
    wheel = _native_wheel_archive(
        tmp_path / "native.whl",
        {"codex_plugin_scanner/_native/hol-guard-runtime": b"runtime"},
        record_override={"codex_plugin_scanner/_native/hol-guard-runtime": "sha256=wrong"},
    )

    with pytest.raises(NativeWheelError) as error:
        native.install_native_payload(wheel, package_root=package_root)

    assert error.value.reason_code == "native_wheel_payload_invalid"
    assert not (package_root / "_native" / "hol-guard-runtime").exists()


def test_native_payload_removes_placed_files_when_the_record_cannot_be_read(tmp_path: Path) -> None:
    package_root = tmp_path / "site" / "codex_plugin_scanner"
    package_root.mkdir(parents=True)
    wheel = _native_wheel_archive(
        tmp_path / "native.whl",
        {
            "codex_plugin_scanner/_native/hol-guard-runtime": b"runtime",
            "codex_plugin_scanner/_native/runtime-manifest.json": b"{}",
        },
    )

    with pytest.raises(NativeWheelError) as error:
        native.install_native_payload(wheel, package_root=package_root)

    assert error.value.reason_code == "native_wheel_payload_install_failed"
    assert not (package_root / "_native" / "hol-guard-runtime").exists()


def test_native_payload_rolls_back_when_a_later_file_cannot_move(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    site = tmp_path / "site"
    package_root = site / "codex_plugin_scanner"
    package_root.mkdir(parents=True)
    (site / "hol_guard-3.41.0.dist-info").mkdir()
    (site / "hol_guard-3.41.0.dist-info" / "RECORD").write_text("", encoding="utf-8")
    wheel = _native_wheel_archive(
        tmp_path / "native.whl",
        {
            "codex_plugin_scanner/_native/hol-guard-runtime": b"runtime",
            "codex_plugin_scanner/_native/runtime-manifest.json": b"{}",
        },
    )
    real_replace = os.replace

    def replace(source: Path, target: Path) -> None:
        if Path(target).name == "hol-guard-runtime":
            raise PermissionError("locked")
        real_replace(source, target)

    monkeypatch.setattr(native.os, "replace", replace)

    with pytest.raises(NativeWheelError):
        native.install_native_payload(wheel, package_root=package_root)

    assert list((package_root / "_native").iterdir()) == []
    assert (site / "hol_guard-3.41.0.dist-info" / "RECORD").read_text(encoding="utf-8") == ""
