"""Native alpha wheel selection, verification, and update wiring."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import subprocess
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard.cli import update_alpha_native_wheel as native
from codex_plugin_scanner.guard.cli import update_commands
from codex_plugin_scanner.guard.cli.update_alpha_native_wheel import (
    AlphaNativeWheelError,
    download_alpha_native_wheel,
    parse_provenance_subjects,
    plan_alpha_native_update,
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
WHEEL_BYTES = {platform: f"native wheel for {platform}".encode() for platform in (MAC_ARM, MAC_INTEL, LINUX, WINDOWS)}


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
    files = {native.provenance_name(version): _bundle(subjects if subjects is not None else _subjects(version))}
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
        with pytest.raises(AlphaNativeWheelError) as error:
            parse_provenance_subjects(bad)
        assert error.value.reason_code == "alpha_native_provenance_invalid"


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

    with pytest.raises(AlphaNativeWheelError) as unsupported:
        select_native_wheel(subjects, VERSION, tags=[LINUX])
    assert unsupported.value.reason_code == "alpha_native_platform_unsupported"

    with pytest.raises(AlphaNativeWheelError) as missing:
        select_native_wheel(_subjects(platforms=()), VERSION, tags=[MAC_ARM])
    assert missing.value.reason_code == "alpha_native_asset_missing"


def test_download_verifies_digest_and_returns_private_wheel() -> None:
    release = FakeRelease(_release_files())

    download = download_alpha_native_wheel(VERSION, opener=release, tags=[LINUX])
    try:
        assert download.path.name == _wheel_name(LINUX)
        assert download.path.read_bytes() == WHEEL_BYTES[LINUX]
        assert download.sha256 == _sha(WHEEL_BYTES[LINUX])
        assert all(url.startswith(native.RELEASE_DOWNLOAD_PREFIX + "alpha%2Fv3.43.0a1/") for url in release.requested)
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

    with pytest.raises(AlphaNativeWheelError) as error:
        download_alpha_native_wheel(VERSION, opener=release, tags=[LINUX])

    assert error.value.reason_code == "alpha_native_digest_mismatch"
    assert list(scratch.iterdir()) == []


@pytest.mark.parametrize("missing", ["provenance", "wheel"])
def test_download_fails_closed_when_release_assets_are_gone(missing: str) -> None:
    files = _release_files()
    del files[native.provenance_name(VERSION) if missing == "provenance" else _wheel_name(LINUX)]

    with pytest.raises(AlphaNativeWheelError) as error:
        download_alpha_native_wheel(VERSION, opener=FakeRelease(files), tags=[LINUX])

    assert error.value.reason_code == "alpha_native_release_unavailable"


def test_download_rejects_non_alpha_or_unsafe_versions_without_network() -> None:
    release = FakeRelease(_release_files())
    for version in ("3.43.0", "../3.43.0a1", "3.43.0a1/../../x"):
        with pytest.raises(AlphaNativeWheelError):
            download_alpha_native_wheel(version, opener=release, tags=[LINUX])
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
        return plan_alpha_native_update(**arguments)

    assert plan(include_alpha=False, target_version="3.43.0a2", runtime_missing=True) is None
    assert plan(target_version="3.43.0a2") == native.AlphaNativePlan("3.43.0a2", "upgrade")
    assert plan(target_version="3.44.0") is None
    assert plan() is None
    assert plan(runtime_missing=True) == native.AlphaNativePlan("3.43.0a1", "repair")
    assert plan(runtime_missing=True, platform_supported=False) is None
    assert plan(current_version="3.43.0", runtime_missing=True) is None


def test_bundled_runtime_detection(tmp_path: Path) -> None:
    runtime = tmp_path / "hol-guard-runtime"
    assert native.bundled_native_runtime_missing(runtime) is True
    runtime.write_bytes(b"binary")
    assert native.bundled_native_runtime_missing(runtime) is False


def test_marker_binds_only_the_recorded_digest(tmp_path: Path) -> None:
    assert native.alpha_native_install_recorded(tmp_path, archive_sha256="a" * 64) is False
    native.record_alpha_native_install(tmp_path, version=VERSION, sha256="a" * 64)
    assert native.alpha_native_install_recorded(tmp_path, archive_sha256="a" * 64) is True
    assert native.alpha_native_install_recorded(tmp_path, archive_sha256="b" * 64) is False
    assert native.alpha_native_install_recorded(tmp_path, archive_sha256=None) is False


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
        monkeypatch.setattr(native, "_default_opener", lambda _policy: release)
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

    def run(self, *, dry_run: bool = False, include_alpha: bool = True) -> tuple[dict[str, Any], int]:
        return update_commands._run_guard_update_unlocked(
            dry_run=dry_run, include_alpha=include_alpha, guard_home=self.guard_home
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
    assert native.alpha_native_install_recorded(harness.guard_home, archive_sha256=_sha(WHEEL_BYTES[LINUX]))


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
    assert payload["reason_code"] == "alpha_native_digest_mismatch"
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
    assert payload["reason_code"] == "alpha_native_platform_unsupported"
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
    assert payload["reason_code"] == "alpha_native_release_unavailable"
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
        native.record_alpha_native_install(harness.guard_home, version=VERSION, sha256=digest)

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
    native.record_alpha_native_install(harness.guard_home, version=version, sha256=digest)
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
