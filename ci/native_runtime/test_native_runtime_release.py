from __future__ import annotations

import hashlib
import json
import os
import zipfile
from pathlib import Path

import pytest

import scripts.verify_native_runtime_release as release
from scripts.release_registry_types import Registry, ReleaseFile, ReleaseInspection

VERSION = "3.0.0a99"
SOURCE_SHA = "a" * 40
RULE_DIGEST = "b" * 64
TARGETS = {
    "manylinux_2_17_x86_64": "x86_64-unknown-linux-musl",
    "macosx_13_0_x86_64": "x86_64-apple-darwin",
    "macosx_11_0_arm64": "aarch64-apple-darwin",
    "win_amd64": "x86_64-pc-windows-msvc",
    "win_arm64": "aarch64-pc-windows-msvc",
}


def _native_wheel(
    root: Path,
    platform: str,
    *,
    runtime: bytes = b"native-runtime",
    target: str | None = None,
    version: str = VERSION,
) -> Path:
    wheel = root / f"hol_guard-{version}-py3-none-{platform}.whl"
    runtime_path = release.WINDOWS_RUNTIME_PATH if platform.startswith("win") else release.RUNTIME_PATH
    manifest = {
        "schema": "hol-guard-native-runtime.v1",
        "protocol_version": 1,
        "package_version": version,
        "target": target or TARGETS[platform],
        "platform_tag": platform,
        "source_sha": SOURCE_SHA,
        "rule_digest": RULE_DIGEST,
        "runtime_sha256": hashlib.sha256(runtime).hexdigest(),
        "runtime_size": len(runtime),
    }
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(release.MANIFEST_PATH, json.dumps(manifest))
        archive.writestr(runtime_path, runtime)
    return wheel


def _native_set(root: Path) -> dict[str, Path]:
    root.mkdir(parents=True, exist_ok=True)
    return {platform: _native_wheel(root, platform) for platform in TARGETS}


def _pure_wheel(root: Path, project: str) -> Path:
    wheel = root / f"{project.replace('-', '_')}-{VERSION}-py3-none-any.whl"
    wheel.write_bytes(b"pure-wheel-placeholder")
    return wheel


def _sdist(root: Path) -> Path:
    sdist = root / f"hol_guard-{VERSION}.tar.gz"
    sdist.write_bytes(b"source-distribution-placeholder")
    return sdist


def _embed_native_manifest(pure: Path, wheels: dict[str, str], *, version: str = VERSION) -> None:
    document = {"schema": release.NATIVE_WHEEL_MANIFEST_SCHEMA, "version": version, "wheels": wheels}
    with zipfile.ZipFile(pure, "w") as archive:
        archive.writestr(release.NATIVE_WHEEL_MANIFEST_PATH, json.dumps(document))


def _guard_set(root: Path) -> tuple[Path, ...]:
    wheels = _native_set(root)
    pure = _pure_wheel(root, release.PROJECT)
    _embed_native_manifest(pure, {path.name: release._sha256_file(path) for path in wheels.values()})
    sdist = _sdist(root)
    return (*tuple(wheels.values()), pure, sdist)


def _file(path: Path) -> ReleaseFile:
    return ReleaseFile(
        filename=path.name,
        sha256=release._sha256_file(path),
        download_url=f"https://example.invalid/{path.name}",
    )


def _inspection(
    *files: ReleaseFile,
    exists: bool = True,
) -> ReleaseInspection:
    return ReleaseInspection(
        registry=Registry.PYPI,
        version=VERSION,
        exists=exists,
        files=files,
    )


def _base_inspection(*native: ReleaseFile) -> ReleaseInspection:
    base = (
        ReleaseFile(
            filename=f"hol_guard-{VERSION}-py3-none-any.whl",
            sha256="1" * 64,
            download_url="https://example.invalid/pure.whl",
        ),
        ReleaseFile(
            filename=f"hol_guard-{VERSION}.tar.gz",
            sha256="2" * 64,
            download_url="https://example.invalid/source.tar.gz",
        ),
    )
    return _inspection(*(base + native))


def test_expected_platform_targets_are_explicit() -> None:
    assert dict(release.EXPECTED_TARGETS) == TARGETS


def test_local_native_set_requires_every_platform(tmp_path: Path) -> None:
    wheels = _native_set(tmp_path / "dist")
    hashes = release.local_native_hashes(
        tmp_path / "dist",
        version=VERSION,
        source_sha=SOURCE_SHA,
    )
    assert set(hashes) == {path.name for path in wheels.values()}

    wheels["win_amd64"].unlink()
    with pytest.raises(release.NativeReleaseError, match="platform set is incomplete"):
        release.local_native_hashes(
            tmp_path / "dist",
            version=VERSION,
            source_sha=SOURCE_SHA,
        )


def test_local_native_set_accepts_complete_distribution_wheels(
    tmp_path: Path,
) -> None:
    dist_dir = tmp_path / "dist"
    wheels = _native_set(dist_dir)
    _pure_wheel(dist_dir, release.PROJECT)
    _pure_wheel(dist_dir, release.SCANNER_PROJECT)

    hashes = release.local_native_hashes(
        dist_dir,
        version=VERSION,
        source_sha=SOURCE_SHA,
    )

    assert set(hashes) == {path.name for path in wheels.values()}


def test_local_native_set_rejects_unexpected_wheel_project(tmp_path: Path) -> None:
    dist_dir = tmp_path / "dist"
    _native_set(dist_dir)
    _pure_wheel(dist_dir, "unexpected-project")

    with pytest.raises(release.NativeReleaseError, match="Unexpected pure release wheel"):
        release.local_native_hashes(
            dist_dir,
            version=VERSION,
            source_sha=SOURCE_SHA,
        )


def test_local_native_set_binds_platform_tag_to_target(tmp_path: Path) -> None:
    dist_dir = tmp_path / "dist"
    _native_set(dist_dir)
    _native_wheel(
        dist_dir,
        "win_amd64",
        target=TARGETS["manylinux_2_17_x86_64"],
    )

    with pytest.raises(release.NativeReleaseError, match="manifest identity"):
        release.local_native_hashes(
            dist_dir,
            version=VERSION,
            source_sha=SOURCE_SHA,
        )


def test_local_native_set_binds_manifest_to_runtime_bytes(tmp_path: Path) -> None:
    wheels = _native_set(tmp_path / "dist")
    windows = wheels["win_amd64"]
    with zipfile.ZipFile(windows, "a") as archive:
        archive.writestr(release.WINDOWS_RUNTIME_PATH, b"different")
    with pytest.raises(release.NativeReleaseError):
        release.local_native_hashes(
            tmp_path / "dist",
            version=VERSION,
            source_sha=SOURCE_SHA,
        )


def test_local_guard_set_requires_exact_six_artifacts(tmp_path: Path) -> None:
    dist_dir = tmp_path / "dist"
    artifacts = _guard_set(dist_dir)
    hashes = release.local_guard_hashes(
        dist_dir,
        version=VERSION,
        source_sha=SOURCE_SHA,
    )
    assert set(hashes) == {path.name for path in artifacts}

    _sdist(dist_dir).unlink()
    with pytest.raises(release.NativeReleaseError, match="wheel and sdist"):
        release.local_guard_hashes(
            dist_dir,
            version=VERSION,
            source_sha=SOURCE_SHA,
        )


def test_plan_upload_from_absent_registry_copies_complete_release(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifacts = _guard_set(tmp_path / "dist")
    monkeypatch.setattr(
        release,
        "_inspection",
        lambda registry, version: _inspection(exists=False),
    )

    planned = release.plan_upload(
        Registry.PYPI,
        version=VERSION,
        source_sha=SOURCE_SHA,
        dist_dir=tmp_path / "dist",
        output_dir=tmp_path / "upload",
    )

    assert set(planned) == {path.name for path in artifacts}
    assert {path.name for path in (tmp_path / "upload").iterdir()} == set(planned)


def test_plan_upload_copies_only_missing_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifacts = _guard_set(tmp_path / "dist")
    by_name = {path.name: path for path in artifacts}
    existing_names = {
        f"hol_guard-{VERSION}-py3-none-any.whl",
        f"hol_guard-{VERSION}.tar.gz",
        f"hol_guard-{VERSION}-py3-none-manylinux_2_17_x86_64.whl",
    }
    existing = tuple(_file(by_name[name]) for name in sorted(existing_names))
    monkeypatch.setattr(
        release,
        "_inspection",
        lambda registry, version: _inspection(*existing),
    )

    planned = release.plan_upload(
        Registry.PYPI,
        version=VERSION,
        source_sha=SOURCE_SHA,
        dist_dir=tmp_path / "dist",
        output_dir=tmp_path / "upload",
    )

    assert len(planned) == 4
    assert set(planned) == set(by_name) - existing_names
    assert {path.name for path in (tmp_path / "upload").iterdir()} == set(planned)


def test_plan_upload_recovers_when_base_artifacts_are_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifacts = _guard_set(tmp_path / "dist")
    native = next(path for path in artifacts if "win_amd64" in path.name)
    monkeypatch.setattr(
        release,
        "_inspection",
        lambda registry, version: _inspection(_file(native)),
    )

    planned = release.plan_upload(
        Registry.PYPI,
        version=VERSION,
        source_sha=SOURCE_SHA,
        dist_dir=tmp_path / "dist",
        output_dir=tmp_path / "upload",
    )

    assert native.name not in planned
    assert f"hol_guard-{VERSION}-py3-none-any.whl" in planned
    assert f"hol_guard-{VERSION}.tar.gz" in planned
    assert len(planned) == 6


@pytest.mark.skipif(os.name == "nt", reason="POSIX dangling-symlink regression")
def test_plan_upload_refuses_dangling_destination_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifacts = _guard_set(tmp_path / "dist")
    monkeypatch.setattr(
        release,
        "_inspection",
        lambda registry, version: _inspection(exists=False),
    )
    output_dir = tmp_path / "upload"
    output_dir.mkdir()
    first_artifact = min(artifacts, key=lambda path: path.name)
    escaped_target = tmp_path / "escaped.whl"
    (output_dir / first_artifact.name).symlink_to(escaped_target)

    with pytest.raises(release.NativeReleaseError, match="Refusing to overwrite"):
        release.plan_upload(
            Registry.PYPI,
            version=VERSION,
            source_sha=SOURCE_SHA,
            dist_dir=tmp_path / "dist",
            output_dir=output_dir,
        )
    assert not escaped_target.exists()


def test_plan_upload_rejects_existing_conflicting_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifacts = _guard_set(tmp_path / "dist")
    pure = next(path for path in artifacts if path.name.endswith("-py3-none-any.whl"))
    conflicting = ReleaseFile(
        filename=pure.name,
        sha256="f" * 64,
        download_url="https://example.invalid/conflict.whl",
    )
    monkeypatch.setattr(
        release,
        "_inspection",
        lambda registry, version: _inspection(conflicting),
    )
    with pytest.raises(release.NativeReleaseError, match="different bytes"):
        release.plan_upload(
            Registry.PYPI,
            version=VERSION,
            source_sha=SOURCE_SHA,
            dist_dir=tmp_path / "dist",
            output_dir=tmp_path / "upload",
        )


def test_plan_upload_rejects_unexpected_remote_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _guard_set(tmp_path / "dist")
    unexpected = ReleaseFile(
        filename="hol_guard-3.0.0a99-1-py3-none-any.whl",
        sha256="f" * 64,
        download_url="https://example.invalid/unexpected.whl",
    )
    monkeypatch.setattr(
        release,
        "_inspection",
        lambda registry, version: _inspection(unexpected),
    )

    with pytest.raises(release.NativeReleaseError, match="unexpected artifacts"):
        release.plan_upload(
            Registry.PYPI,
            version=VERSION,
            source_sha=SOURCE_SHA,
            dist_dir=tmp_path / "dist",
            output_dir=tmp_path / "upload",
        )


def test_published_release_requires_exact_complete_set(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifacts = _guard_set(tmp_path / "dist")
    remote = tuple(_file(path) for path in artifacts)
    monkeypatch.setattr(
        release,
        "_inspection",
        lambda registry, version: _inspection(*remote),
    )
    release.assert_published_exact(
        Registry.PYPI,
        version=VERSION,
        source_sha=SOURCE_SHA,
        dist_dir=tmp_path / "dist",
    )

    monkeypatch.setattr(
        release,
        "_inspection",
        lambda registry, version: _inspection(*remote[:-1]),
    )
    with pytest.raises(release.NativeReleaseError, match="not the exact"):
        release.assert_published_exact(
            Registry.PYPI,
            version=VERSION,
            source_sha=SOURCE_SHA,
            dist_dir=tmp_path / "dist",
        )


def test_select_upload_artifacts_keeps_only_the_pure_wheel() -> None:
    selected = release.select_upload_artifacts(
        {
            f"hol_guard-{VERSION}-py3-none-any.whl": "aaa",
            f"hol_guard-{VERSION}.tar.gz": "bbb",
        },
        version=VERSION,
        artifact_set="pure",
    )
    assert selected == {f"hol_guard-{VERSION}-py3-none-any.whl": "aaa"}


def test_published_pure_set_matches_only_the_any_wheel(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifacts = _guard_set(tmp_path / "dist")
    pure = next(path for path in artifacts if path.name.endswith("-py3-none-any.whl"))
    monkeypatch.setattr(
        release,
        "_inspection",
        lambda registry, version: _inspection(_file(pure)),
    )
    release.assert_published_exact(
        Registry.PYPI,
        version=VERSION,
        source_sha=SOURCE_SHA,
        dist_dir=tmp_path / "dist",
        artifact_set="pure",
    )


def test_base_release_requires_pure_wheel_and_sdist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inspection = ReleaseInspection(
        registry=Registry.PYPI,
        version=VERSION,
        exists=True,
        files=(
            ReleaseFile(
                filename=f"hol_guard-{VERSION}-py3-none-any.whl",
                sha256="1" * 64,
                download_url="https://example.invalid/pure.whl",
            ),
        ),
    )
    monkeypatch.setattr(release, "_inspection", lambda registry, version: inspection)
    with pytest.raises(
        release.NativeReleaseError,
        match="pure wheel or source distribution",
    ):
        release.assert_base_release_ready(Registry.PYPI, version=VERSION)


def test_base_release_rejects_non_sdist_impostor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inspection = ReleaseInspection(
        registry=Registry.PYPI,
        version=VERSION,
        exists=True,
        files=(
            ReleaseFile(
                filename=f"hol_guard-{VERSION}-py3-none-any.whl",
                sha256="1" * 64,
                download_url="https://example.invalid/pure.whl",
            ),
            ReleaseFile(
                filename="release-notes.txt",
                sha256="2" * 64,
                download_url="https://example.invalid/release-notes.txt",
            ),
        ),
    )
    monkeypatch.setattr(release, "_inspection", lambda registry, version: inspection)
    with pytest.raises(
        release.NativeReleaseError,
        match="pure wheel or source distribution",
    ):
        release.assert_base_release_ready(Registry.PYPI, version=VERSION)


def test_canary_native_set_may_omit_windows_arm64(tmp_path: Path) -> None:
    canary = "3.0.0.dev7"
    dist = tmp_path / "dist"
    dist.mkdir()
    wheels = {
        platform: _native_wheel(dist, platform, version=canary)
        for platform in TARGETS
        if platform not in release.CANARY_OPTIONAL_PLATFORMS
    }
    hashes = release.local_native_hashes(dist, version=canary, source_sha=SOURCE_SHA)
    assert set(hashes) == {path.name for path in wheels.values()}

    wheels["win_amd64"].unlink()
    with pytest.raises(release.NativeReleaseError, match="platform set is incomplete"):
        release.local_native_hashes(dist, version=canary, source_sha=SOURCE_SHA)


def test_release_native_set_requires_windows_arm64(tmp_path: Path) -> None:
    wheels = _native_set(tmp_path / "dist")
    wheels["win_arm64"].unlink()
    with pytest.raises(release.NativeReleaseError, match=r"missing=\['win_arm64'\]"):
        release.local_native_hashes(tmp_path / "dist", version=VERSION, source_sha=SOURCE_SHA)


@pytest.mark.parametrize("change", ["missing", "stale_digest", "missing_wheel", "wrong_version"])
def test_local_guard_set_requires_exact_native_wheel_manifest(tmp_path: Path, change: str) -> None:
    dist = tmp_path / "dist"
    _guard_set(dist)
    pure = dist / f"hol_guard-{VERSION}-py3-none-any.whl"
    wheels = {path.name: release._sha256_file(path) for path in sorted(dist.glob("*.whl")) if path != pure}
    version = VERSION
    if change == "missing":
        pure.write_bytes(b"pure-wheel-placeholder")
    else:
        if change == "stale_digest":
            wheels[next(iter(wheels))] = "0" * 64
        elif change == "missing_wheel":
            wheels.pop(next(iter(wheels)))
        else:
            version = "3.0.0a98"
        _embed_native_manifest(pure, wheels, version=version)
    with pytest.raises(release.NativeReleaseError, match="native wheel manifest"):
        release.local_guard_hashes(dist, version=VERSION, source_sha=SOURCE_SHA)
