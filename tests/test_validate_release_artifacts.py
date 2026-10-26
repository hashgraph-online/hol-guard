from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

import pytest

from scripts.ci.validate_release_artifacts import (
    BUNDLE_ROOT_PATH,
    EXPECTED_PLATFORMS,
    ReleaseArtifactError,
    validate_identity,
    validate_provenance,
    validate_sbom,
    validate_wheel_set,
)

VERSION = "3.0.1"
SOURCE_SHA = "a" * 40
RULE_DIGEST = "b" * 64
NON_WINDOWS = tuple(sorted(set(EXPECTED_PLATFORMS) - {"win_amd64"}))


def _write_wheel(
    root: Path, platform: str, *, runtime: bytes = b"runtime", bundle_root: bytes | None = None, descriptor=None
) -> Path:
    wheel = root / f"hol_guard-{VERSION}-py3-none-{platform}.whl"
    runtime_name = (
        "codex_plugin_scanner/_native/hol-guard-runtime.exe"
        if platform == "win_amd64"
        else ("codex_plugin_scanner/_native/hol-guard-runtime")
    )
    manifest = {
        "schema": "hol-guard-native-runtime.v1",
        "protocol_version": 1,
        "package_version": VERSION,
        "target": EXPECTED_PLATFORMS[platform],
        "platform_tag": platform,
        "source_sha": SOURCE_SHA,
        "rule_digest": RULE_DIGEST,
        "runtime_sha256": hashlib.sha256(runtime).hexdigest(),
        "runtime_size": len(runtime),
    }
    if descriptor is not None:
        manifest["command_pack_bundle"] = descriptor
    with zipfile.ZipFile(wheel, "w") as archive:
        dist_info = f"hol_guard-{VERSION}.dist-info"
        archive.writestr(
            f"{dist_info}/METADATA",
            f"Metadata-Version: 2.4\nName: hol-guard\nVersion: {VERSION}\n\n",
        )
        archive.writestr(
            f"{dist_info}/WHEEL",
            f"Wheel-Version: 1.0\nRoot-Is-Purelib: false\nTag: py3-none-{platform}\n",
        )
        archive.writestr("codex_plugin_scanner/_native/runtime-manifest.json", json.dumps(manifest))
        archive.writestr(runtime_name, runtime)
        if bundle_root is not None:
            archive.writestr(BUNDLE_ROOT_PATH, bundle_root)
    return wheel


def _dist(root: Path, platforms: tuple[str, ...] = NON_WINDOWS) -> Path:
    root.mkdir()
    pure = root / f"hol_guard-{VERSION}-py3-none-any.whl"
    with zipfile.ZipFile(pure, "w") as archive:
        dist_info = f"hol_guard-{VERSION}.dist-info"
        archive.writestr(
            f"{dist_info}/METADATA",
            f"Metadata-Version: 2.4\nName: hol-guard\nVersion: {VERSION}\n\n",
        )
        archive.writestr(
            f"{dist_info}/WHEEL",
            "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        )
    for platform in platforms:
        _write_wheel(root, platform)
    return root


def test_validate_wheel_set_records_non_windows_matrix_and_waiver(tmp_path: Path) -> None:
    evidence = validate_wheel_set(
        _dist(tmp_path / "dist"),
        version=VERSION,
        source_sha=SOURCE_SHA,
        rule_digest=RULE_DIGEST,
        windows_waiver="user-waived-for-this-run",
    )

    assert evidence["platforms"] == list(NON_WINDOWS)
    assert evidence["windows_waiver"] == "user-waived-for-this-run"
    assert len(evidence["artifacts"]) == 4


def test_validate_wheel_set_requires_explicit_windows_waiver(tmp_path: Path) -> None:
    with pytest.raises(ReleaseArtifactError, match="Windows wheel omission"):
        validate_wheel_set(
            _dist(tmp_path / "dist"),
            version=VERSION,
            source_sha=SOURCE_SHA,
            rule_digest=RULE_DIGEST,
        )


def test_validate_wheel_set_accepts_a_windows_only_job(tmp_path: Path) -> None:
    evidence = validate_wheel_set(
        _dist(tmp_path / "dist", ("win_amd64",)),
        version=VERSION,
        source_sha=SOURCE_SHA,
        rule_digest=RULE_DIGEST,
        platforms=("win_amd64",),
    )

    assert evidence["platforms"] == ["win_amd64"]
    assert evidence["windows_waiver"] is None


def test_validate_wheel_set_rejects_manifest_rule_drift(tmp_path: Path) -> None:
    dist = _dist(tmp_path / "dist")
    wheel = dist / f"hol_guard-{VERSION}-py3-none-{NON_WINDOWS[0]}.whl"
    with zipfile.ZipFile(wheel) as archive:
        runtime_name = "codex_plugin_scanner/_native/hol-guard-runtime"
        runtime = archive.read(runtime_name)
        manifest = json.loads(archive.read("codex_plugin_scanner/_native/runtime-manifest.json"))
    manifest["rule_digest"] = "c" * 64
    with zipfile.ZipFile(wheel, "w") as archive:
        dist_info = f"hol_guard-{VERSION}.dist-info"
        archive.writestr(
            f"{dist_info}/METADATA",
            f"Metadata-Version: 2.4\nName: hol-guard\nVersion: {VERSION}\n\n",
        )
        archive.writestr(
            f"{dist_info}/WHEEL",
            f"Wheel-Version: 1.0\nRoot-Is-Purelib: false\nTag: py3-none-{NON_WINDOWS[0]}\n",
        )
        archive.writestr("codex_plugin_scanner/_native/runtime-manifest.json", json.dumps(manifest))
        archive.writestr(runtime_name, runtime)

    with pytest.raises(ReleaseArtifactError, match="manifest identity"):
        validate_wheel_set(
            dist,
            version=VERSION,
            source_sha=SOURCE_SHA,
            rule_digest=RULE_DIGEST,
            windows_waiver="waived",
        )


def test_validate_wheel_set_rejects_unsafe_archive_entry(tmp_path: Path) -> None:
    dist = _dist(tmp_path / "dist", (NON_WINDOWS[0],))
    pure = dist / f"hol_guard-{VERSION}-py3-none-any.whl"
    with zipfile.ZipFile(pure, "a") as archive:
        archive.writestr("../outside.txt", b"escape")

    with pytest.raises(ReleaseArtifactError, match="unsafe archive entry"):
        validate_wheel_set(
            dist,
            version=VERSION,
            source_sha=SOURCE_SHA,
            rule_digest=RULE_DIGEST,
            platforms=(NON_WINDOWS[0],),
            windows_waiver="Windows omitted for this run",
        )


def test_validate_wheel_set_rejects_pathful_windows_waiver(tmp_path: Path) -> None:
    with pytest.raises(ReleaseArtifactError, match="bounded release text"):
        validate_wheel_set(
            _dist(tmp_path / "dist"),
            version=VERSION,
            source_sha=SOURCE_SHA,
            rule_digest=RULE_DIGEST,
            windows_waiver="/tmp/operator-note",
        )


def test_identity_sbom_and_provenance_are_hashable_aggregate_inputs(tmp_path: Path) -> None:
    identity = tmp_path / "policy-identity.json"
    identity.write_text(
        json.dumps(
            {
                "package_version": VERSION,
                "source_sha": SOURCE_SHA,
                "rule_digest": RULE_DIGEST,
                "policy_digest": "d" * 64,
            }
        ),
        encoding="utf-8",
    )
    sbom = tmp_path / "sbom.json"
    sbom.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "metadata": {"component": {"version": VERSION}},
                "components": [],
            }
        ),
        encoding="utf-8",
    )
    provenance = tmp_path / "provenance.jsonl"
    provenance.write_text('{"subject": [{"name": "hol-guard"}]}\n', encoding="utf-8")

    assert (
        validate_identity(identity, version=VERSION, source_sha=SOURCE_SHA, rule_digest=RULE_DIGEST)["policy_digest"]
        == "d" * 64
    )
    assert validate_sbom(sbom, version=VERSION)["format"] == "CycloneDX"
    assert validate_provenance(provenance)["records"] == 1


def test_validate_provenance_accepts_multiline_json_array(tmp_path: Path) -> None:
    provenance = tmp_path / "provenance.json"
    provenance.write_text(
        json.dumps(
            [
                {"subject": [{"name": "hol-guard"}]},
                {"predicateType": "https://slsa.dev/provenance/v1"},
            ],
            indent=2,
        ),
        encoding="utf-8",
    )

    assert validate_provenance(provenance)["records"] == 2


def _bundle_descriptor(bundle_root: bytes) -> dict[str, object]:
    return {
        "schema": "guard.command-pack-bundle.v1",
        "path": BUNDLE_ROOT_PATH,
        "sha256": hashlib.sha256(bundle_root).hexdigest(),
        "length": len(bundle_root),
        "source_sha": SOURCE_SHA,
        "engine": "c" * 64,
    }


def test_validate_wheel_set_accepts_a_bound_command_pack_bundle(tmp_path: Path) -> None:
    dist = _dist(tmp_path / "dist", ())
    bundle_root = b'{"schema":"guard.command-pack-bundle.v1"}'
    _write_wheel(dist, "win_amd64", bundle_root=bundle_root, descriptor=_bundle_descriptor(bundle_root))

    evidence = validate_wheel_set(
        dist, version=VERSION, source_sha=SOURCE_SHA, rule_digest=RULE_DIGEST, platforms=("win_amd64",)
    )

    assert evidence["platforms"] == ["win_amd64"]


@pytest.mark.parametrize(
    ("embedded", "descriptor"),
    [
        (b"other root", _bundle_descriptor(b"root")),
        (None, _bundle_descriptor(b"root")),
        (b"root", None),
        (b"root", {**_bundle_descriptor(b"root"), "source_sha": "d" * 40}),
        (b"root", {**_bundle_descriptor(b"root"), "extra": 1}),
        (b"root", {**_bundle_descriptor(b"root"), "schema": "guard.command-pack-bundle.v2"}),
    ],
)
def test_validate_wheel_set_rejects_an_unbound_command_pack_bundle(
    tmp_path: Path, embedded: bytes | None, descriptor: dict[str, object] | None
) -> None:
    dist = _dist(tmp_path / "dist", ())
    _write_wheel(dist, "win_amd64", bundle_root=embedded, descriptor=descriptor)

    with pytest.raises(ReleaseArtifactError, match="command pack bundle"):
        validate_wheel_set(
            dist, version=VERSION, source_sha=SOURCE_SHA, rule_digest=RULE_DIGEST, platforms=("win_amd64",)
        )
