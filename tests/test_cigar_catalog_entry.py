"""Maintainer drafts cannot bypass locks, dependency closure or qualification."""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

_PATH = Path(__file__).resolve().parents[1] / "scripts" / "cigar_catalog_entry.py"
_SPEC = importlib.util.spec_from_file_location("cigar_catalog_entry", _PATH)
assert _SPEC and _SPEC.loader
tool = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(tool)


def fixture(tmp_path, requires="protobuf>=6.33.5,<8", *, sdk_version="0.99.5", core_version="0.99.3"):
    worker = b"synthetic worker bytes, never executed"
    sdk = tmp_path / f"hol_cigar-{sdk_version}-py3-none-any.whl"
    dep = tmp_path / "protobuf-7.36.2-py3-none-any.whl"
    for path, name, version in [(sdk, "hol-cigar", sdk_version), (dep, "protobuf", "7.36.2")]:
        info = f"{name.replace('-', '_')}-{version}.dist-info"
        with ZipFile(path, "w", ZIP_DEFLATED) as archive:
            metadata = f"Metadata-Version: 2.4\nName: {name}\nVersion: {version}\nRequires-Python: >=3.14,<3.15\n"
            if name == "hol-cigar":
                metadata += f"Requires-Dist: {requires}\n"
                archive.writestr(
                    "cigar_sdk/release.json",
                    json.dumps(
                        {
                            "version": version,
                            "local_context_core_version": core_version,
                            "local_context_protocol": "cigar.context-worker.v1",
                        }
                    ),
                )
                base = "cigar_sdk/_native/darwin-arm64/"
                archive.writestr(base + "cigar-context-worker", worker)
                archive.writestr(
                    base + "manifest.json",
                    json.dumps(
                        {
                            "core_version": core_version,
                            "sdk_release": version,
                            "protocol": "cigar.context-worker.v1",
                            "sha256": hashlib.sha256(worker).hexdigest(),
                        }
                    ),
                )
            else:
                archive.writestr("google/protobuf/__init__.py", b"# synthetic dependency")
            archive.writestr(info + "/METADATA", metadata + "\n")
            archive.writestr(info + "/WHEEL", "Wheel-Version: 1.0\nTag: py3-none-any\n")
    manifest = tmp_path / "release-manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema": "cigar.context-sdk-distribution-release.v1",
                "source_commit": "a" * 40,
                "release": sdk_version,
                "payloads": [
                    {
                        "file": sdk.name,
                        "bytes": sdk.stat().st_size,
                        "sha256": hashlib.sha256(sdk.read_bytes()).hexdigest(),
                    }
                ],
            }
        )
    )
    return argparse.Namespace(
        sdk_wheel=sdk,
        dependency_wheel=[dep],
        release_manifest=manifest,
        platform="darwin-arm64",
        build_id="synthetic-only-0_99_5",
        python_version="3.14.7",
    )


def test_preview_draft_preserves_exact_native_core_and_non_pep440_release_tag(tmp_path):
    args = fixture(tmp_path, sdk_version="0.99.5rc1+candidate.7", core_version="native-0.99.3-rc.2+arm64.9")
    args.release_tag = "v0.99.5-rc.1-candidate.7"
    result = tool.draft(args)
    assert result["build"]["channel"] == "preview"
    assert result["build"]["identity"]["sdk_version"] == "0.99.5rc1+candidate.7"
    assert result["build"]["identity"]["core_version"] == "native-0.99.3-rc.2+arm64.9"
    assert result["build"]["platforms"][0]["wheel"]["source"]["tag"] == args.release_tag
    assert not result["guard_qualified"]


@pytest.mark.parametrize("label", ["../core", "v0.15/other", "v0.15?token=x", "v0.15#x", "v0.15%2fother", "a" * 129])
def test_draft_rejects_unsafe_core_labels_and_release_tags(tmp_path, label):
    args = fixture(tmp_path, core_version=label)
    with pytest.raises(ValueError, match="SDK/worker identity mismatch"):
        tool.draft(args)
    args = fixture(tmp_path)
    args.release_tag = label
    with pytest.raises(ValueError, match="invalid exact release tag"):
        tool.draft(args)


def test_draft_preserves_independent_versions_and_never_qualifies(tmp_path):
    result = tool.draft(fixture(tmp_path))
    build = result["build"]
    assert build["identity"]["sdk_version"] == "0.99.5"
    assert build["identity"]["core_version"] == "0.99.3"
    assert result["dependency_closure_checked"] is True
    assert result["guard_qualified"] is False
    assert build["platforms"][0]["qualification"] == "upstream_only"
    assert build["platforms"][0]["features"] == ["graph", "sharing", "persistence", "execution_context"]
    assert len(build["platforms"][0]["package_tree_sha256"]) == 64
    assert build["platforms"][0]["wheel"]["requires_python"] == ">=3.14,<3.15"
    assert build["platforms"][0]["dependencies"][0]["requires_python"] == ">=3.14,<3.15"


@pytest.mark.parametrize(
    "requires",
    ["missing-package>=1", "protobuf>=8", "protobuf @ https://example.invalid/package.whl", "protobuf[extra]>=7"],
)
def test_dependency_closure_refuses_missing_incompatible_urls_and_extras(tmp_path, requires):
    with pytest.raises(ValueError):
        tool.draft(fixture(tmp_path, requires))


def test_dependency_markers_use_target_python_not_maintainer_python(tmp_path):
    args = fixture(tmp_path, "missing-package>=1; python_version < '3.14'")
    assert tool.draft(args)["dependency_closure_checked"] is True


def test_changed_sdk_bytes_are_not_accepted_by_the_upstream_manifest(tmp_path):
    args = fixture(tmp_path)
    with ZipFile(args.sdk_wheel, "a") as archive:
        archive.writestr("cigar_sdk/changed.py", b"changed SDK")
    with pytest.raises(ValueError, match="differs from upstream manifest"):
        tool.draft(args)


def test_a_later_python_patch_is_data_and_implementation_markers_use_it(tmp_path):
    args = fixture(tmp_path, "missing-package>=1; implementation_version < '3.14'")
    args.python_version = "3.14.8"
    result = tool.draft(args)
    assert result["target_python"]["version"] == "3.14.8"
    assert result["guard_qualified"] is False


@pytest.mark.parametrize("version", ["3.15.0", "3.14.8rc1", "3.14.8+custom", "1!3.14.8", "3.14"])
def test_draft_refuses_unsupported_python_or_unqualified_builds(tmp_path, version):
    args = fixture(tmp_path)
    args.python_version = version
    with pytest.raises(ValueError, match=r"final CPython 3\.14 patch"):
        tool.draft(args)


def dependency_url(args):
    name = args.dependency_wheel[0].name
    return f"{name}=https://files.pythonhosted.org/packages/ab/cd/{'e' * 60}/{name}"


def test_explicit_dependency_origin_changes_no_artifact_or_qualification_identity(tmp_path):
    args = fixture(tmp_path)
    original = tool.draft(args)
    args.dependency_url = [dependency_url(args)]
    result = tool.draft(args)
    assert result["build"]["identity"] == original["build"]["identity"]
    original_platform = original["build"]["platforms"][0]
    platform = result["build"]["platforms"][0]
    assert platform["package_tree_sha256"] == original_platform["package_tree_sha256"]
    dependency = platform["dependencies"][0]
    assert dependency["sha256"] == original_platform["dependencies"][0]["sha256"]
    assert dependency["source"]["kind"] == "pypi_file"
    assert platform["qualification"] == "upstream_only"
    assert platform["features"] == ["graph", "sharing", "persistence", "execution_context"]


@pytest.mark.parametrize("change", ["host", "query", "unknown", "sdk", "duplicate", "traversal"])
def test_dependency_origins_cannot_widen_hosts_or_rebind_locked_files(tmp_path, change):
    args = fixture(tmp_path)
    value = dependency_url(args)
    if change == "host":
        value = value.replace("files.pythonhosted.org", "untrusted.example")
    elif change == "query":
        value += "?token=secret"
    elif change == "unknown":
        value = "unknown.whl=" + value.split("=", 1)[1]
    elif change == "sdk":
        value = value.replace(args.dependency_wheel[0].name, args.sdk_wheel.name)
    elif change == "traversal":
        value = value.replace("/ab/", "/../")
    args.dependency_url = [value, value] if change == "duplicate" else [value]
    with pytest.raises(ValueError, match="dependency origin"):
        tool.draft(args)


def test_three_synthetic_builds_use_the_same_generator_and_profile_without_qualification(tmp_path):
    """Drafting a candidate, final rebuild and next release changes data only."""
    drafts = []
    for index, version in enumerate(["0.99.5", "0.99.5", "0.99.6"]):
        directory = tmp_path / f"build-{index}"
        directory.mkdir()
        args = fixture(directory, sdk_version=version, core_version="core-build.99")
        args.build_id = f"synthetic-bump-{index}"
        with ZipFile(args.sdk_wheel, "a") as archive:
            archive.writestr("cigar_sdk/_synthetic_build.py", f"# Never executed; synthetic build {index}\n")
        manifest = json.loads(args.release_manifest.read_text())
        manifest["source_commit"] = "abc"[index] * 40
        manifest["payloads"][0].update(
            bytes=args.sdk_wheel.stat().st_size,
            sha256=hashlib.sha256(args.sdk_wheel.read_bytes()).hexdigest(),
        )
        args.release_manifest.write_text(json.dumps(manifest))
        draft = tool.draft(args)
        assert tool.draft(args) == draft, "same approved input bytes yield the same draft"
        assert draft["guard_qualified"] is False
        assert draft["build"]["platforms"][0]["qualification"] == "upstream_only"
        assert draft["build"]["platforms"][0]["features"] == ["graph", "sharing", "persistence", "execution_context"]
        drafts.append(draft["build"])
    assert {draft["profile_id"] for draft in drafts} == {"cigar-sdk-v1"}
    assert [draft["identity"]["sdk_version"] for draft in drafts] == ["0.99.5", "0.99.5", "0.99.6"]
    assert {draft["identity"]["core_version"] for draft in drafts} == {"core-build.99"}
    for identify in [
        lambda draft: draft["identity"]["build_id"],
        lambda draft: draft["identity"]["source_revision"],
        lambda draft: draft["identity"]["manifest_sha256"],
        lambda draft: draft["platforms"][0]["wheel"]["sha256"],
        lambda draft: draft["platforms"][0]["package_tree_sha256"],
    ]:
        assert len({identify(draft) for draft in drafts}) == 3
