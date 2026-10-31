"""Private interpreter drafts are data, not setup/qualification authority."""

import argparse
import hashlib
import importlib.util
import io
import json
import tarfile
from pathlib import Path

import pytest

PATH = Path(__file__).resolve().parents[1] / "scripts/cigar_interpreter_entry.py"
SPEC = importlib.util.spec_from_file_location("cigar_interpreter_entry", PATH)
assert SPEC and SPEC.loader
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)


def fixture(tmp_path, extra=None):
    path = tmp_path / "cpython-3.14.11+20261027-aarch64-apple-darwin-install_only_stripped.tar.gz"
    with tarfile.open(path, "w:gz", format=tarfile.GNU_FORMAT) as archive:
        for name, data in [
            ("python/bin/python3.14", b"synthetic interpreter, never executed"),
            ("python/lib/python3.14/os.py", b"# synthetic stdlib"),
        ]:
            member = tarfile.TarInfo(name)
            member.size = len(data)
            member.mode = 0o755 if "/bin/" in name else 0o644
            archive.addfile(member, io.BytesIO(data))
        link = tarfile.TarInfo("python/bin/python3")
        link.type = tarfile.SYMTYPE
        link.linkname = "python3.14"
        archive.addfile(link)
        if extra:
            name, target = extra
            link = tarfile.TarInfo(name)
            link.type = tarfile.SYMTYPE
            link.linkname = target
            archive.addfile(link)
    metadata = tmp_path / "release.json"
    metadata.write_text(
        json.dumps(
            {
                "tag_name": "20261027",
                "target_commitish": "a" * 40,
                "draft": False,
                "prerelease": False,
                "assets": [
                    {
                        "name": path.name,
                        "size": path.stat().st_size,
                        "digest": "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest(),
                        "browser_download_url": "https://github.com/astral-sh/python-build-standalone/releases/download/20261027/"
                        + path.name.replace("+", "%2B"),
                    }
                ],
            }
        )
    )
    return argparse.Namespace(
        archive=path, release_metadata=metadata, platform="darwin-arm64", source_revision=None, build_id=None
    )


def test_later_patch_draft_is_data_and_never_qualifies(tmp_path):
    result = tool.draft(fixture(tmp_path))
    build = result["interpreter_build"]
    assert build["python_version"] == [3, 14, 11]
    assert build["files"] == 3 and len(build["tree_sha256"]) == 64
    assert build["build_id"] == "cpython-3_14_11-20261027-darwin-arm64"
    assert build["qualification"] == "upstream_only" and build["qualification_receipt_sha256"] is None
    assert result["guard_qualified"] is False


@pytest.mark.parametrize(
    "name,target",
    [
        ("python/bin/escape", "../../outside"),
        ("python/bin/escape", "/outside"),
        ("python/bin/cycle", "cycle"),
        ("python/bin/missing", "missing"),
        ("python/hooks.pth", "bin/python3.14"),
        ("python/BIN/alias", "../bin/python3.14"),
    ],
)
def test_alias_escapes_cycles_missing_targets_hooks_and_case_aliases_refuse(tmp_path, name, target):
    with pytest.raises(ValueError):
        tool.draft(fixture(tmp_path, (name, target)))


def test_changed_bytes_and_wrong_origin_do_not_make_a_valid_draft(tmp_path):
    args = fixture(tmp_path)
    metadata = json.loads(args.release_metadata.read_text())
    metadata["assets"][0]["browser_download_url"] = "https://untrusted.example/archive.tar.gz"
    args.release_metadata.write_text(json.dumps(metadata))
    with pytest.raises(ValueError, match="differs"):
        tool.draft(args)
    metadata["assets"][0]["browser_download_url"] = (
        "https://github.com/astral-sh/python-build-standalone/releases/download/20261027/"
        + args.archive.name.replace("+", "%2B")
    )
    args.release_metadata.write_text(json.dumps(metadata))
    args.archive.write_bytes(b"changed")
    with pytest.raises(ValueError, match="differs"):
        tool.draft(args)


@pytest.mark.parametrize(
    "field,value", [("draft", True), ("prerelease", True), ("tag_name", "../escape"), ("target_commitish", "main")]
)
def test_metadata_does_not_establish_missing_source_identity(tmp_path, field, value):
    args = fixture(tmp_path)
    metadata = json.loads(args.release_metadata.read_text())
    metadata[field] = value
    args.release_metadata.write_text(json.dumps(metadata))
    with pytest.raises(ValueError, match="source identity"):
        tool.draft(args)


def test_concatenated_gzip_and_trailing_tar_are_not_the_shipped_layout(tmp_path):
    args = fixture(tmp_path)
    data = args.archive.read_bytes()
    with pytest.raises(ValueError, match="gzip framing"):
        tool.inspect_archive(data + data)
