"""Native archive admission must not hand a replaced path to a decompressor."""

from __future__ import annotations

import hashlib
import io
import json
import stat
import subprocess
import zipfile

from codex_plugin_scanner.guard.catalog_delivery import cache_io


def archive_bytes(identity, data, compression):
    output = io.BytesIO()
    member = zipfile.ZipInfo(identity + ".json")
    member.create_system = 3
    member.external_attr = (stat.S_IFREG | 0o400) << 16
    member.compress_type = compression
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr(member, data)
    return output.getvalue()


def test_replaced_archive_cannot_start_python_decompression(tmp_path, monkeypatch, native_hook_force):
    identity = hashlib.sha256(b"{}").hexdigest()
    original = archive_bytes(identity, b"{}", zipfile.ZIP_STORED)
    replacement = archive_bytes(identity, b"A" * (4 * 1024 * 1024), zipfile.ZIP_DEFLATED)
    reference = {
        "sha256": hashlib.sha256(original).hexdigest(),
        "length": len(original),
        "location": "synthetic-archive",
    }
    directory = tmp_path / "cache"
    directory.mkdir(mode=0o700)
    calls = []

    def admitted_then_replaced(kind, **fields):
        response = subprocess.run(
            [str(native_hook_force), "pack-lifecycle", "--stdin"],
            input=json.dumps({"kind": kind, **fields}).encode(),
            capture_output=True,
            timeout=30,
        )
        assert response.returncode == 0, response.stderr.decode()
        admitted = json.loads(response.stdout)
        assert admitted["members"][0][0] == identity
        from pathlib import Path

        Path(fields["path"]).write_bytes(replacement)
        return admitted

    def forbidden_decompression(*args, **kwargs):
        calls.append(True)
        raise AssertionError("Python decompression followed native archive admission")

    monkeypatch.setattr(zipfile.ZipFile, "read", forbidden_decompression)
    cache_io.stage_archive(directory, reference, lambda *_: original, invoke=admitted_then_replaced)
    assert not calls
    assert (directory / "objects" / (identity + ".json")).read_bytes() == b"{}"
