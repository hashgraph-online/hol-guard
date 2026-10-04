"""Native release archives preserve payloads while using maximum DEFLATE."""

from __future__ import annotations

import stat
import zipfile
import zlib
from pathlib import Path

import scripts.build_native_hol_guard_wheel as wheel_builder


def test_native_wheel_uses_maximum_deflate_without_changing_payload_or_mode(tmp_path: Path) -> None:
    """ZipInfo entries must not silently fall back to the default compression level."""
    content = b"".join(bytes((index % 251,)) * (index % 73 + 1) for index in range(10000))
    compressor = zlib.compressobj(level=9, wbits=-15)
    expected = compressor.compress(content) + compressor.flush()
    default = zlib.compressobj(level=6, wbits=-15)
    assert len(expected) < len(default.compress(content) + default.flush())
    path = tmp_path / "compressed.whl"
    name = "codex_plugin_scanner/_native/hol-guard-runtime"
    wheel_builder._write_output_wheel_exclusive(path, {name: content}, {name: 0o755})
    with zipfile.ZipFile(path) as archive:
        info = archive.getinfo(name)
        assert archive.read(name) == content
        assert info.compress_type == zipfile.ZIP_DEFLATED
        assert info.compress_size == len(expected)
        assert stat.S_IMODE(info.external_attr >> 16) == 0o755
