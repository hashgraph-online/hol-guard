from pathlib import Path

import pytest
from packaging.tags import sys_tags

from scripts.select_installed_native_wheel import select_native_wheel


def _native_platform() -> str:
    platform = next(
        (
            tag.platform
            for tag in sys_tags()
            if tag.interpreter == "py3" and tag.abi == "none" and tag.platform != "any"
        ),
        None,
    )
    assert platform is not None, "current Python has no supported native wheel platform tag"
    return platform


def test_selects_only_the_compatible_native_wheel(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "hol_guard-3.4.5-py3-none-any.whl").write_bytes(b"pure")
    native = dist / f"hol_guard-3.4.5-py3-none-{_native_platform()}.whl"
    native.write_bytes(b"native")

    selected = select_native_wheel(dist, "3.4.5", tmp_path / "selected")

    assert selected.name == native.name
    assert selected.read_bytes() == b"native"


def test_rejects_missing_or_ambiguous_native_wheels(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "hol_guard-3.4.5-py3-none-any.whl").write_bytes(b"pure")
    with pytest.raises(ValueError, match="found 0"):
        select_native_wheel(dist, "3.4.5", tmp_path / "selected")

    platform = _native_platform()
    (dist / f"hol_guard-3.4.5-py3-none-{platform}.whl").write_bytes(b"native-1")
    (dist / f"hol_guard-3.4.5-py2.py3-none-{platform}.whl").write_bytes(b"native-2")
    with pytest.raises(ValueError, match="found 2"):
        select_native_wheel(dist, "3.4.5", tmp_path / "selected")
