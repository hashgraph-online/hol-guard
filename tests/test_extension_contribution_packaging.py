"""Packaging coverage for Guard extension contribution metadata."""

from __future__ import annotations

import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - Python 3.10 compatibility
    import tomli as tomllib


def test_wheel_force_includes_every_extension_contribution() -> None:
    root = Path(__file__).resolve().parents[1]
    config = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    force_include = config["tool"]["hatch"]["build"]["targets"]["wheel"]["force-include"]
    source_contributions = {
        path.relative_to(root).as_posix()
        for path in (root / "contributions" / "extensions").glob("*.json")
    }

    assert source_contributions
    assert source_contributions <= set(force_include)
