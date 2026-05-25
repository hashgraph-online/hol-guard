"""Tests for package/CLI version consistency."""

from pathlib import Path

import pytest

from codex_plugin_scanner import __version__ as package_version
from codex_plugin_scanner.cli import main

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 fallback
    import tomli as tomllib


def test_pyproject_version_matches_package_version():
    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    assert pyproject["project"]["version"] == package_version


def test_cli_version_matches_package_version(capsys: pytest.CaptureFixture[str]):
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])
    assert exc_info.value.code == 0
    output = capsys.readouterr().out.strip()
    assert output.endswith(package_version)
