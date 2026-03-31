"""Tests for package/CLI version consistency."""

import pytest

from codex_plugin_scanner import __version__ as package_version
from codex_plugin_scanner.cli import main


def test_cli_version_matches_package_version(capsys: pytest.CaptureFixture[str]):
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])
    assert exc_info.value.code == 0
    output = capsys.readouterr().out.strip()
    assert output.endswith(package_version)
