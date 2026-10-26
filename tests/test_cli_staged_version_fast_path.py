"""Version probes must stay cheap under temporary executable names."""

from __future__ import annotations

import sys

import pytest

from codex_plugin_scanner import cli
from codex_plugin_scanner.version import __version__


@pytest.mark.parametrize(
    ("program_name", "frozen"),
    [
        ("hol-guard-3.8.1-123-456.partial", True),
        ("hol-guard-3.8.1-123-456.partial", False),
        ("hol-guard", False),
        ("plugin-guard", False),
    ],
)
def test_version_probe_avoids_full_command_surface_for_guard_executable_names(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    program_name: str,
    frozen: bool,
) -> None:
    monkeypatch.setattr(sys, "argv", [program_name, "--version"])
    monkeypatch.setattr(sys, "frozen", frozen, raising=False)

    def unexpected_parser(*_args: object, **_kwargs: object) -> None:
        pytest.fail("a version probe must not build the full command surface")

    monkeypatch.setattr(cli, "_build_parser", unexpected_parser)

    assert cli.main() == 0
    assert capsys.readouterr().out.strip() == f"{program_name} {__version__}"


@pytest.mark.parametrize("program_name", ["plugin-scanner", "plugin-scanner-extra"])
@pytest.mark.parametrize("frozen", [False, True])
def test_non_guard_version_keeps_argparse_exit(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    program_name: str,
    frozen: bool,
) -> None:
    monkeypatch.setattr(sys, "argv", [program_name, "--version"])
    monkeypatch.setattr(sys, "frozen", frozen, raising=False)

    with pytest.raises(SystemExit) as exit_info:
        _ = cli.main()

    assert exit_info.value.code == 0
    assert capsys.readouterr().out.strip() == f"{program_name} {__version__}"
