"""``hol-guard telemetry plugins``: consent, the device key and the weekly report.

Counts are opt-in, so the regression cases here pin that nothing is fetched
or sent before ``on``, that a report names only public HOL listings, and that
it carries nothing that identifies the machine.
"""

from __future__ import annotations

import contextlib
import io
import json
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner import cli as guard_cli
from codex_plugin_scanner.guard import config as guard_config
from codex_plugin_scanner.guard.plugin_telemetry import cli as telemetry_cli
from codex_plugin_scanner.guard.plugin_telemetry import report as telemetry_report
from codex_plugin_scanner.guard.plugin_telemetry.state import SECRET_FILE, TelemetryState, read_state

INDEX = [
    {"slug": "acme/notes-kit", "repository": "https://github.com/acme/notes-kit"},
    {"slug": "acme/other", "repository": "https://github.com/acme/other"},
]


@pytest.fixture
def guard_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "guard-home"
    monkeypatch.setattr(guard_config, "resolve_guard_home", lambda override=None: home)
    monkeypatch.setattr(telemetry_cli, "resolve_guard_home", lambda override=None: home)
    return home


@pytest.fixture
def user_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "user"
    listed = home / ".claude" / "plugins" / "cache" / "acme" / "notes-kit" / "1.2.0" / ".claude-plugin"
    listed.mkdir(parents=True)
    (listed / "plugin.json").write_text(
        json.dumps({"name": "notes-kit", "version": "1.2.0", "repository": "https://github.com/acme/notes-kit.git"}),
        encoding="utf-8",
    )
    private = home / ".claude" / "plugins" / "cache" / "corp" / "internal-tool" / "0.1.0" / ".claude-plugin"
    private.mkdir(parents=True)
    (private / "plugin.json").write_text(
        json.dumps(
            {"name": "internal-tool", "version": "0.1.0", "repository": "https://github.com/corp/internal-tool"}
        ),
        encoding="utf-8",
    )
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    monkeypatch.delenv("CODEX_HOME", raising=False)
    monkeypatch.setattr(telemetry_report.Path, "home", staticmethod(lambda: home))
    return home


def _run(argv: list[str]) -> tuple[int, str, str]:
    output = io.StringIO()
    error = io.StringIO()
    original_argv = guard_cli.sys.argv
    try:
        guard_cli.sys.argv = ["hol-guard"]
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            exit_code = guard_cli.main(argv)
    finally:
        guard_cli.sys.argv = original_argv
    return exit_code, output.getvalue(), error.getvalue()


def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("telemetry reached the network")

    monkeypatch.setattr(telemetry_report, "fetch_index", refuse)
    monkeypatch.setattr(telemetry_report, "post_report", refuse)


def test_counts_are_off_until_turned_on_and_nothing_is_sent(guard_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _no_network(monkeypatch)
    exit_code, output, _error = _run(["telemetry", "plugins", "status"])
    assert exit_code == 0
    assert "off" in output
    assert telemetry_report.send_if_due(guard_home) is None
    exit_code, _output, error = _run(["telemetry", "plugins", "send"])
    assert exit_code == 2
    assert "telemetry plugins on" in error
    assert not (guard_home / SECRET_FILE).exists()


def test_on_creates_an_owner_only_key_and_off_deletes_it(guard_home: Path) -> None:
    exit_code, output, _error = _run(["telemetry", "plugins", "on"])
    assert exit_code == 0
    assert "never leave the machine" in output
    secret = guard_home / SECRET_FILE
    assert secret.is_file()
    if sys.platform != "win32":
        assert stat.S_IMODE(secret.stat().st_mode) == 0o600
    assert read_state(guard_home).enabled
    exit_code, _output, _error = _run(["telemetry", "plugins", "off"])
    assert exit_code == 0
    assert not secret.exists()
    assert not read_state(guard_home).enabled


def test_report_names_only_listed_plugins_and_nothing_about_the_machine(
    guard_home: Path, user_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(telemetry_report, "fetch_index", lambda: INDEX)
    sent: list[dict[str, object]] = []
    monkeypatch.setattr(telemetry_report, "post_report", lambda report: sent.append(dict(report)) or 1)
    assert _run(["telemetry", "plugins", "on"])[0] == 0

    now = datetime(2026, 10, 21, tzinfo=timezone.utc)
    result = telemetry_report.send_if_due(guard_home, now=now)
    assert result is not None
    assert (result["week"], result["installed"], result["listed"]) == ("2026-W43", 2, 1)
    assert telemetry_report.send_if_due(guard_home, now=now) is None, "one report per week"

    (report,) = sent
    assert set(report) == {"schema", "week", "guardVersion", "entries"}
    (entry,) = report["entries"]
    assert set(entry) == {"slug", "runtime", "version", "key"}
    assert (entry["slug"], entry["runtime"], entry["version"]) == ("acme/notes-kit", "claude-code", "1.2.0")
    assert len(entry["key"]) == 64
    text = json.dumps(report)
    for private in ("internal-tool", "corp", str(user_home), str(guard_home)):
        assert private not in text


def test_dry_run_prints_the_report_without_opt_in_or_sending(
    guard_home: Path, user_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(telemetry_report, "fetch_index", lambda: INDEX)
    monkeypatch.setattr(telemetry_report, "post_report", lambda _report: pytest.fail("dry run sent a report"))
    exit_code, output, error = _run(["telemetry", "plugins", "send", "--dry-run", "--json"])
    assert (exit_code, error) == (0, "")
    report = json.loads(output)
    assert [entry["slug"] for entry in report["entries"]] == ["acme/notes-kit"]
    assert not (guard_home / SECRET_FILE).exists()
    assert not read_state(guard_home).enabled


def test_turning_counts_off_during_a_send_stops_it_and_stays_off(
    guard_home: Path, user_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def index_then_opt_out() -> list[dict[str, str]]:
        assert _run(["telemetry", "plugins", "off"])[0] == 0
        return INDEX

    monkeypatch.setattr(telemetry_report, "fetch_index", index_then_opt_out)
    monkeypatch.setattr(telemetry_report, "post_report", lambda _report: pytest.fail("sent after opt-out"))
    assert _run(["telemetry", "plugins", "on"])[0] == 0

    with pytest.raises(telemetry_report.PluginTelemetryError):
        telemetry_report.send_if_due(guard_home, now=datetime(2026, 10, 21, tzinfo=timezone.utc))
    assert read_state(guard_home) == TelemetryState(enabled=False, last_week=None)
    assert not (guard_home / SECRET_FILE).exists()


def test_a_failed_send_leaves_the_week_due(guard_home: Path, user_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(telemetry_report, "fetch_index", lambda: INDEX)

    def refuse(_report: object) -> int:
        raise telemetry_report.PluginTelemetryError("HOL did not accept the report (HTTP 503).")

    monkeypatch.setattr(telemetry_report, "post_report", refuse)
    assert _run(["telemetry", "plugins", "on"])[0] == 0
    now = datetime(2026, 10, 21, tzinfo=timezone.utc)
    with pytest.raises(telemetry_report.PluginTelemetryError):
        telemetry_report.send_if_due(guard_home, now=now)
    assert read_state(guard_home).last_week is None

    sent: list[object] = []
    monkeypatch.setattr(telemetry_report, "post_report", lambda report: sent.append(report) or 1)
    assert telemetry_report.send_if_due(guard_home, now=now) is not None
    assert len(sent) == 1
    assert read_state(guard_home).last_week == "2026-W43"


def test_report_builds_when_the_full_index_is_larger_than_one_native_request(
    guard_home: Path, user_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    padding = [
        {
            "slug": f"bulk/plugin-{number}",
            "repository": f"https://github.com/bulk/plugin-{number}",
            "manifestName": "x" * 60,
        }
        for number in range(70_000)
    ]
    assert len(json.dumps(padding)) > 6 * 1024 * 1024
    monkeypatch.setattr(telemetry_report, "fetch_index", lambda: [*padding, *INDEX])
    sent: list[dict[str, object]] = []
    monkeypatch.setattr(telemetry_report, "post_report", lambda report: sent.append(dict(report)) or 1)
    assert _run(["telemetry", "plugins", "on"])[0] == 0

    result = telemetry_report.send_if_due(guard_home, now=datetime(2026, 10, 21, tzinfo=timezone.utc))
    assert result is not None
    assert result["listed"] == 1
    (report,) = sent
    entries = report["entries"]
    assert isinstance(entries, list)
    assert [entry["slug"] for entry in entries] == ["acme/notes-kit"]


def test_index_urls_that_are_not_normalized_still_match(
    guard_home: Path, user_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    index: list[dict[str, object]] = [
        {"slug": "acme/notes-kit", "repository": "git+https://www.GitHub.com/Acme/Notes-Kit.git/"}
    ]
    monkeypatch.setattr(telemetry_report, "fetch_index", lambda: index)
    assert telemetry_report.installed_index(index) == index
    result = telemetry_report.build_report("ab" * 32, week="2026-W43", index=index)
    entries = result["report"]["entries"]
    assert [entry["slug"] for entry in entries] == ["acme/notes-kit"]


def test_index_downloads_wait_for_a_server_that_is_still_building_the_index(monkeypatch: pytest.MonkeyPatch) -> None:
    # HOL builds the listing index from the whole catalog, about 30 seconds on a
    # cold server; a 20 second limit made every first request to it fail.
    from codex_plugin_scanner.guard.plugin_telemetry import updates as telemetry_updates

    timeouts: list[float] = []

    @contextlib.contextmanager
    def record(request: object, *, timeout: float):
        timeouts.append(timeout)
        yield io.BytesIO(json.dumps({"entries": []}).encode())

    monkeypatch.setattr(telemetry_report, "managed_urlopen", record)
    monkeypatch.setattr(telemetry_updates, "managed_urlopen", record)
    telemetry_report.fetch_index()
    telemetry_updates.fetch_release_index()
    assert len(timeouts) == 2
    assert min(timeouts) >= 45
