"""``hol-guard plugin verify``: the installed Claude Code commit against HOL's integrity record. Warns only."""

from __future__ import annotations

import contextlib
import io
import json
import urllib.error
from email.message import Message
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner import cli as guard_cli
from codex_plugin_scanner.guard.plugin_kit import install, verify

SCANNED = "0123456789abcdef0123456789abcdef01234567"
OTHER = "fedcba9876543210fedcba9876543210fedcba98"

SPEC: dict[str, Any] = {
    "schema": "hol.plugin-install-spec.v2",
    "slug": "acme/toolgate",
    "version": "1.2.0",
    "listingUrl": "https://hol.org/registry/plugins/acme%2Ftoolgate",
    "targets": [
        {
            "runtime": "claude-code",
            "marketplace": {"repository": "acme/toolgate", "name": "acme", "ref": SCANNED},
            "plugin": "toolgate",
        },
        {"runtime": "agent-skills", "repository": "acme/toolgate"},
    ],
}


def _ledger(*records: dict[str, Any], events: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {"schema": verify.LEDGER_SCHEMA, "slug": "acme/toolgate", "records": list(records), "events": events or []}


def _record(commit: str, version: str = "1.2.0", channel: str = "hol_catalog") -> dict[str, Any]:
    return {
        "channel": channel,
        "kind": "git_commit",
        "version": version,
        "platform": None,
        "commitSha": commit,
        "treeSha": None,
        "sha256": None,
        "observedAt": "2026-10-30T00:00:00.000Z",
    }


class Reply:
    def __init__(self, body: bytes) -> None:
        self.body = body

    def __enter__(self) -> Reply:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self, limit: int) -> bytes:
        return self.body[:limit]


@pytest.fixture
def claude_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "claude-home"
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(home))
    monkeypatch.delenv(install.SPEC_URL_ENV, raising=False)
    return home


def _installed(home: Path, entry: dict[str, Any] | None) -> None:
    path = home / "plugins" / "installed_plugins.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    plugins = {"toolgate@acme": [{"scope": "user", **entry}]} if entry is not None else {}
    path.write_text(json.dumps({"version": 2, "plugins": plugins}), encoding="utf-8")


def _serve(monkeypatch: pytest.MonkeyPatch, ledger: dict[str, Any] | BaseException) -> list[str]:
    asked: list[str] = []
    monkeypatch.setattr(install, "fetch_spec", lambda slug, endpoint, **_kwargs: SPEC)

    def urlopen(request: Any, **_kwargs: Any) -> Reply:
        asked.append(request.full_url)
        if isinstance(ledger, BaseException):
            raise ledger
        return Reply(json.dumps(ledger).encode())

    monkeypatch.setattr(verify, "managed_urlopen", urlopen)
    return asked


def run(argv: list[str], monkeypatch: pytest.MonkeyPatch) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    monkeypatch.setattr(guard_cli.sys, "argv", ["hol-guard"])
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = guard_cli.main(argv)
    return code, out.getvalue(), err.getvalue()


def test_matching_commit_reports_a_match(claude_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _installed(claude_home, {"version": "1.2.0", "gitCommitSha": SCANNED})
    asked = _serve(monkeypatch, _ledger(_record(SCANNED), _record(SCANNED, channel="claude_official")))

    code, out, err = run(["plugin", "verify", "acme/toolgate"], monkeypatch)

    assert code == 0
    assert "acme/toolgate in Claude Code: 1.2.0 at commit 0123456" in out
    assert "Matches what HOL recorded for 1.2.0." in out
    assert "Warning" not in err
    assert asked == ["https://hol.org/api/guard/plugins/integrity-ledger?slug=acme%2Ftoolgate"]


def test_different_commit_warns_and_still_exits_zero(claude_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _installed(claude_home, {"version": "1.2.0", "gitCommitSha": OTHER})
    before = (claude_home / "plugins" / "installed_plugins.json").read_bytes()
    event = {"kind": "republished", "version": "1.2.0", "channels": ["hol_catalog"], "sentence": "1.2.0 was re-tagged."}
    _serve(monkeypatch, _ledger(_record(SCANNED), _record(OTHER, version="1.1.0"), events=[event]))

    code, out, err = run(["plugin", "verify", "acme/toolgate"], monkeypatch)

    assert code == 0
    # The whole differing result goes to stderr, so piping stdout away keeps the notes with the warning.
    assert out == ""
    assert "Warning: HOL recorded 0123456 (hol_catalog) for 1.2.0, not the commit Claude Code installed." in err
    assert "HOL noted: 1.2.0 was re-tagged." in err
    assert "Releases: https://hol.org/registry/plugins/acme%2Ftoolgate/releases" in err
    # Warn only: Guard leaves Claude Code's record exactly as it was.
    assert (claude_home / "plugins" / "installed_plugins.json").read_bytes() == before


def test_json_document_names_status_and_recorded_commits(claude_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _installed(claude_home, {"version": "1.2.0", "gitCommitSha": OTHER})
    _serve(monkeypatch, _ledger(_record(SCANNED), _record(SCANNED, channel="claude_official")))

    code, out, _err = run(["plugin", "verify", "acme/toolgate", "--json"], monkeypatch)

    document = json.loads(out)
    assert code == 0
    assert document["schema"] == "hol-guard.plugin-verify/1"
    assert document["status"] == "differs"
    assert document["installed"] == {"version": "1.2.0", "commit": OTHER}
    assert document["recorded"] == [{"commit": SCANNED, "channels": ["hol_catalog", "claude_official"]}]
    assert document["error"] is None


@pytest.mark.parametrize(
    ("entry", "records", "status", "line"),
    [
        (
            {"version": "1.3.0", "gitCommitSha": OTHER},
            [_record(SCANNED)],
            "not_recorded",
            "no commit recorded for 1.3.0",
        ),
        ({"sourceCommand": "node setup.js"}, [_record(SCANNED)], "no_commit", "kept no commit for this install"),
        # Without a version no recorded commit can be tied to the install, even one HOL saw for another version.
        ({"gitCommitSha": OTHER}, [_record(OTHER, version="1.1.0")], "no_version", "kept no version for this install"),
    ],
)
def test_nothing_to_compare_is_said_plainly(
    claude_home: Path,
    monkeypatch: pytest.MonkeyPatch,
    entry: dict[str, Any],
    records: list[dict[str, Any]],
    status: str,
    line: str,
) -> None:
    _installed(claude_home, entry)
    _serve(monkeypatch, _ledger(*records))

    code, out, err = run(["plugin", "verify", "acme/toolgate"], monkeypatch)
    assert code == 0
    assert line in out
    assert "Warning" not in err

    code, out, _err = run(["plugin", "verify", "acme/toolgate", "--json"], monkeypatch)
    assert (code, json.loads(out)["status"]) == (0, status)


def test_not_installed_exits_three_without_asking_the_ledger(
    claude_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _installed(claude_home, None)
    asked = _serve(monkeypatch, _ledger(_record(SCANNED)))

    code, _out, err = run(["plugin", "verify", "acme/toolgate"], monkeypatch)

    assert code == 3
    assert "Claude Code has no install of acme/toolgate" in err
    assert asked == []


def test_unreachable_ledger_exits_six(claude_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _installed(claude_home, {"version": "1.2.0", "gitCommitSha": SCANNED})
    _serve(monkeypatch, urllib.error.URLError("offline"))

    code, out, err = run(["plugin", "verify", "acme/toolgate", "--json"], monkeypatch)

    assert code == 6
    assert json.loads(out)["error"]["code"] == "unreachable"
    assert "could not be downloaded from HOL" in err


def test_unknown_listing_in_the_ledger_exits_three(claude_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _installed(claude_home, {"version": "1.2.0", "gitCommitSha": SCANNED})
    _serve(monkeypatch, urllib.error.HTTPError("u", 404, "Not Found", Message(), None))

    code, _out, err = run(["plugin", "verify", "acme/toolgate"], monkeypatch)

    assert code == 3
    assert "HOL has no integrity record for acme/toolgate." in err


@pytest.mark.parametrize(
    "override",
    [
        "http://localhost:3017/api/guard/plugins/install-spec",
        "http://localhost:3017/api/guard/plugins/install-spec/",
        "http://localhost:3017",
        "http://localhost:3017/",
    ],
)
def test_ledger_url_follows_a_local_spec_override(override: str) -> None:
    assert verify.ledger_endpoint(override) == "http://localhost:3017/api/guard/plugins/integrity-ledger"


def _spec_answer(monkeypatch: pytest.MonkeyPatch, error: BaseException) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    def urlopen(_request: Any, **kwargs: Any) -> Reply:
        calls.append(kwargs)
        raise error

    monkeypatch.setattr(install, "managed_urlopen", urlopen)
    return calls


def test_unknown_listing_in_the_spec_lookup_exits_three(claude_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _spec_answer(monkeypatch, urllib.error.HTTPError("u", 404, "Not Found", Message(), None))

    code, out, err = run(["plugin", "verify", "acme/toolgate", "--json"], monkeypatch)

    assert code == 3
    assert json.loads(out)["error"]["code"] == "not_found"
    assert "No plugin acme/toolgate is listed on HOL." in err


def test_spec_lookup_does_not_follow_redirects(claude_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _spec_answer(monkeypatch, urllib.error.HTTPError("u", 302, "Found", Message(), None))

    code, _out, err = run(["plugin", "verify", "acme/toolgate"], monkeypatch)

    assert code == 6
    assert [call.get("allow_redirects") for call in calls] == [False]
    assert "redirect, which verify does not follow" in err


def test_ledger_for_another_listing_is_refused(claude_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _installed(claude_home, {"version": "1.2.0", "gitCommitSha": SCANNED})
    _serve(monkeypatch, {**_ledger(_record(SCANNED)), "slug": "acme/other"})

    code, out, err = run(["plugin", "verify", "acme/toolgate"], monkeypatch)

    assert code == 2
    assert out == ""
    assert "another listing's record" in err


def test_canonical_slug_from_the_spec_is_accepted(claude_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _installed(claude_home, {"version": "1.2.0", "gitCommitSha": SCANNED})
    _serve(monkeypatch, {**_ledger(_record(SCANNED)), "slug": "Acme/ToolGate"})

    code, out, _err = run(["plugin", "verify", "ACME/toolgate"], monkeypatch)

    assert code == 0
    assert "Matches what HOL recorded for 1.2.0." in out


@pytest.mark.parametrize(
    "ledger",
    [
        _ledger({**_record(SCANNED), "kind": 5}),
        _ledger({**_record(SCANNED), "commitSha": ["x"]}),
        _ledger(events=[{"kind": "republished", "version": "1.2.0", "sentence": {"text": "x"}}]),
        _ledger(events=[{"kind": "republished", "version": 1, "sentence": "x"}]),
        {**_ledger(), "records": {}},
    ],
)
def test_malformed_ledger_entries_are_refused(
    claude_home: Path, monkeypatch: pytest.MonkeyPatch, ledger: dict[str, Any]
) -> None:
    _installed(claude_home, {"version": "1.2.0", "gitCommitSha": SCANNED})
    _serve(monkeypatch, ledger)

    code, _out, err = run(["plugin", "verify", "acme/toolgate"], monkeypatch)

    assert code == 2
    assert "not in the expected shape" in err


def test_ledger_text_cannot_drive_the_terminal(claude_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _installed(claude_home, {"version": "1.2.0", "gitCommitSha": OTHER})
    event = {"kind": "republished", "version": "1.2.0", "sentence": "\x1b]0;owned\x07 re-tagged"}
    _serve(monkeypatch, _ledger(_record(SCANNED, channel="hol\x1b[2Jcatalog"), events=[event]))

    code, out, err = run(["plugin", "verify", "acme/toolgate"], monkeypatch)

    assert code == 0
    assert "\x1b" not in out + err and "\x07" not in out + err
    assert "HOL noted: \\u001b]0;owned\\u0007 re-tagged" in err
    assert "(hol\\u001b[2Jcatalog)" in err


def test_unexpected_ledger_shape_is_refused(claude_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _installed(claude_home, {"version": "1.2.0", "gitCommitSha": SCANNED})
    _serve(monkeypatch, {"schema": "something-else"})

    code, _out, err = run(["plugin", "verify", "acme/toolgate"], monkeypatch)

    assert code == 2
    assert "not in the expected shape" in err
