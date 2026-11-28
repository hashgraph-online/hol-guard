"""``hol-guard integrations list|status|connect|disconnect|test|settings`` call the daemon's provider routes.

A fake daemon client records every request, so these tests show what the CLI sends: the key only
in the connect body, a proof only after a preview, and nothing at all when the user says no.
"""

from __future__ import annotations

import io
import json

import pytest

from codex_plugin_scanner import cli
from codex_plugin_scanner.guard.cli import integrations_providers_command as providers
from codex_plugin_scanner.guard.native_daemon_client import GuardDaemonRequestError

SHIELD = "provider.exampleshield"
BASE = f"/v1/integrations/providers/{SHIELD}"
KEY = "fixture-cli-" + "k" * 24
SUMMARY = {
    "id": SHIELD,
    "name": "ExampleShield",
    "summary": "Fixture origin reputation",
    "verified": False,
    "state": "connected",
    "capabilities": ["browser.origin-reputation"],
}
DETAIL = {
    "summary": SUMMARY,
    "auth_kind": "api-key",
    "shares": ["target.origin"],
    "enabled_opt_in_facts": [],
    "settings": [
        {
            "capability": "browser.origin-reputation",
            "effect": "tighten",
            "require_fresh_check": False,
            "quieted_reason_codes": [],
        }
    ],
    "last_verified_at_ms": 1000,
    "cache_counts": {},
}


class Terminal(io.StringIO):
    def isatty(self) -> bool:
        return True


class FakeClient:
    def __init__(self, answers: dict[str, object]) -> None:
        self.answers = answers
        self.sent: list[tuple[str, str, dict[str, object] | None]] = []

    def _answer(self, path: str) -> dict[str, object]:
        answer = self.answers[path]
        if isinstance(answer, Exception):
            raise answer
        assert isinstance(answer, dict)
        return answer

    def _get(self, path: str, *, timeout: float) -> dict[str, object]:
        self.sent.append(("GET", path, None))
        return self._answer(path)

    def _post(self, path: str, payload: dict[str, object], *, timeout: float = 5.0) -> dict[str, object]:
        self.sent.append(("POST", path, payload))
        return self._answer(path)


def _install(monkeypatch: pytest.MonkeyPatch, answers: dict[str, object], stdin: io.StringIO) -> FakeClient:
    client = FakeClient(answers)
    monkeypatch.setattr(providers, "_daemon_client", lambda _args: client)
    monkeypatch.setattr("sys.stdin", stdin)
    return client


def _preview(**extra: object) -> dict[str, object]:
    return {"provider_id": SHIELD, "challenge": "fixture-proof", "expires_at_ms": 9, **extra}


def test_list_prints_each_provider(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    client = _install(monkeypatch, {"/v1/integrations/providers": {"providers": [SUMMARY]}}, io.StringIO())
    assert cli.main(["guard", "integrations", "list"]) == 0
    out = capsys.readouterr().out
    assert f"{SHIELD}  connected  unverified  browser.origin-reputation" in out
    assert client.sent == [("GET", "/v1/integrations/providers", None)]


def test_status_json_is_the_daemon_answer(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    _install(monkeypatch, {BASE: DETAIL}, io.StringIO())
    assert cli.main(["guard", "integrations", "status", SHIELD, "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == DETAIL


def test_connect_sends_the_key_only_with_the_proof(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    answers = {
        f"{BASE}/connect/preview": _preview(shares=["target.origin"], opt_in_facts=[], hosts=["api.example"]),
        f"{BASE}/connect": {"provider_id": SHIELD, "state": "connected"},
    }
    client = _install(monkeypatch, answers, Terminal("y\n"))
    monkeypatch.setattr(providers.getpass, "getpass", lambda _prompt, stream=None: KEY)
    assert cli.main(["guard", "integrations", "connect", SHIELD]) == 0
    captured = capsys.readouterr()
    assert "Sent with each lookup: target.origin" in captured.out
    assert "Only these hosts are called: api.example" in captured.out
    assert KEY not in captured.out + captured.err
    assert client.sent == [
        ("POST", f"{BASE}/connect/preview", {}),
        ("POST", f"{BASE}/connect", {"key": KEY, "proof": "fixture-proof", "enabled_opt_in_facts": []}),
    ]


def test_connect_answering_no_sends_no_key(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    answers = {f"{BASE}/connect/preview": _preview(shares=[], opt_in_facts=[], hosts=[])}
    client = _install(monkeypatch, answers, Terminal("n\n"))
    monkeypatch.setattr(providers.getpass, "getpass", lambda _prompt, stream=None: KEY)
    assert cli.main(["guard", "integrations", "connect", SHIELD]) == 2
    assert "cancelled: Nothing was changed." in capsys.readouterr().err
    assert [path for _method, path, _body in client.sent] == [f"{BASE}/connect/preview"]


def test_connect_without_a_terminal_needs_key_stdin(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    client = _install(monkeypatch, {}, io.StringIO(KEY + "\n"))
    assert cli.main(["guard", "integrations", "connect", SHIELD]) == 2
    assert "terminal_required" in capsys.readouterr().err
    assert client.sent == []


def test_key_stdin_needs_yes_and_reads_one_line(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    answers = {
        f"{BASE}/connect/preview": _preview(shares=["target.origin"], opt_in_facts=["page.script_hashes"], hosts=[]),
        f"{BASE}/connect": {"provider_id": SHIELD},
    }
    client = _install(monkeypatch, answers, io.StringIO(KEY + "\n"))
    assert cli.main(["guard", "integrations", "connect", SHIELD, "--key-stdin"]) == 2
    assert "confirmation_required" in capsys.readouterr().err

    client = _install(monkeypatch, answers, io.StringIO(KEY + "\n"))
    argv = ["guard", "integrations", "connect", SHIELD, "--key-stdin", "--yes", "--share", "page.script_hashes"]
    assert cli.main(argv) == 0
    assert client.sent[-1] == (
        "POST",
        f"{BASE}/connect",
        {"key": KEY, "proof": "fixture-proof", "enabled_opt_in_facts": ["page.script_hashes"]},
    )


def test_connect_refuses_a_fact_the_provider_does_not_offer(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    answers = {f"{BASE}/connect/preview": _preview(shares=[], opt_in_facts=[], hosts=[])}
    client = _install(monkeypatch, answers, io.StringIO(KEY + "\n"))
    argv = ["guard", "integrations", "connect", SHIELD, "--key-stdin", "--yes", "--share", "action.intent"]
    assert cli.main(argv) == 2
    assert "does not offer action.intent" in capsys.readouterr().err
    assert len(client.sent) == 1


def test_disconnect_spends_the_preview_proof(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    answers = {
        f"{BASE}/disconnect/preview": _preview(),
        f"{BASE}/disconnect": {"provider_id": SHIELD, "disconnected": True},
    }
    client = _install(monkeypatch, answers, io.StringIO())
    assert cli.main(["guard", "integrations", "disconnect", SHIELD, "--yes"]) == 0
    assert f"{SHIELD} disconnected." in capsys.readouterr().out
    assert client.sent[-1] == ("POST", f"{BASE}/disconnect", {"proof": "fixture-proof"})


def test_test_prints_the_signal_and_says_it_was_not_stored(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    answer = {
        "provider_id": SHIELD,
        "capability": "browser.origin-reputation",
        "signal": {"verdict": "danger", "reason_codes": ["phishing"]},
        "refresh_at_ms": 5,
    }
    client = _install(monkeypatch, {f"{BASE}/test": answer}, io.StringIO())
    origin = "https://storefront.example-org.com"
    assert cli.main(["guard", "integrations", "test", SHIELD, "--origin", origin]) == 0
    out = capsys.readouterr().out
    assert "answered danger for browser.origin-reputation (reasons: phishing)" in out
    assert "not stored" in out
    assert client.sent == [("POST", f"{BASE}/test", {"capability": "browser.origin-reputation", "origin": origin})]


def test_settings_change_one_effect_and_keep_the_rest(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    answers = {
        BASE: DETAIL,
        f"{BASE}/settings/preview": _preview(settings=[], enabled_opt_in_facts=[]),
        f"{BASE}/settings": {"provider_id": SHIELD, "applied": True},
    }
    client = _install(monkeypatch, answers, io.StringIO())
    argv = [
        "guard",
        "integrations",
        "settings",
        SHIELD,
        "--effect",
        "browser.origin-reputation",
        "enforce",
        "--require-fresh",
        "browser.origin-reputation",
        "on",
        "--yes",
    ]
    assert cli.main(argv) == 0
    assert f"Settings applied to {SHIELD}." in capsys.readouterr().out
    change = {
        "settings": [
            {
                "capability": "browser.origin-reputation",
                "effect": "enforce",
                "require_fresh_check": True,
                "quieted_reason_codes": [],
            }
        ],
        "enabled_opt_in_facts": [],
    }
    assert client.sent[1] == ("POST", f"{BASE}/settings/preview", change)
    assert client.sent[2] == ("POST", f"{BASE}/settings", {**change, "proof": "fixture-proof"})


def test_settings_refuse_an_unknown_effect(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    client = _install(monkeypatch, {BASE: DETAIL}, io.StringIO())
    argv = ["guard", "integrations", "settings", SHIELD, "--effect", "browser.origin-reputation", "block", "--yes"]
    assert cli.main(argv) == 2
    assert "block is not one of observe, tighten, enforce" in capsys.readouterr().err
    assert len(client.sent) == 1


def test_a_daemon_refusal_prints_its_code(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    refusal = GuardDaemonRequestError("Managed policy locks this setting.", status=409, code="setting_managed")
    _install(monkeypatch, {f"{BASE}/disconnect/preview": refusal}, io.StringIO())
    assert cli.main(["guard", "integrations", "disconnect", SHIELD, "--yes", "--json"]) == 2
    answer = json.loads(capsys.readouterr().out)
    assert answer == {
        "ok": False,
        "error": {"code": "setting_managed", "message": "Managed policy locks this setting."},
    }


def test_a_malformed_provider_id_sends_nothing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    client = _install(monkeypatch, {}, io.StringIO())
    assert cli.main(["guard", "integrations", "status", "../v1/settings"]) == 2
    assert "not_found" in capsys.readouterr().err
    assert client.sent == []


def test_enforce_blocks_sets_and_lowers_every_capability(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    answers = {
        BASE: DETAIL,
        f"{BASE}/settings/preview": _preview(settings=[], enabled_opt_in_facts=[]),
        f"{BASE}/settings": {"provider_id": SHIELD, "applied": True},
    }
    for flag, effect in (("on", "enforce"), ("off", "tighten")):
        client = _install(monkeypatch, answers, io.StringIO())
        assert cli.main(["guard", "integrations", "settings", SHIELD, "--enforce-blocks", flag, "--yes"]) == 0
        _method, _path, body = client.sent[1]
        assert body is not None
        assert [row["effect"] for row in body["settings"]] == [effect]
    capsys.readouterr()


def test_settings_send_the_baseline_they_read(monkeypatch: pytest.MonkeyPatch) -> None:
    answers = {
        BASE: {**DETAIL, "settings_baseline": "a" * 64},
        f"{BASE}/settings/preview": _preview(settings=[], enabled_opt_in_facts=[]),
        f"{BASE}/settings": {"provider_id": SHIELD, "applied": True},
    }
    client = _install(monkeypatch, answers, io.StringIO())
    argv = ["guard", "integrations", "settings", SHIELD, "--enforce-blocks", "on", "--yes"]
    assert cli.main(argv) == 0
    _method, path, preview_body = client.sent[1]
    assert path == f"{BASE}/settings/preview"
    assert preview_body is not None and preview_body["baseline"] == "a" * 64
    _method, path, apply_body = client.sent[2]
    assert apply_body is not None and "baseline" not in apply_body, "the proof carries the baseline"


def test_json_with_a_prompt_keeps_stdout_for_the_answer(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    answers = {
        f"{BASE}/disconnect/preview": _preview(),
        f"{BASE}/disconnect": {"provider_id": SHIELD, "disconnected": True},
    }
    _install(monkeypatch, answers, Terminal("y\n"))
    assert cli.main(["guard", "integrations", "disconnect", SHIELD, "--json"]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {"provider_id": SHIELD, "disconnected": True}
    assert "deletes its key" in captured.err, "the preview is shown before the person answers"
    assert "Disconnect this provider? [y/N]" in captured.err


def test_key_stdin_refuses_a_terminal_that_would_echo_the_key(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    client = _install(monkeypatch, {}, Terminal(KEY + "\n"))
    assert cli.main(["guard", "integrations", "connect", SHIELD, "--key-stdin", "--yes"]) == 2
    assert "key_stdin_needs_a_pipe" in capsys.readouterr().err
    assert client.sent == []


def test_a_prompt_that_cannot_hide_the_key_is_refused(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def echoing(_prompt: str, stream: object = None) -> str:
        import warnings

        warnings.warn("echo is on", providers.getpass.GetPassWarning, stacklevel=1)
        return KEY

    client = _install(monkeypatch, {}, Terminal("y\n"))
    monkeypatch.setattr(providers.getpass, "getpass", echoing)
    assert cli.main(["guard", "integrations", "connect", SHIELD]) == 2
    assert "terminal_required" in capsys.readouterr().err
    assert client.sent == []


def test_a_daemon_that_cannot_load_answers_json(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def unavailable(_args: object) -> object:
        raise RuntimeError("Guard daemon state is incomplete.")

    monkeypatch.setattr(providers, "_daemon_client", unavailable)
    assert cli.main(["guard", "integrations", "list", "--json"]) == 2
    answer = json.loads(capsys.readouterr().out)
    assert answer["ok"] is False and answer["error"]["code"] == "daemon_unavailable"
