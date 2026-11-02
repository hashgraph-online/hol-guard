"""The requests the Grok user-config facade sends the native runtime and how it handles the answers."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import grok_config, grok_user_config
from codex_plugin_scanner.guard.cli import grok_hook_validation
from codex_plugin_scanner.guard.native_runner_authority import NativeRunnerAuthorityError

VECTORS = Path(__file__).resolve().parents[1] / "rust/crates/guard-runtime/testdata/grok/user_config_vectors.json"
DOCUMENT = json.loads(VECTORS.read_text(encoding="utf-8"))
CASES = DOCUMENT["cases"]
MERGES = [case for case in CASES if case["op"] == "merge" and "error" not in case["expect"]]
REMOVES = [case for case in CASES if case["op"] == "remove"]
STATE = {
    "added_deny_rules": [],
    "added_hook_events": [],
    "hook_command": "guard hook",
    "prior_compat_hooks": {},
    "created_keys": [],
}


class _Native:
    def __init__(self, answers: list[dict[str, object]]) -> None:
        self.answers = answers
        self.sent: list[tuple[str, dict[str, object]]] = []

    def __call__(self, kind: str, args: dict[str, object], **_kwargs: object) -> dict[str, object]:
        self.sent.append((kind, dict(args)))
        return self.answers.pop(0)


def _native(monkeypatch: pytest.MonkeyPatch, *answers: dict[str, object]) -> _Native:
    native = _Native(list(answers))
    monkeypatch.setattr(grok_user_config, "native_runner_authority", native)
    return native


@pytest.mark.parametrize("case", MERGES, ids=[case["name"] for case in MERGES])
def test_merge_asks_for_candidates_then_retires_the_missing_ones(case: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    native = _native(monkeypatch, {"commands": case["candidates"]}, case["expect"])
    asked: list[tuple[str, str]] = []

    def is_missing(command: str, replacement: str) -> bool:
        asked.append((command, replacement))
        return command in case["missing"]

    monkeypatch.setattr(grok_hook_validation, "is_missing_grok_hook_command", is_missing)

    merged, state = grok_user_config.prepare_user_config_text(
        case["existing_text"], case["hook_command"], previous_state=case["previous_state"]
    )

    read = {"existing_text": case["existing_text"], "previous_state": case["previous_state"]}
    retired = [command for command in case["candidates"] if command in case["missing"]]
    assert native.sent == [
        ("grok_user_config", {**read, "mode": "candidates"}),
        (
            "grok_user_config",
            {**read, "hook_command": case["hook_command"], "mode": "merge", "retired_commands": retired},
        ),
    ]
    assert asked == [(command, case["hook_command"]) for command in case["candidates"]]
    assert (merged, state) == (case["expect"]["merged"], case["expect"]["state"])


@pytest.mark.parametrize("case", REMOVES, ids=[case["name"] for case in REMOVES])
def test_remove_sends_the_recorded_request(case: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    native = _native(monkeypatch, case["expect"])

    restored = grok_user_config.remove_user_config_settings(case["existing_text"], case["previous_state"])

    request = {"existing_text": case["existing_text"], "mode": "remove", "previous_state": case["previous_state"]}
    assert native.sent == [("grok_user_config", request)]
    assert restored == case["expect"]["text"]


def test_a_refused_document_raises_the_runtime_message(monkeypatch: pytest.MonkeyPatch) -> None:
    refusal = {"error": "Grok permission must be a TOML table."}
    _native(monkeypatch, refusal)
    with pytest.raises(ValueError, match=r"Grok permission must be a TOML table\."):
        grok_user_config.prepare_user_config_text("permission = 1\n", "guard hook", previous_state={})
    _native(monkeypatch, {"error": "Grok config is not valid TOML."})
    with pytest.raises(ValueError, match="not valid TOML"):
        grok_user_config.remove_user_config_settings("[", {})


@pytest.mark.parametrize(
    "answer",
    [
        {},
        {"commands": "guard hook"},
        {"commands": [1]},
        {"error": 1},
        {"error": "refused", "commands": []},
    ],
)
def test_an_unusable_candidates_answer_is_refused(answer: dict[str, object], monkeypatch: pytest.MonkeyPatch) -> None:
    _native(monkeypatch, answer)
    with pytest.raises(NativeRunnerAuthorityError):
        grok_user_config.prepare_user_config_text("", "guard hook", previous_state={})


@pytest.mark.parametrize(
    "answer",
    [
        {},
        {"merged": "", "state": []},
        {"merged": 1, "state": STATE},
        {"merged": "", "state": {**STATE, "extra": 1}},
        {"merged": "", "state": {key: value for key, value in STATE.items() if key != "created_keys"}},
    ],
)
def test_an_unusable_merge_answer_is_refused(answer: dict[str, object], monkeypatch: pytest.MonkeyPatch) -> None:
    _native(monkeypatch, {"commands": []}, answer)
    with pytest.raises(NativeRunnerAuthorityError):
        grok_user_config.prepare_user_config_text("", "guard hook", previous_state={})


@pytest.mark.parametrize("answer", [{}, {"text": 1}, {"text": None}])
def test_an_unusable_remove_answer_is_refused(answer: dict[str, object], monkeypatch: pytest.MonkeyPatch) -> None:
    _native(monkeypatch, answer)
    with pytest.raises(NativeRunnerAuthorityError):
        grok_user_config.remove_user_config_settings("", {})


def test_the_native_constants_match_the_python_ones() -> None:
    constants = DOCUMENT["constants"]
    assert constants["managed_deny_rules"] == list(grok_config.MANAGED_DENY_RULES)
    assert constants["compat_vendors"] == list(grok_config.FOREIGN_HOOK_COMPAT_VENDORS)
    assert constants["observe_events"] == list(grok_config.OBSERVE_HOOK_EVENTS)
    assert constants["pretool_timeout"] == grok_config.GROK_PRETOOL_HOOK_TIMEOUT_SECONDS
