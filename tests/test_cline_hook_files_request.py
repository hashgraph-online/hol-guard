"""The request Guard sends to the native ``cline_hook_files`` kind and the answers it accepts."""

from __future__ import annotations

import json
import os
from hashlib import sha256
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_runner_authority as authority_module
from codex_plugin_scanner.guard.adapters import cline_hooks
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.native_runner_authority import NativeRunnerAuthorityError

_EVENTS = ("PreToolUse", "PostToolUse", "UserPromptSubmit", "TaskStart", "TaskError", "SessionShutdown")
_MARKER = "# HOL_GUARD_MANAGED_CLINE_HOOK_V1\n"


def _context(tmp_path: Path) -> HarnessContext:
    return HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard")


def _answering(monkeypatch: pytest.MonkeyPatch, answer: object) -> list[tuple[str, dict[str, object]]]:
    calls: list[tuple[str, dict[str, object]]] = []

    def fake(kind: str, args: dict[str, object], **_kwargs: object) -> object:
        calls.append((kind, json.loads(json.dumps(args, allow_nan=False))))
        if isinstance(answer, Exception):
            raise answer
        return answer

    monkeypatch.setattr(authority_module, "native_runner_authority", fake)
    return calls


def _files(slot_suffix: str = "") -> dict[str, dict[str, object]]:
    return {
        event: {
            "slot": f"{event}{slot_suffix}",
            "worker": "{}\n",
            "worker_sha256": "w",
            "launcher": _MARKER,
            "launcher_sha256": "l",
        }
        for event in _EVENTS
    }


def test_render_sends_every_event_path_and_the_platform(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    context = _context(tmp_path)
    calls = _answering(monkeypatch, {"files": _files()})

    files = cline_hooks._render_hook_files(context, runtime="/runtime", guard_cli=["guard", "hook"])

    assert files["TaskStart"]["slot"] == "TaskStart"
    [(kind, request)] = calls
    assert kind == "cline_hook_files"
    managed = context.guard_home / "managed" / "cline"
    assert request == {
        "op": "render",
        "windows": os.name == "nt",
        "runtime": "/runtime",
        "guard_cli": ["guard", "hook"],
        "adapter_state": str(managed / "adapter-state.json"),
        "events": {
            event: {
                "worker": str(managed / "hook-workers" / f"{event}.json"),
                "proof": str(managed / "proofs" / f"native-{event.lower()}.json"),
            }
            for event in _EVENTS
        },
    }


@pytest.mark.parametrize(
    "answer",
    [
        {},
        {"files": []},
        {"files": {event: entry for event, entry in _files().items() if event != "TaskError"}},
        {"files": {**_files(), "Unknown": _files()["TaskStart"]}},
        {"files": {**_files(), "TaskStart": {**_files()["TaskStart"], "extra": "x"}}},
        {"files": {**_files(), "TaskStart": {k: v for k, v in _files()["TaskStart"].items() if k != "worker"}}},
        {"files": {**_files(), "TaskStart": {**_files()["TaskStart"], "worker_sha256": 7}}},
        {"files": {**_files(), "TaskStart": {**_files()["TaskStart"], "slot": "../TaskStart"}}},
        {"files": {**_files(), "TaskStart": {**_files()["TaskStart"], "slot": ".."}}},
    ],
)
def test_malformed_render_answers_are_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, answer: dict[str, object]
) -> None:
    _answering(monkeypatch, answer)
    with pytest.raises(RuntimeError, match="malformed"):
        cline_hooks._render_hook_files(_context(tmp_path), runtime="/r", guard_cli=["g"])


@pytest.mark.parametrize("error", [ValueError("bad"), NativeRunnerAuthorityError("native_runner_authority_refused")])
def test_a_native_refusal_is_the_adapter_runtime_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    _answering(monkeypatch, error)
    with pytest.raises(RuntimeError, match="Cline native hook files failed"):
        cline_hooks._render_hook_files(_context(tmp_path), runtime="/r", guard_cli=["g"])


def _installed(context: HarnessContext) -> tuple[str, dict[str, object]]:
    root = cline_hooks.cline_hook_roots(context)[0]
    suffix = ".ps1" if os.name == "nt" else ""
    paths, workers = {}, {}
    for event in _EVENTS:
        for path in (root / f"{event}{suffix}", cline_hooks._worker_path(context, event)):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(_MARKER, encoding="utf-8")
        paths[event] = str(root / f"{event}{suffix}")
        workers[event] = str(cline_hooks._worker_path(context, event))
    text = json.dumps({"root": str(root), "paths": paths, "sha256": {}, "workers": workers, "worker_sha256": {}})
    state = cline_hooks._state_path(context)
    state.parent.mkdir(parents=True, exist_ok=True)
    state.write_text(text, encoding="utf-8")
    proof = cline_hooks._proof_path(context, "PreToolUse")
    proof.parent.mkdir(parents=True, exist_ok=True)
    proof.write_text('{"timestamp": 1}', encoding="utf-8")
    return text, {"sha256": sha256(_MARKER.encode()).hexdigest(), "managed": True}


def _verdict(**overrides: object) -> dict[str, object]:
    unproven = {"present": False, "fresh": False, "live": False}
    return {
        "installed": True,
        "integrity_ok": True,
        "synthetic_canary_ok": False,
        "live_pretool_proof": {
            "present": True,
            "fresh": True,
            "live": True,
            "event": "PreToolUse",
            "outcome": "blocked",
        },
        "live_posttool_proof": unproven,
        "pretool_blocking_proven": True,
        "posttool_observation_proven": False,
        "post_tool_output_mediation": "observation-only",
        "missing_events": [],
        "modified_events": [],
        "ready": True,
        **overrides,
    }


def test_state_sends_the_observed_files_and_proof_texts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    context = _context(tmp_path)
    text, observed = _installed(context)
    calls = _answering(monkeypatch, {"state": _verdict(), "canary": False})

    cline_hooks.cline_native_hook_state(context)

    [(kind, request)] = calls
    assert kind == "cline_hook_files"
    assert isinstance(request.pop("now"), float)
    assert request == {
        "op": "state",
        "state_text": text,
        "launchers": dict.fromkeys(_EVENTS, observed),
        "workers": dict.fromkeys(_EVENTS, observed),
        "proofs": {"PreToolUse": '{"timestamp": 1}', "PostToolUse": None},
    }


def test_state_without_a_state_file_sends_nothing_observed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    early = {"installed": False, "integrity_ok": False, "ready": False, "missing_events": list(_EVENTS)}
    calls = _answering(monkeypatch, {"state": early, "canary": False})

    assert cline_hooks.cline_native_hook_state(_context(tmp_path)) == early
    request = calls[0][1]
    assert request["state_text"] is None
    assert request["launchers"] == dict.fromkeys(_EVENTS)
    assert request["workers"] == dict.fromkeys(_EVENTS)


@pytest.mark.parametrize(("canary_ok", "ready"), [(True, True), (False, False)])
def test_the_canary_runs_only_when_asked_and_gates_readiness(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, canary_ok: bool, ready: bool
) -> None:
    runs: list[HarnessContext] = []

    def canary(context: HarnessContext) -> dict[str, object]:
        runs.append(context)
        return {"ok": canary_ok}

    monkeypatch.setattr(cline_hooks, "run_cline_hook_canary", canary)
    _answering(monkeypatch, {"state": _verdict(), "canary": True})
    state = cline_hooks.cline_native_hook_state(_context(tmp_path))
    assert (state["synthetic_canary_ok"], state["ready"], len(runs)) == (canary_ok, ready, 1)

    _answering(monkeypatch, {"state": _verdict(ready=False), "canary": False})
    state = cline_hooks.cline_native_hook_state(_context(tmp_path))
    assert (state["synthetic_canary_ok"], state["ready"], len(runs)) == (False, False, 1)


@pytest.mark.parametrize(
    "answer",
    [
        {"state": _verdict()},
        {"state": _verdict(), "canary": "yes"},
        {"state": _verdict(), "canary": False, "extra": 1},
        {"state": [], "canary": False},
        {"state": {**_verdict(), "extra": True}, "canary": False},
        {"state": {k: v for k, v in _verdict().items() if k != "modified_events"}, "canary": False},
        {"state": _verdict(installed="true"), "canary": False},
        {"state": _verdict(missing_events=[1]), "canary": False},
        {"state": _verdict(post_tool_output_mediation="mediated"), "canary": False},
        {"state": _verdict(live_pretool_proof={"present": True}), "canary": False},
        {"state": _verdict(live_pretool_proof={"present": 1, "fresh": False, "live": False}), "canary": False},
        {"state": {"installed": False, "integrity_ok": False, "ready": False}, "canary": False},
    ],
)
def test_malformed_state_answers_are_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, answer: dict[str, object]
) -> None:
    _answering(monkeypatch, answer)
    with pytest.raises(RuntimeError, match="malformed"):
        cline_hooks.cline_native_hook_state(_context(tmp_path))
