"""Record the Oh My Pi steps the daemon takes on the hooks the resident answers.

Four groups, each recorded from the daemon code itself:

* ``source_ref_external_allowed``: the flag ``_review_native_edge_with_snapshot``
  passes the edge for a route harness spelling, captured at its edge call.
* ``structured_mediation``: whether ``_apply_structured_mediation`` reads the
  managed structured-output config for a harness and event, captured at that
  read.
* ``structured_output``: for a managed policy and a ``pi`` or ``omp``
  ``PostToolUse``, the view the publisher binds (``null`` when it binds
  none) and whether ``_apply_structured_mediation`` returned the edge
  response unchanged after resolving that policy through the native
  ``resolution`` query. The resident answers only such a hook.
* ``lifecycle``: the constant ``availability_harness_response`` returns for an
  ``pi`` or ``omp`` event the edge does not review.

Run from the repository root with a native runtime; the recorder resolves in
a throwaway home of its own and fails rather than record an unavailable one:

    HOL_GUARD_NATIVE_BINARY=<hol-guard-runtime> HOL_GUARD_NATIVE=force \
        .venv/bin/python rust/crates/guard-runtime/testdata/hook_direct_pi/record_pi_vectors.py
"""

from __future__ import annotations

import json
import os
import tempfile
from contextlib import suppress
from pathlib import Path
from types import SimpleNamespace

from codex_plugin_scanner.guard.daemon.hook_availability_policy import availability_harness_response
from codex_plugin_scanner.guard.daemon.hook_worker_native import HookWorkerNativeMixin
from codex_plugin_scanner.guard.native_content_sensitivity import content_query
from codex_plugin_scanner.guard.native_policy_snapshot_direct_lane_structured import structured_output_view
from codex_plugin_scanner.guard.native_policy_snapshot_publisher import provision_native_verifier_key_for_store
from codex_plugin_scanner.guard.runtime.structured_output_mediation import _config_wire
from codex_plugin_scanner.guard.store import GuardStore

OUT = Path(__file__).with_name("pi_vectors.json")
HOME = Path("/home/guard")
UNAVAILABLE_REASON_CODE = "native_hook_event_unavailable"
SPELLINGS = [
    "pi",
    "omp",
    "PI",
    " Omp ",
    "\tpi\n",
    "\x1cpi\x1f",
    "\u3000omp\u00a0",
    "o_m_p",
    "oh-my-pi",
    "oh_my_pi",
    "pi-agent",
    "pi_coding_agent",
    "pi-coding-agent",
    "pix",
    "p i",
    "",
    "codex",
    "claude-code",
    "cursor",
    "copilot",
    "kimi",
    "devin",
    "zcode",
    "openclaw",
    "hermes",
    "cline",
    "opencode",
    "grok",
]
EVENTS = ["PreToolUse", "PostToolUse", "UserPromptSubmit"]
LIFECYCLE_EVENTS = [
    "SessionStart",
    "SessionEnd",
    "session_start",
    "Stop",
    "SubagentStop",
    "Notification",
    "TaskStart",
    "SessionShutdown",
    "agent_end",
    "turn_end",
]


class _ReachedError(Exception):
    pass


class _EdgeHost:
    """Stops `_review_native_edge_with_snapshot` at its edge call."""

    def __init__(self) -> None:
        self.captured: dict[str, object] = {}

    def _review_raw_hook_native(self, **kwargs: object) -> None:
        self.captured = kwargs
        raise _ReachedError


class _MediationHost:
    """Stops `_apply_structured_mediation` at its config read."""

    def _structured_output_resolution(self, **_kwargs: object) -> None:
        raise _ReachedError


def _source_ref_external_allowed(spelling: str, guard_home: Path) -> bool:
    host = _EdgeHost()
    with suppress(_ReachedError):
        HookWorkerNativeMixin._review_native_edge_with_snapshot(  # pyright: ignore[reportPrivateUsage]
            host,  # type: ignore[arg-type]
            payload={"tool_name": "Bash", "tool_input": {"command": "pwd"}},
            harness=spelling,
            event_name="PreToolUse",
            default_harness=spelling,
            home_dir=HOME,
            guard_home=guard_home,
            workspace=None,
            deadline=None,
            policy_snapshot={"generation": 1},
            recording_only=False,
        )
    allowed = host.captured["source_ref_external_allowed"]
    assert isinstance(allowed, bool)
    return allowed


def _structured_mediation(spelling: str, event: str, guard_home: Path) -> bool:
    try:
        HookWorkerNativeMixin._apply_structured_mediation(  # pyright: ignore[reportPrivateUsage]
            _MediationHost(),  # type: ignore[arg-type]
            {},
            payload={},
            native_harness=spelling,
            native_event=event,
            accepted_receipt=None,
            guard_home=guard_home,
            workspace=None,
            deadline=None,
            recording_only=False,
        )
    except _ReachedError:
        return True
    return False


SETTING = "data_control.structured_output"
HASH = "a" * 64
OTHER_HASH = "b" * 64
EDGE_RESULT = {"harness_response": {"decision": "allow"}, "event_name": "PostToolUse"}


def _setting(harnesses: object, **overrides: object) -> dict[str, object]:
    setting: dict[str, object] = {
        "version": "hol-guard-structured-output-policy.v1",
        "enabled": True,
        "harnesses": harnesses,
        "event": "PostToolUse",
        "destinationRole": "model_visible_tool_result",
        "schema": {
            "fields": [
                {"path": ["email"], "role": "protected_personal", "valueType": "string", "category": "email_address"}
            ]
        },
        "onMatch": "withhold",
        "onUnsupported": "withhold",
    }
    setting.update(overrides)
    return setting


def _policy(content_hash: object, settings: object) -> SimpleNamespace:
    return SimpleNamespace(content_hash=content_hash, settings=settings)


def _structured(setting: object) -> dict[str, object]:
    return {"data_control": {"structured_output": setting}, "harness_postures": {"pi": "watch"}}


def _config(status: object, policy_hash: object, locked: object, policy: object) -> SimpleNamespace:
    return SimpleNamespace(
        managed_policy_status=status,
        managed_policy_hash=policy_hash,
        managed_locked_settings=locked,
        managed_policy=policy,
    )


MANAGED_POLICIES: list[tuple[str, SimpleNamespace]] = [
    ("absent", _config("absent", None, (), None)),
    ("no_status", _config(None, None, (), None)),
    ("absent_reserved", _config("absent", None, (SETTING,), None)),
    ("absent_with_hash", _config("absent", HASH, (), None)),
    ("absent_with_policy", _config("absent", None, (), _policy(HASH, {}))),
    ("active_without_setting", _config("active", HASH, ("harness_postures",), _policy(HASH, {"other": {"x": 1}}))),
    ("active_other_data_control", _config("active", HASH, (), _policy(HASH, {"data_control": {"other": True}}))),
    ("active_unlocked_setting", _config("active", HASH, (), _policy(HASH, _structured(_setting(["pi"]))))),
    ("active_locked_pi", _config("active", HASH, (SETTING,), _policy(HASH, _structured(_setting(["pi"]))))),
    ("active_locked_omp", _config("active", HASH, [SETTING], _policy(HASH, _structured(_setting(["omp"]))))),
    ("active_locked_both", _config("active", HASH, (SETTING,), _policy(HASH, _structured(_setting(["omp", "pi"]))))),
    (
        "active_locked_disabled",
        _config("active", HASH, (SETTING,), _policy(HASH, _structured(_setting(["omp"], enabled=False)))),
    ),
    (
        "active_locked_unknown_harness",
        _config("active", HASH, (SETTING,), _policy(HASH, _structured(_setting(["codex"])))),
    ),
    ("active_locked_without_setting", _config("active", HASH, (SETTING,), _policy(HASH, {}))),
    ("active_locked_without_hash", _config("active", None, (SETTING,), _policy(None, _structured(_setting(["omp"]))))),
    ("active_locked_short_hash", _config("active", "abc", (SETTING,), _policy("abc", _structured(_setting(["omp"]))))),
    ("active_locked_without_policy", _config("active", HASH, (SETTING,), None)),
    (
        "active_locked_hash_mismatch",
        _config("active", HASH, (SETTING,), _policy(OTHER_HASH, _structured(_setting(["omp"])))),
    ),
    ("active_locked_settings_unreadable", _config("active", HASH, (SETTING,), _policy(HASH, None))),
    ("active_locked_set", _config("active", HASH, frozenset({SETTING}), _policy(HASH, _structured(_setting(["omp"]))))),
    ("active_locked_text", _config("active", HASH, SETTING, _policy(HASH, _structured(_setting(["omp"]))))),
    ("invalid", _config("invalid", HASH, ("*",), _policy(HASH, {}))),
    ("inaccessible", _config("inaccessible", None, (), None)),
    ("tampered", _config("tampered", None, (), None)),
    ("revoked", _config("revoked", None, (), None)),
    ("stale", _config("stale", None, (), None)),
    ("unknown_status", _config("ACTIVE", HASH, (), _policy(HASH, {}))),
    # Views the publisher does not bind: the resident defers whatever the
    # daemon then resolves.
    ("tuple_harnesses", _config("active", HASH, (SETTING,), _policy(HASH, _structured(_setting(("omp",)))))),
    (
        "float_in_setting",
        _config("active", HASH, (SETTING,), _policy(HASH, _structured(_setting(["omp"], version=1.5)))),
    ),
    ("integer_key_in_setting", _config("active", HASH, (SETTING,), _policy(HASH, _structured({1: "omp"})))),
    (
        "unpaired_surrogate",
        _config("active", HASH, (SETTING,), _policy(HASH, _structured(_setting(["omp"], event="\ud800")))),
    ),
]


class _ResolvingHost:
    """Resolves through the daemon's own read and stops before mediating."""

    def __init__(self, config: object) -> None:
        self.config = config

    def _load_config(self, _guard_home: Path, _workspace: Path | None) -> object:
        return self.config

    def _structured_output_resolution(self, **kwargs: object) -> object:
        resolution = HookWorkerNativeMixin._structured_output_resolution(self, **kwargs)  # type: ignore[arg-type]
        if resolution.required:
            raise _ReachedError
        return resolution


def _resolves_natively(config: object, harness: str) -> None:
    # The daemon reads any query failure as required. Recording one would
    # record this machine, not the rule, so only an unencodable view may fail.
    try:
        json.dumps(_config_wire(config), ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        return
    content_query("resolution", {"config": _config_wire(config), "harness": harness})


def _edge_unchanged(config: object, harness: str, guard_home: Path) -> bool:
    try:
        result = HookWorkerNativeMixin._apply_structured_mediation(  # pyright: ignore[reportPrivateUsage]
            _ResolvingHost(config),  # type: ignore[arg-type]
            EDGE_RESULT,
            payload={},
            native_harness=harness,
            native_event="PostToolUse",
            accepted_receipt=None,
            guard_home=guard_home,
            workspace=None,
            deadline=None,
            recording_only=False,
        )
    except _ReachedError:
        return False
    assert result == EDGE_RESULT
    return True


def _structured_output(guard_home: Path) -> list[dict[str, object]]:
    store_home = Path(os.environ["HOME"]) / ".hol-guard"
    store_home.mkdir(mode=0o700)
    provision_native_verifier_key_for_store(GuardStore(store_home))
    vectors: list[dict[str, object]] = []
    for name, config in MANAGED_POLICIES:
        for harness in ("pi", "omp"):
            _resolves_natively(config, harness)
            vectors.append(
                {
                    "policy": name,
                    "harness": harness,
                    "view": structured_output_view(config),
                    "unchanged": _edge_unchanged(config, harness, guard_home),
                }
            )
    return vectors


def main() -> None:
    if not os.environ.get("HOL_GUARD_NATIVE_BINARY"):
        raise SystemExit("set HOL_GUARD_NATIVE_BINARY to a hol-guard-runtime")
    with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as home:
        # The native query resolves in the home the process names.
        os.environ["HOME"] = home
        guard_home = Path(root)
        source_ref = [
            {"harness": spelling, "allowed": _source_ref_external_allowed(spelling, guard_home)}
            for spelling in SPELLINGS
        ]
        mediation = [
            {"harness": spelling, "event": event, "mediated": _structured_mediation(spelling, event, guard_home)}
            for spelling in SPELLINGS
            for event in EVENTS
        ]
        structured_output = _structured_output(guard_home)
    lifecycle = [
        {
            "harness": harness,
            "event": event,
            "response": availability_harness_response(
                {},
                harness=harness,
                event_name=event,
                reason_code=UNAVAILABLE_REASON_CODE,
                reason="HOL Guard could not complete the native hook decision safely.",
            ),
        }
        for harness in ("pi", "omp")
        for event in LIFECYCLE_EVENTS
    ]
    vectors = {
        "source_ref_external_allowed": source_ref,
        "structured_mediation": mediation,
        "lifecycle": lifecycle,
        "structured_output": structured_output,
    }
    OUT.write_text(json.dumps(vectors, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
