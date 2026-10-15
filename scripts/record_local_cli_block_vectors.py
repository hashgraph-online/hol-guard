#!/usr/bin/env python3
"""Record parity vectors for the daemon's custom extension block.

The expected answers come from the Python the daemon runs for an allowed
native ``PreToolUse`` while a custom block rule exists:
``native_local_cli_block_response`` (``hook_native_local_cli.py``), the
grant answer checks in ``decide_local_cli_grant`` and ``_decode_payload``,
``match_command_id``, and the Watch replacement in ``hook_worker_native.py``.
The resident's port in ``hook_direct_local_cli_block.rs`` replays every
vector. Identity derivation and the store read are the resident's own, so
the grant and the launch identity are given; rendering is captured as the
verdict handed to the resident's renderer.

Usage: python scripts/record_local_cli_block_vectors.py [--check]
Deterministic output.
"""

from __future__ import annotations

import ast
import json
import sys
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from codex_plugin_scanner.guard import local_cli_grant_decision as grant_decision  # noqa: E402
from codex_plugin_scanner.guard.daemon import hook_native_local_cli as block  # noqa: E402
from codex_plugin_scanner.guard.daemon import hook_native_saved_approval as saved  # noqa: E402
from codex_plugin_scanner.guard.native_local_cli_grant import (  # noqa: E402
    NativeLocalCliGrantFailure,
    _decode_payload,
)
from codex_plugin_scanner.guard.runtime.local_cli_commands import (  # noqa: E402
    LocalCliCommand,
    match_command_id,
)
from codex_plugin_scanner.guard.runtime.local_cli_identity import UnlistedCliIdentity  # noqa: E402

OUT = ROOT / "rust/crates/guard-runtime/tests/fixtures/local_cli_block_vectors.json"
WORKER = ROOT / "src/codex_plugin_scanner/guard/daemon/hook_worker_native.py"
CLI_ID = "local-cli.demo-tool"
HASH = "a" * 64
OTHER_HASH = "b" * 64
HARNESSES = ["codex", "claude-code", "copilot", "kimi", "devin", "zcode", "openclaw", "hermes", "cline", "grok"]


def identity(name: str = "demo-tool") -> UnlistedCliIdentity:
    return UnlistedCliIdentity(
        cli_id=CLI_ID,
        name=name,
        kind="script",
        identity_hash=HASH,
        example_label=name,
        identity_source={"kind": "fixture"},
    )


def command_id_cases() -> list[tuple[list[str], list[str]]]:
    catalog = ["build", "db", "db.migrate", "db.migrate.up", "a.b.c.d", "a.b.c.d.e"]
    return [
        ([], catalog),
        ([], []),
        (["build"], catalog),
        (["build", "--watch"], catalog),
        (["db", "migrate"], catalog),
        (["db", "migrate", "up", "--all"], catalog),
        (["db", "seed"], catalog),
        (["a", "b", "c", "d", "e"], catalog),
        (["a", "b", "c"], catalog),
        (["test"], catalog),
        (["test"], []),
        (["Build"], catalog),
        (["db.migrate"], catalog),
        ([""], ["", "x"]),
    ]


def grant_cases() -> list[tuple[str, object]]:
    def answer(state: object, cli_id: object = CLI_ID, identity_hash: object = HASH) -> dict[str, object]:
        return {"state": state, "cli_id": cli_id, "identity_hash": identity_hash}

    return [
        ("allowed", answer("allowed")),
        ("blocked", answer("blocked")),
        ("none", answer("none")),
        ("none-without-identity", answer("none", None, None)),
        ("unknown-state", answer("review")),
        ("other-cli", answer("blocked", "local-cli.other")),
        ("other-hash", answer("blocked", CLI_ID, OTHER_HASH)),
        ("allowed-other-hash", answer("allowed", CLI_ID, OTHER_HASH)),
        ("blocked-without-cli", answer("blocked", None)),
        ("upper-hash", answer("blocked", CLI_ID, HASH.upper())),
        ("extra-key", {**answer("blocked"), "extra": 1}),
        ("failure", None),
    ]


def grant_outcome(payload: object) -> str | None:
    def native(**_: object) -> object:
        decoded = _decode_payload(payload) if payload is not None else None
        return decoded if decoded is not None else NativeLocalCliGrantFailure("native_local_cli_grant_payload_invalid")

    store = mock.Mock(path=Path("/guard/guard.db"), guard_home=Path("/guard"))
    store.read_local_cli_command_catalog.return_value = []
    # The decision logs each unverified answer; the vectors record the outcome.
    with (
        mock.patch.object(grant_decision, "native_local_cli_grant", native),
        mock.patch.object(grant_decision, "_LOGGER"),
    ):
        try:
            return grant_decision.decide_local_cli_grant(
                store=store,
                identity=identity(),
                command="demo-tool build",
                cwd=Path("/work"),
                home_dir=None,
                current_action="allow",
            )
        except grant_decision.LocalCliIdentityUnavailableError:
            return "unverified"


def results() -> list[tuple[str, dict[str, object]]]:
    base: dict[str, object] = {
        "decision": "allow",
        "minimum_action": "allow",
        "policy_action": "allow",
        "reason_code": "native_allow",
        "reason": "Allowed by policy.",
    }
    return [
        ("plain", base),
        ("bare", {"decision": "allow", "minimum_action": "allow"}),
        (
            "with-action",
            {
                **base,
                "action": {"action_type": "shell", "command": "demo-tool build"},
                "risk": {"level": "low", "signals": ["local_cli"]},
                "scope": "workspace",
            },
        ),
        ("unicode", {**base, "reason": "Allowed — résumé ☃"}),
    ]


def block_cases() -> list[tuple[str, str, dict[str, object], str]]:
    cases = [(f"{harness}-plain", harness, results()[0][1], "demo-tool") for harness in HARNESSES]
    for label, result in results()[1:]:
        cases.extend((f"{harness}-{label}", harness, result, "demo-tool") for harness in ("codex", "claude-code"))
    cases.append(("codex-name", "codex", results()[0][1], 'My "quoted" tool é'))
    return cases


def block_outcome(harness: str, result: dict[str, object], name: str) -> dict[str, object] | None:
    rendered: list[dict[str, object]] = []

    def capture(harness: str, verdict: dict[str, object], **_: object) -> dict[str, object]:
        rendered.append({"harness": harness, "verdict": dict(verdict)})
        return {}

    with (
        mock.patch.object(block, "_has_block_rules", return_value=True),
        mock.patch.object(block, "_matching_grant", return_value=(identity(name), "blocked")),
        mock.patch.object(block, "store_guard_home", return_value=None),
        mock.patch.object(saved, "render_pre_tool", capture),
    ):
        response = block.native_local_cli_block_response(
            object(), harness=harness, payload={}, native_result=result, workspace=None, home_dir=None
        )
    if response is None:
        return None
    (call,) = rendered
    return {**call, "approval_reuse_status": response["approval_reuse_status"]}


def watch_render() -> dict[str, str]:
    """The arguments the worker renders a custom block with in Watch."""

    tree = ast.parse(WORKER.read_text(encoding="utf-8"))
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "render_recording_only_pre_tool":
            keywords = {kw.arg: kw.value for kw in node.keywords}
            code = keywords.get("reason_code")
            if isinstance(code, ast.Constant) and code.value == "local_cli_extension_blocked":
                reason = keywords["reason"]
                assert isinstance(reason, ast.Constant)
                found.append({"reason_code": code.value, "reason": reason.value})
    (only,) = found
    return only


def cases() -> list[object]:
    return [*command_id_cases(), *grant_cases(), *block_cases()]


def document() -> dict[str, object]:
    return {
        "command_ids": [
            {
                "tokens": tokens,
                "catalog": catalog,
                "expected": match_command_id(
                    tokens, [LocalCliCommand(command_id=item, name=item, usage="", description="") for item in catalog]
                ),
            }
            for tokens, catalog in command_id_cases()
        ],
        "grant_answers": {
            "cli_id": CLI_ID,
            "identity_hash": HASH,
            "cases": [
                {"label": label, "answer": payload, "expected": grant_outcome(payload)}
                for label, payload in grant_cases()
            ],
        },
        "blocks": [
            {
                "label": label,
                "harness": harness,
                "result": result,
                "name": name,
                "expected": block_outcome(harness, result, name),
            }
            for label, harness, result, name in block_cases()
        ],
        "watch": watch_render(),
    }


def render() -> str:
    return json.dumps(document(), indent=2, ensure_ascii=True, sort_keys=True) + "\n"


def main() -> int:
    text = render()
    if "--check" in sys.argv[1:]:
        if OUT.read_text(encoding="utf-8") != text:
            print(f"{OUT} is stale; rerun {Path(__file__).name}", file=sys.stderr)
            return 1
        return 0
    OUT.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
