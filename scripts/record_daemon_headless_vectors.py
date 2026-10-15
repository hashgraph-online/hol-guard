#!/usr/bin/env python3
"""Record headless-action response vectors from the retired Python builders.

The expected answers come only from the Python response builders that existed
before the resident owned these decisions (a scratch checkout of the base
commit, passed as ``--base-src``). They are never produced by the Rust runtime,
so the vectors stay an independent oracle for it.

Usage:
    record_daemon_headless_vectors.py --base-src <base-checkout>/src \
        --base-commit <sha> --output <file>

The parent builds the cases and the native query encoding from the working
tree; a child (``--oracle``) whose ``PYTHONPATH`` is the base checkout calls
the old builders.
"""

from __future__ import annotations

import argparse
import itertools
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

KINDS = frozenset(
    {"headless_error", "headless_cursor_surface", "headless_state", "detection_statuses", "supply_chain_sync_error"}
)

_OPERATIONS = ["install", "repair", "remove", "status", "scan", "policy_sync", "bogus", ""]
_ERROR_CODES = [
    "missing_harness",
    "unknown_harness",
    "confirmation_required",
    "unsupported_operation",
    "unexpected daemon blowup",
    "",
    "Missing_Harness",
]
_MESSAGES = ["", "   ", " plan limit reached ", "boom", "multi\nline", "caf\u00e9 \u2603", "\u00a0x\u2003", "\t x "]
_ERRORS = ["authorization_expired", "not_configured", "not_available", "other"]


def _cases() -> list[dict]:
    out: list[dict] = []

    def add(kind: str, raw: dict) -> None:
        out.append({"kind": kind, "raw": raw, "name": f"{kind}.{len(out)}"})

    for operation, code in itertools.product(_OPERATIONS, _ERROR_CODES):
        add("headless_error", {"operation": operation, "error_code": code})
    add("headless_cursor_surface", {"surface": ""})
    add("headless_cursor_surface", {"surface": "bogus"})
    harnesses = ["codex", "claude-code", ""]
    managed = [
        None,
        "x",
        {},
        {"active": True},
        {"active": False},
        {"active": None},
        {"active": 0},
        {"active": 1},
        {"active": ""},
        {"active": "yes"},
        {"active": []},
    ]
    verification = [
        None,
        [],
        {},
        {"installed": True},
        {"installed": False},
        {"installed": 0, "command_available": True},
        {"installed": None, "config_paths": ["a"]},
        {"installed": "", "command_available": 0, "config_paths": []},
        {"command_available": False, "config_paths": ["x"]},
        {"config_paths": {}},
    ]
    for harness, operation, managed_install, check in itertools.product(harnesses, _OPERATIONS, managed, verification):
        result: dict = {}
        if managed_install is not None:
            result["managed_install"] = managed_install
        if check is not None:
            result["verification"] = check
        add("headless_state", {"harness": harness, "operation": operation, "result": result})
    for values in (
        [],
        ["protected"],
        ["found", "not_found", "protected", "unknown", "", "None", "Protected", "bogus"],
        ["protected "],
    ):
        add("detection_statuses", {"values": values})
    for error, message, retryable in itertools.product(_ERRORS, _MESSAGES, [True, False]):
        add(
            "supply_chain_sync_error", {"operation": "sync", "error": error, "message": message, "retryable": retryable}
        )
    for operation in ("install", "audit", ""):
        add("supply_chain_sync_error", {"operation": operation, "error": "other", "message": "x", "retryable": False})
    return out


def _oracle_case(case: dict, srv) -> dict:
    kind, raw = case["kind"], case["raw"]
    if kind == "headless_error":
        status, body = srv._headless_action_error_payload(operation=raw["operation"], error_code=raw["error_code"])
        return {"outcome": "reject", "status": status, "body": body, "fields": {}}
    if kind == "headless_cursor_surface":
        handler = object.__new__(srv._GuardDaemonHandler)
        handler.server = SimpleNamespace(store=SimpleNamespace(guard_home=Path("/tmp/oracle-guard-home")))

        def refuse(_payload):
            raise ValueError("invalid_cursor_surface")

        handler._cursor_headless_surface = refuse
        status, body = handler._headless_app_action_payload(
            action_path="connect", payload={"harness": "cursor", "surface": raw["surface"]}
        )
        body["error"].pop("surface")
        return {"outcome": "reject", "status": status, "body": body, "fields": {}}
    if kind == "headless_state":
        state = srv._headless_action_state_payload(
            harness=raw["harness"], operation=raw["operation"], result=raw["result"], receipt={}
        )
        state.pop("receipt_summary")
        return {"outcome": "proceed", "status": 200, "body": {}, "fields": state}
    if kind == "detection_statuses":
        mapped = [srv._headless_detection_status_to_app_status(value) for value in raw["values"]]
        return {"outcome": "proceed", "status": 200, "body": {}, "fields": {"app_statuses": mapped}}
    status, body = srv._supply_chain_package_action_error_response(operation=raw["operation"], error=_build_error(raw))
    return {"outcome": "reject", "status": status, "body": body, "fields": {}}


def _build_error(raw: dict) -> Exception:
    from codex_plugin_scanner.guard.runtime import runner

    kind, message = raw["error"], raw["message"]
    if kind == "authorization_expired":
        return runner.GuardSyncAuthorizationExpiredError(message)
    if kind == "not_configured":
        return runner.GuardSyncNotConfiguredError(message)
    if kind == "not_available":
        return runner.GuardSyncNotAvailableError(message, retryable=raw["retryable"])
    return RuntimeError(message)


def _capture_query(case: dict) -> dict:
    from codex_plugin_scanner.guard import native_daemon_handler as transport

    class _CapturedError(Exception):
        pass

    def capture(query, *_args, **_kwargs):
        raise _CapturedError(dict(query))

    original = transport._decide
    transport._decide = capture
    kind, raw = case["kind"], case["raw"]
    try:
        try:
            if kind == "headless_error":
                transport.native_headless_action_error(raw["operation"], raw["error_code"])
            elif kind == "headless_cursor_surface":
                transport.native_headless_cursor_surface_error()
            elif kind == "headless_state":
                transport.native_headless_action_state(raw["harness"], raw["operation"], raw["result"])
            elif kind == "detection_statuses":
                transport.native_detection_app_statuses(raw["values"])
            else:
                transport.native_supply_chain_error(raw["operation"], _build_error(raw))
        except _CapturedError as captured:
            return captured.args[0]
    finally:
        transport._decide = original
    raise SystemExit("query was not captured")


def _oracle(cases: list[dict]) -> list[dict]:
    from codex_plugin_scanner.guard.daemon import server as srv

    return [_oracle_case(case, srv) for case in cases]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--oracle", action="store_true")
    parser.add_argument("--base-src", type=Path)
    parser.add_argument("--base-commit", default="")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.oracle:
        print(json.dumps(_oracle(json.loads(sys.stdin.read())), sort_keys=True))
        return
    cases = _cases()
    done = subprocess.run(
        [sys.executable, str(Path(__file__).resolve()), "--oracle"],
        input=json.dumps(cases),
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": str(args.base_src)},
        check=False,
    )
    if done.returncode != 0:
        raise SystemExit(done.stderr)
    expected = json.loads(done.stdout)
    lines = [
        json.dumps(
            {"expected": answer, "name": case["name"], "query": _capture_query(case), "raw": case["raw"]},
            sort_keys=True,
            separators=(",", ":"),
        )
        for case, answer in zip(cases, expected, strict=True)
    ]
    header = json.dumps({"base_commit": args.base_commit}, separators=(",", ":"))[:-1]
    args.output.write_text(header + ',\n"vectors":[\n' + ",\n".join(lines) + "\n]}\n", encoding="utf-8")


if __name__ == "__main__":
    main()
