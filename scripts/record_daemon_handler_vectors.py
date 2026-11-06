#!/usr/bin/env python3
"""Record daemon handler validation vectors from the retired Python handlers.

The expected answers come only from the Python handler methods that existed
before the resident owned this validation (a scratch checkout of the base
commit, passed as ``--base-src``). They are never produced by the Rust runtime,
so the vectors stay an independent oracle for it.

Usage:
    record_daemon_handler_vectors.py --base-src <base-checkout>/src \
        --base-commit <sha> --output <file>

The script runs twice: the parent builds inputs and the native query encoding
from the working tree, and a child (``--oracle``) whose ``PYTHONPATH`` is the
base checkout runs the old handler methods against a recording store.
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

ABSENT = object()


def _oracle(cases: list[dict]) -> list[dict]:
    from codex_plugin_scanner.guard.daemon import business_review_queue
    from codex_plugin_scanner.guard.daemon import server as srv

    calls: dict = {}
    srv.require_high_risk = lambda *_a, **_k: None
    srv.approval_gate_input_from_mapping = lambda _payload: None
    srv.require_harness_disconnect_gate = lambda *_a, **_k: None

    def bulk(store, request_ids, approval_gate_input):
        calls["ids"] = list(request_ids)
        return {"resolved_count": len(request_ids), "failed": []}

    srv.bulk_allow_read_only_once = bulk
    srv.build_harness_verification = lambda *_a, **_k: calls.setdefault("verify", True) and {"verified": True}
    srv.build_harness_setup_plan = lambda *_a, **kw: calls.update(plan=kw.get("dry_run")) or {"plan": True}
    srv.apply_managed_install = lambda *_a, **_k: calls.update(apply=True) or {}
    business_review_queue.local_request_page = lambda _store, **opts: calls.update(opts=opts) or {"items": []}

    store = SimpleNamespace(guard_home=Path("/tmp/oracle-guard-home"))
    store.clear_policy_decisions = lambda harness, source, **kw: calls.update(clear=(harness, source, kw)) or 7
    store.clear_approval_requests = lambda harness, status: calls.update(requests_clear=(harness, status)) or 7
    store.upsert_policy = lambda decision, _now, approval_gate_grant=None: calls.update(upsert=decision)

    out: list[dict] = []
    for case in cases:
        calls.clear()
        writes: list = []
        handler = object.__new__(srv._GuardDaemonHandler)
        handler.server = SimpleNamespace(store=store)
        handler._write_json = lambda payload, status=200, extra_headers=None, _w=writes: _w.append((status, payload))
        handler._is_hosted_dashboard_origin = lambda: False
        kind, raw = case["kind"], case["raw"]
        if kind == "policy_upsert":
            handler._handle_policy_upsert(dict(raw))
        elif kind == "policy_clear":
            handler._handle_policy_clear(dict(raw))
        elif kind == "requests_clear":
            handler._handle_requests_clear(dict(raw))
        elif kind == "bulk_allow":
            handler._handle_bulk_allow_read_once(dict(raw))
        elif kind == "requests_list":
            handler._handle_requests_list(raw["query"])
        elif kind == "harness_action":
            payload = dict(raw["payload"])
            if raw["action"] == "uninstall":
                payload["confirmation_phrase"] = srv.uninstall_confirmation_token("claude-code")
            handler._handle_harness_action("claude-code", raw["action"], payload)
        elif kind == "events_cursor":
            out.append(
                {
                    "outcome": "proceed",
                    "status": 200,
                    "body": {},
                    "fields": {"cursor": srv._int_query_value(raw["query"], "cursor")},
                }
            )
            continue
        else:
            raise SystemExit(f"unknown kind {kind}")
        status, body = writes[-1]
        fields: dict | None = None
        if "upsert" in calls:
            decision = calls["upsert"]
            fields = {
                key: getattr(decision, key)
                for key in ("harness", "scope", "action", "artifact_id", "workspace", "publisher", "reason")
            }
        elif "clear" in calls:
            harness, source, kw = calls["clear"]
            kw.pop("approval_gate_grant", None)
            fields = {"harness": harness, "source": source, **kw}
        elif "requests_clear" in calls:
            harness, request_status = calls["requests_clear"]
            fields = {"status": request_status, "harness": harness}
        elif "ids" in calls:
            fields = {"request_ids": calls["ids"]}
        elif "opts" in calls:
            opts = calls["opts"]
            fields = {key: opts[key] for key in ("limit", "include_totals", "cursor", "harness", "search")}
            fields["status"] = opts["status"]
        elif kind == "harness_action":
            if calls.get("verify"):
                fields = {"dry_run": None}
            elif "plan" in calls:
                fields = {"dry_run": True}
            elif calls.get("apply"):
                fields = {"dry_run": False}
        if fields is None:
            out.append({"outcome": "reject", "status": status, "body": body, "fields": {}})
        else:
            out.append({"outcome": "proceed", "status": 200, "body": body, "fields": fields})
    return out


def _cases() -> list[dict]:
    cases: list[dict] = []

    def body(kind: str, **fields: object) -> None:
        raw = {key: value for key, value in fields.items() if value is not ABSENT}
        cases.append({"kind": kind, "raw": raw, "name": f"{kind}.{len(cases)}"})

    targets = [{}, {"artifact_id": "x"}, {"workspace": " w "}, {"publisher": "p", "artifact_id": "  "}]
    for harness, scope, action, target in itertools.product(
        ["codex", ABSENT],
        ["global", "harness", "workspace", "artifact", "publisher", " artifact ", "bogus", "", ABSENT],
        ["allow", "block", "warn", "review", "require-reapproval", "sandbox-required", " block ", "bogus"],
        targets,
    ):
        body("policy_upsert", harness=harness, scope=scope, action=action, **target)
    for harness, action in itertools.product([" codex ", 5, "", None, ["a"]], [7, ABSENT, "allow", None]):
        body("policy_upsert", harness=harness, scope="harness", action=action)
    for reason in (ABSENT, "why", "  ", 3, None, " spaced reason "):
        body("policy_upsert", harness="codex", scope="harness", action="warn", reason=reason, workspace=" w ")

    fixed = {"artifact_id": "a1", "artifact_hash": " h ", "workspace": "w", "publisher": ABSENT}
    for harness, source, scope, every, id_null in itertools.product(
        [ABSENT, "codex", " ", 5],
        [ABSENT],
        [ABSENT, "global", "bogus"],
        [ABSENT, True, False, "true", "off", "", "maybe", 1, []],
        [ABSENT, True, "bad"],
    ):
        body(
            "policy_clear", harness=harness, source=source, scope=scope, all=every, artifact_id_is_null=id_null, **fixed
        )
    for scope, source in itertools.product(
        ["artifact", " publisher ", 4, "workspace", "harness"], ["user", " src ", None]
    ):
        body("policy_clear", harness="codex", scope=scope, source=source, **fixed)
    for hash_null in (ABSENT, "yes", "x", 0, False, " ON "):
        body("policy_clear", harness="codex", artifact_hash_is_null=hash_null)

    for status, harness in itertools.product(
        [ABSENT, "pending", "resolved", " resolved ", "all", "bogus", 5, ""], [ABSENT, "codex", " x ", 5]
    ):
        body("requests_clear", status=status, harness=harness)

    for ids in (
        ABSENT,
        [],
        "abc",
        5,
        None,
        ["a"],
        [" a ", "", "  ", 5, "b"],
        [5, None],
        ["  "],
        [None],
        {"a": 1},
        [f"id-{n}" for n in range(300)],
        ["a", "a"],
    ):
        body("bulk_allow", request_ids=ids)

    limits = [
        "",
        "limit=5",
        "limit=0",
        "limit=-3",
        "limit=abc",
        "limit=500",
        "limit=+7",
        "limit=1_0",
        "limit=1__0",
        "limit=%209",
        "limit=",
        "limit=3&limit=",
        "limit=3&limit=9",
        "limit=99999999999999999999999",
        "limit=-99999999999999999999999",
        "limit=007",
        "limit=1.5",
        "limit=%D9%A3",
        "limit=%EF%BC%91%EF%BC%90",
        "limit=%E0%A5%A7_%E0%A5%A8",
        "limit=-%D9%A3",
        "limit=%C2%B2",
        "limit=%D9%A3%D9%A",
        "limit=9223372036854775807",
        "limit=9223372036854775808",
        "limit=1000000000000000000",
    ]
    statuses = [
        "",
        "status=all",
        "status=resolved",
        "status=pending",
        "status=bogus",
        "status=+all+",
        "status=",
        "status=%61ll",
    ]
    for limit, status in itertools.product(limits, statuses):
        query = "&".join(part for part in (limit, status) if part)
        cases.append({"kind": "requests_list", "raw": {"query": query}, "name": f"requests_list.{query!r}"})
    for query in (
        "include_totals=false",
        "include_totals=0",
        "include_totals=OFF",
        "include_totals=maybe",
        "include_totals=",
        "include_totals=%20no%20",
        "include_totals=yes&include_totals=off",
        "cursor=abc%2Fdef",
        "cursor=%zz",
        "cursor=%C3%A9",
        "cursor=%E9",
        "cursor=+++",
        "harness=codex&harness=claude",
        "search=a+b%26c",
        "search=&search=x",
        "bogus",
        "a=1&b&harness=h",
        "harness=h&&&search=s",
        "%68arness=h",
        "harness%3Dh",
    ):
        cases.append({"kind": "requests_list", "raw": {"query": query}, "name": f"requests_list.{query!r}"})

    for action, dry_run in itertools.product(
        ["install", "verify", "repair", "uninstall", "bogus", "Install", ""],
        [ABSENT, True, False, "true", "FALSE", " 1 ", "", "maybe", 0, 1, [], None, {}],
    ):
        raw = {"action": action, "payload": {} if dry_run is ABSENT else {"dry_run": dry_run}}
        cases.append({"kind": "harness_action", "raw": raw, "name": f"harness_action.{len(cases)}"})

    for query in (
        "",
        "cursor=5",
        "cursor=0",
        "cursor=-4",
        "cursor=abc",
        "cursor=",
        "cursor=7&cursor=8",
        "cursor=7&cursor=",
        "cursor=+12+",
        "cursor=1_000",
        "cursor=1__0",
        "cursor=_1",
        "cursor=1_",
        "cursor=0x10",
        "cursor=1.5",
        "cursor=%20%209",
        "cursor=9223372036854775807",
        "cursor=9223372036854775806",
        "cursor=1000000000000000000",
        "cursor=-1000000000000000000",
        "cursor=-9223372036854775808",
        "cursor=-9223372036854775807",
        "cursor=0000000000000000000009223372036854775807",
        "cursor=%D9%A3",
        "cursor=%D9%A1%D9%A2",
        "cursor=-%DB%B5",
        "cursor=%EF%BC%91_%EF%BC%92",
        "cursor=%D9%A3x",
        "cursor=%C2%B2",
        "cursor=%E2%85%A3",
        "cursor=00012",
        "cursor=+-3",
        "cursor=--3",
        "other=1",
    ):
        cases.append({"kind": "events_cursor", "raw": {"query": query}, "name": f"events_cursor.{query!r}"})
    return cases


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
            if kind in ("policy_upsert", "policy_clear", "requests_clear", "bulk_allow"):
                transport.native_body_handler(kind, raw)
            elif kind == "requests_list":
                transport.native_requests_list(raw["query"])
            elif kind == "events_cursor":
                transport.native_events_cursor(raw["query"])
            else:
                transport.native_harness_action(raw["action"], raw["payload"])
        except _CapturedError as captured:
            return captured.args[0]
    finally:
        transport._decide = original
    raise SystemExit("query was not captured")


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
    env = {**os.environ, "PYTHONPATH": str(args.base_src)}
    done = subprocess.run(
        [sys.executable, str(Path(__file__).resolve()), "--oracle"],
        input=json.dumps(cases),
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    if done.returncode != 0:
        raise SystemExit(done.stderr)
    expected = json.loads(done.stdout)
    lines = []
    for case, answer in zip(cases, expected, strict=True):
        if case["kind"] == "events_cursor" and not -(2**63) <= answer["fields"]["cursor"] < 2**63:
            continue
        lines.append(
            json.dumps(
                {"expected": answer, "name": case["name"], "query": _capture_query(case), "raw": case["raw"]},
                sort_keys=True,
                separators=(",", ":"),
            )
        )
    header = json.dumps({"base_commit": args.base_commit}, separators=(",", ":"))[:-1]
    args.output.write_text(header + ',\n"vectors":[\n' + ",\n".join(lines) + "\n]}\n", encoding="utf-8")


if __name__ == "__main__":
    main()
