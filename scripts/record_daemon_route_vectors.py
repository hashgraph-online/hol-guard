#!/usr/bin/env python3
"""Record daemon route/auth/origin/resolve vectors from the retired Python.

The expected answers come only from the Python implementation that existed
before the resident owned this policy (a scratch checkout of the base commit,
passed as ``--base-src``). They are never produced by the Rust runtime, so the
vectors stay an independent oracle for it.

Usage:
    record_daemon_route_vectors.py --base-src <base-checkout>/src --output <file>

The script runs twice: the parent builds inputs and the native query encoding
from the working tree, and a child (``--oracle``) whose ``PYTHONPATH`` is the
base checkout evaluates the old handler methods on those inputs.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import os
import subprocess
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

from daemon_route_session_cases import session_cases
from daemon_route_vector_cases import LOOPBACK, ORIGIN_PATHS, ORIGINS, resolve_cases, route_paths

BASE_COMMIT = "c412d841caf0d085943fd3a8ae2cad2a82d63b32"
_RESOLVE_START = "        request_id, action, matched = self._resolve_request_action(path_parts, payload)\n"
_RESOLVE_END = "        try:\n            existing_request = self.server.store.get_approval_request(request_id)"
_RESOLVE_BLOCK_SHA256 = "02668b51ff04115b608c57aae78cce60e8e252918e0d57d2be3221c0b536a637"


class _Headers:
    def __init__(self, values: dict[str, str | None]) -> None:
        self._values = values

    def get(self, name: str, default: object = None) -> object:
        value = self._values.get(name)
        return default if value is None else value


# --------------------------------------------------------------------------
# Oracle (runs against the base checkout)
# --------------------------------------------------------------------------


def _resolve_block(base_server: Path) -> str:
    text = base_server.read_text(encoding="utf-8")
    start = text.index(_RESOLVE_START)
    end = text.index(_RESOLVE_END, start)
    return text[start:end]


def _old_resolve(handler_cls, prefix: str, path: str, payload: dict) -> dict:
    """Transcription of the base ``do_POST`` resolve preamble (drift-guarded by hash)."""

    path_parts = [part for part in path.split("/") if part]
    request_id, action, matched = handler_cls._resolve_request_action(path_parts, payload)
    empty = {"request_id": None, "action": None, "scope": None, "scope_contract_version": None}
    empty["scope_contract_digest"] = None
    if not matched:
        return {"outcome": "not_matched", **empty}
    if action is None or request_id is None:
        return {"outcome": "missing_required_fields", **empty}
    scope = payload.get("scope")
    if not isinstance(scope, str) or not scope.strip():
        return {"outcome": "missing_required_fields", **empty}
    version_value = payload.get("scope_contract_version")
    if version_value is not None and (not isinstance(version_value, str) or not version_value.strip()):
        return {"outcome": "invalid_scope_contract_version", **empty}
    version = version_value.strip() if isinstance(version_value, str) else None
    if version is not None and (not version.startswith(prefix) or not version.removeprefix(prefix).isdigit()):
        return {"outcome": "invalid_scope_contract_version", **empty}
    digest_value = payload.get("scope_contract_digest")
    if digest_value is not None and (not isinstance(digest_value, str) or not digest_value.strip()):
        return {"outcome": "invalid_scope_contract_digest", **empty}
    digest = digest_value.strip() if isinstance(digest_value, str) else None
    if digest is not None and (len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest)):
        return {"outcome": "invalid_scope_contract_digest", **empty}
    return {
        "outcome": "resolved",
        "request_id": request_id,
        "action": action,
        "scope": scope.strip(),
        "scope_contract_version": version,
        "scope_contract_digest": digest,
    }


def _stub(handler_cls, command: str, path: str, headers: dict, nonces: dict | None = None):
    handler = object.__new__(handler_cls)
    handler.command = command
    handler.path = path
    handler.headers = _Headers(headers)
    handler.server = SimpleNamespace(
        package_firewall_session_nonces=dict(nonces or {}),
        package_firewall_session_nonces_lock=threading.Lock(),
    )
    return handler


def _oracle(cases: list[dict]) -> list[dict]:
    from codex_plugin_scanner.guard import approval_scope_support
    from codex_plugin_scanner.guard.daemon import server

    cls = server._GuardDaemonHandler
    out: list[dict] = []
    for case in cases:
        kind, raw = case["kind"], case["raw"]
        if kind == "route":
            path = raw["path"]
            parts = [part for part in path.split("/") if part]
            handler = _stub(cls, raw["method"], path, {})
            route_class = "none"
            if path in server._EXTENSION_CONTROL_PATHS:
                route_class = "extension_control"
            elif path in server._LOCAL_CLI_PATHS:
                route_class = "local_cli"
            out.append(
                {
                    "requires_header_token": cls._requires_header_token(path, parts),
                    "session_path": handler._path_supports_dashboard_session(path, parts),
                    "route_class": route_class,
                }
            )
        elif kind == "origin":
            path = raw["path"]
            handler = _stub(cls, "GET", path, {"Origin": raw["origin"]})
            parts = [part for part in path.split("/") if part]
            out.append(
                {
                    "allowed": handler._origin_is_allowed_for_request(path, parts),
                    "hosted_origin": handler._is_hosted_dashboard_origin(),
                    "normalized": cls._normalize_origin(raw["origin"]),
                }
            )
        elif kind == "strict_loopback":
            out.append(
                {
                    "origin": cls._strict_loopback_origin(raw["value"]),
                    "normalized": cls._normalize_origin(raw["value"]),
                }
            )
        elif kind == "session_authorize":
            headers = {"Origin": raw.get("origin_header"), "X-Guard-Dashboard-Nonce": raw.get("nonce_header")}
            handler = _stub(cls, raw["method"], raw["path"], headers)
            allowed = handler._dashboard_session_claims_authorize_request(raw["claims"], payload=raw["payload"])
            consumed = sorted(handler.server.package_firewall_session_nonces)
            replay = _stub(cls, raw["method"], raw["path"], headers, {name: 1e18 for name in consumed})
            replay_allowed = replay._dashboard_session_claims_authorize_request(raw["claims"], payload=raw["payload"])
            assert len(consumed) <= 1, consumed
            out.append(
                {
                    "allowed": allowed,
                    "consume_nonce": consumed[0] if consumed else None,
                    "replay_allowed": replay_allowed,
                }
            )
        elif kind == "resolve_request":
            out.append(
                _old_resolve(
                    cls, approval_scope_support.APPROVAL_SCOPE_CONTRACT_VERSION_PREFIX, raw["path"], raw["payload"]
                )
            )
        else:
            raise SystemExit(f"unknown kind {kind}")
    return out


# --------------------------------------------------------------------------
# Case generation (runs against the working tree)
# --------------------------------------------------------------------------


def _capture_query(kind: str, raw: dict) -> dict:
    from codex_plugin_scanner.guard import native_daemon_route as transport

    class _CapturedError(Exception):
        pass

    def capture(query, *_args, **_kwargs):
        raise _CapturedError(dict(query))

    original = transport._decide
    transport._decide = capture
    try:
        try:
            if kind == "session_authorize":
                transport.native_session_authorize(
                    method=raw["method"],
                    path=raw["path"],
                    claims=raw["claims"],
                    payload=raw["payload"],
                    header_nonce=raw["nonce_header"],
                    request_origin=raw["request_origin"],
                )
            else:
                transport.native_resolve_request(raw["path"], raw["payload"])
        except _CapturedError as captured:
            return captured.args[0]
    finally:
        transport._decide = original
    raise SystemExit("query was not captured")


def _build(base_src: Path) -> dict:
    from codex_plugin_scanner.guard.daemon import server as new_server

    base_server = base_src / "codex_plugin_scanner" / "guard" / "daemon" / "server.py"
    block = _resolve_block(base_server)
    digest = hashlib.sha256(block.encode()).hexdigest()
    if _RESOLVE_BLOCK_SHA256 and digest != _RESOLVE_BLOCK_SHA256:
        raise SystemExit("base resolve preamble drifted from the transcribed oracle")
    cases: list[dict] = []
    for path in route_paths(base_server):
        for method in ("POST", "GET"):
            cases.append({"kind": "route", "name": f"route.{method}.{path}", "raw": {"method": method, "path": path}})
    for method in ("DELETE", "PUT"):
        for path in ("/v1/runtime", "/v1/hooks/codex/pre", "/v1/requests/r1/approve", "/v1/receipts/r1", "/v1/update"):
            cases.append({"kind": "route", "name": f"route.{method}.{path}", "raw": {"method": method, "path": path}})
    for origin, path in itertools.product(ORIGINS, ORIGIN_PATHS):
        cases.append({"kind": "origin", "name": f"origin.{origin!r}.{path}", "raw": {"origin": origin, "path": path}})
    for value in LOOPBACK:
        cases.append({"kind": "strict_loopback", "name": f"strict_loopback.{value!r}", "raw": {"value": value}})
    cases.extend(session_cases(new_server.PROTECTION_REPAIR_DASHBOARD_SURFACE))
    cases.extend(resolve_cases())
    env = {**os.environ, "PYTHONPATH": str(base_src)}
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
    vectors: list[dict] = []
    python_gate: list[dict] = []
    seen: set[str] = set()
    for case, answer in zip(cases, expected, strict=True):
        kind, raw = case["kind"], case["raw"]
        if kind == "route":
            query = {"kind": "route", **raw}
        elif kind == "origin":
            if answer["normalized"] is None:
                assert answer["allowed"] is False and answer["hosted_origin"] is False
                python_gate.append(
                    {"name": case["name"], "raw": raw, "expected": {"allowed": False, "hosted_origin": False}}
                )
                continue
            query = {"kind": "origin", "origin": answer["normalized"], "path": raw["path"]}
            answer = {"allowed": answer["allowed"], "hosted_origin": answer["hosted_origin"]}
        elif kind == "strict_loopback":
            query = {"kind": "strict_loopback", "raw": raw["value"].strip(), "normalized": answer["normalized"]}
            answer = {"origin": answer["origin"]}
        elif kind == "session_authorize":
            raw = {**raw, "request_origin": _normalize(new_server, raw.get("origin_header"))}
            query = _capture_query(kind, raw)
        else:
            query = _capture_query(kind, raw)
        key = json.dumps([query, raw], sort_keys=True)
        if key in seen:
            continue
        seen.add(key)
        vectors.append({"name": case["name"], "raw": raw, "query": query, "expected": answer})
    return {"base_commit": BASE_COMMIT, "resolve_block_sha256": digest, "vectors": vectors, "python_gate": python_gate}


def _normalize(new_server, origin: str | None) -> str | None:
    return new_server._GuardDaemonHandler._normalize_origin(origin)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-src")
    parser.add_argument("--output")
    parser.add_argument("--oracle", action="store_true")
    args = parser.parse_args()
    if args.oracle:
        json.dump(_oracle(json.load(sys.stdin)), sys.stdout)
        return
    document = _build(Path(args.base_src).resolve())
    lines = ",\n".join(json.dumps(vector, sort_keys=True, separators=(",", ":")) for vector in document["vectors"])
    gate = ",\n".join(json.dumps(item, sort_keys=True, separators=(",", ":")) for item in document["python_gate"])
    header = json.dumps(
        {"base_commit": document["base_commit"], "resolve_block_sha256": document["resolve_block_sha256"]}
    )[1:-1]
    Path(args.output).write_text(
        "{" + header + ',\n"vectors":[\n' + lines + '\n],\n"python_gate":[\n' + gate + "\n]}\n", encoding="utf-8"
    )
    print(f"vectors={len(document['vectors'])} python_gate={len(document['python_gate'])}")


if __name__ == "__main__":
    main()
