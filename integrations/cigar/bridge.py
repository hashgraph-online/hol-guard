"""Private SDK transport. Rust owns consent, artifact checks, scopes and source I/O.

Launched with -I -S by the native supervisor, never imported by Guard hooks.
Only public local SDK methods are dispatched. No files are ingested here.
"""

import sys

if sys.implementation.name != "cpython" or sys.version_info[:2] != (3, 14) or sys.version_info.releaselevel != "final":
    raise SystemExit(78)

import json

# This absolute directory has already been fingerprinted by the native host.
# -S deliberately skips .pth processing; -I excludes user site and PYTHONPATH.
sys.path.insert(0, sys.argv[1])

if sys.platform == "win32":
    import platform
    import sysconfig

    # Windows reports the host processor from platform.machine(), so the x64
    # interpreter Guard installs on an ARM64 PC would claim arm64 and the SDK
    # would look for a worker built for a processor it does not ship. The
    # build tag names the interpreter, which is the ABI the worker must match.
    _machine = {"win-amd64": "AMD64", "win-arm64": "ARM64"}.get(sysconfig.get_platform())
    if _machine is not None:
        platform.machine = lambda: _machine

from cigar_sdk.context import LocalContextError, LocalContextGraph

_SCHEMA = "guard-cigar-bridge.v1"
_MAX_REQUEST = 1024 * 1024
_MAX_RESPONSE = 4 * 1024 * 1024
_graphs = {}
_views = {}
_brokers = {}


def broker_dispatch(request):
    from cigar_sdk import LocalContextBroker

    op = request["op"]
    key = request["domain"]
    if op == "broker_open":
        _brokers[key] = LocalContextBroker(
            key,
            timeout=3.0,
            graph=request["graph_limits"],
            retention=request["retention"],
            queues=request["queues"],
            transport=request["transport"],
            storage=request.get("storage"),
        )
        return _brokers[key].capabilities()
    broker = _brokers[key]
    if op == "broker_close":
        broker.close()
        del _brokers[key]
        return {"closed": True}
    if op == "broker_revision":
        return broker.source_revision(request["source"])
    if op == "broker_provenance":
        return broker.provenance(request["source"])
    if op == "broker_replace":
        return broker.replace_source(
            request["source"], request["expected"], request["documents"], request["provenance"]
        )
    if op == "broker_grant":
        return broker.grant(
            request["view"], limits=request["limits"], queue=request["queue"], lease_ms=request["lease_ms"]
        ).export()
    if op == "broker_revoke":
        return {"revoked": broker.revoke(request["client"])}
    if op == "broker_proposal":
        return broker.proposal(request["proposal"])
    if op == "broker_admit":
        return broker.admit_proposal(request["proposal"], request["provenance"])
    if op == "broker_reject":
        broker.reject_proposal(request["proposal"])
        return {"rejected": True}
    if op == "broker_submission":
        return broker.submission(request["ticket"])
    if op == "broker_check_answer":
        return broker.check_answer(request["ticket"], request["submission_id"], request["reviews"], request["policy"])
    if op == "broker_bind_execution":
        return broker.bind_execution(
            request["ticket"],
            request["submission_id"],
            request["effect_id"],
            request["intent_digest"],
            request["review"],
        )
    if op == "broker_take_execution":
        return broker.take_execution_handoff(request["binding"], request["review"])
    raise ValueError


def dispatch(request):
    op = request["op"]
    if op.startswith("broker_"):
        return broker_dispatch(request)
    if op == "health":
        return {"running": True}
    if op == "doctor":
        with LocalContextGraph("guard-runtime-doctor", timeout=3.0) as graph:
            capabilities = graph.capabilities()
            graph.upsert({"id": "doctor", "source": "guard:doctor", "text": "Guard local context works."})
            compiled = graph.compile({"required": ["doctor"], "allowed": ["doctor"], "max_tokens": 256})
            verified = graph.verify(compiled["snapshot"]) == compiled
            return {
                "capabilities": capabilities,
                "compile_verified": verified,
                "rendered_tokens": compiled["snapshot"]["stats"]["rendered_tokens"],
            }
    if op == "shutdown":
        return {"closed": True}
    key = request["graph"]
    if op == "open_graph":
        if key in _graphs:
            raise ValueError
        _graphs[key] = LocalContextGraph(key, limits=request["limits"], timeout=3.0)
        return _graphs[key].capabilities()
    graph = _graphs[key]
    if op == "close_graph":
        graph.close()
        del _graphs[key]
        for view_key in tuple(_views):
            if view_key[0] == key:
                del _views[view_key]
        return {"closed": True}
    if op == "replace_source":
        return graph.replace_source(request["source"], request["documents"])
    if op == "create_view":
        spec = request["spec"]
        _views[(key, spec["id"])] = graph.create_view(spec)
        return {"created": True}
    if op == "revoke_view":
        result = graph.revoke_view(request["view"])
        _views.pop((key, request["view"]), None)
        return result
    if op == "compile_view":
        return _views[(key, request["view"])].compile(request["request"])
    if op == "explain_view":
        return _views[(key, request["view"])].explain(request["context"])
    if op == "stats":
        return graph.stats()
    if op == "clear_cache":
        graph.clear_cache()
        return {"cleared": True}
    raise ValueError


def main():
    try:
        while True:
            line = sys.stdin.buffer.readline(_MAX_REQUEST + 1)
            if not line:
                break
            if len(line) > _MAX_REQUEST or not line.endswith(b"\n"):
                break
            request_id = 0
            op = None
            try:
                frame = json.loads(line)
                request_id = frame["id"]
                if frame["schema"] != _SCHEMA or type(request_id) is not int or request_id <= 0:
                    break
                op = frame["request"]["op"]
                result = dispatch(frame["request"])
                response = {"schema": _SCHEMA, "id": request_id, "ok": True, "result": result}
            except LocalContextError as error:
                response = {"schema": _SCHEMA, "id": request_id, "ok": False, "error": error.code}
            except Exception as error:
                # Never emit exception messages, source text or local paths.
                code = "BridgeRequestFailed"
                if isinstance(op, str) and op.startswith("broker_"):
                    from cigar_sdk import LocalBrokerError

                    if isinstance(error, LocalBrokerError):
                        code = error.code if error.dispatched is not None else "BrokerOutcomeUnknown"
                response = {"schema": _SCHEMA, "id": request_id, "ok": False, "error": code}
            encoded = (json.dumps(response, ensure_ascii=True, allow_nan=False) + "\n").encode()
            if len(encoded) > _MAX_RESPONSE:
                break
            sys.stdout.buffer.write(encoded)
            sys.stdout.buffer.flush()
            if op == "shutdown":
                break
    finally:
        for graph in _graphs.values():
            graph.close()
        for broker in _brokers.values():
            broker.close()


if __name__ == "__main__":
    main()
