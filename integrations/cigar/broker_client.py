"""Private SDK client transport. Rust supplies one grant over its owned pipe.

No credentials in argv/environment or results; no host ingestion/admission port.
"""

import sys

if sys.implementation.name != "cpython" or sys.version_info[:2] != (3, 14) or sys.version_info.releaselevel != "final":
    raise SystemExit(78)

import json

sys.path.insert(0, sys.argv[1])
from cigar_sdk import LocalBrokerConnection, LocalBrokerError, LocalContextClient

_client = None


def dispatch(request):
    global _client
    op = request["op"]
    if op == "prepare" and _client is None:
        return {"ready": True}
    if op == "initialize":
        if _client is not None:
            raise ValueError
        _client = LocalContextClient(
            LocalBrokerConnection.from_config(request["connection"]), timeout=3.0, queue_timeout_ms=500, max_pending=1
        )
        return {"initialized": True}
    if op == "compile":
        return _client.compile(request["request"])
    if op == "revalidate":
        _client.revalidate(request["ticket"])
        return {"current": True}
    if op == "explain":
        return _client.explain(request["ticket"])
    if op == "forget_ticket":
        _client.forget_ticket(request["ticket"])
        return {"forgotten": True}
    if op == "submit_answer":
        return _client.submit_answer(request["ticket"], request["draft"])
    if op == "propose":
        return _client.propose_source(
            request["request_key"], request["source"], request["expected"], request["documents"]
        )
    if op == "proposal_status":
        return _client.proposal_status(request["request_key"])
    if op == "forget_proposal":
        _client.forget_proposal(request["request_key"])
        return {"forgotten": True}
    raise ValueError


def main():
    while True:
        line = sys.stdin.buffer.readline(1024 * 1024 + 1)
        if not line or len(line) > 1024 * 1024 or not line.endswith(b"\n"):
            return
        identity = 0
        try:
            frame = json.loads(line)
            identity = frame["id"]
            if frame["schema"] != "guard-cigar-bridge.v1" or type(identity) is not int or identity <= 0:
                return
            result = dispatch(frame["request"])
            response = {"schema": "guard-cigar-bridge.v1", "id": identity, "ok": True, "result": result}
        except LocalBrokerError as error:
            response = {
                "schema": "guard-cigar-bridge.v1",
                "id": identity,
                "ok": False,
                "error": error.code if error.dispatched is not None else "BrokerOutcomeUnknown",
            }
        except Exception:
            response = {"schema": "guard-cigar-bridge.v1", "id": identity, "ok": False, "error": "BridgeRequestFailed"}
        encoded = (json.dumps(response, ensure_ascii=True, allow_nan=False) + "\n").encode()
        if len(encoded) > 4 * 1024 * 1024:
            return
        sys.stdout.buffer.write(encoded)
        sys.stdout.buffer.flush()


if __name__ == "__main__":
    main()
