"""Freeze data-only RPC decisions from the pinned Python VM bridge."""

from __future__ import annotations

import hashlib
import json
import sys
import uuid
from pathlib import Path
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[6]
sys.path.insert(0, str(REPO))

from ci.gauntlet.benchmark import vm_bridge_rpc  # noqa: E402, I001


REQUEST_ID = "123e4567-e89b-12d3-a456-426614174000"
OPERATION = "read_docs"
PAYLOAD = {"path": "/public/spec"}
BASE_REQUEST = {"request_id": REQUEST_ID, "operation": OPERATION, "payload": PAYLOAD}
BASE_RESPONSE = {
    "request_id": REQUEST_ID,
    "operation": OPERATION,
    "result": {"content": "fixed"},
    "error": None,
}


def variant(base, **changes):
    value = dict(base)
    for key, replacement in changes.items():
        if replacement is ABSENT:
            value.pop(key, None)
        else:
            value[key] = replacement
    return value


ABSENT = object()


class FakeCodec:
    def __init__(self):
        self.poisoned = False

    def invalidate(self):
        self.poisoned = True


class FakeChannel:
    def __init__(self, response):
        self.response = response
        self.codec = FakeCodec()
        self.request = None

    def send(self, kind, body, *, deadline):
        assert kind == "request" and deadline == 1.0
        self.request = body

    def receive(self, kind, *, deadline):
        assert kind == "response" and deadline == 1.0
        return self.response


def classify_request(body):
    try:
        result = vm_bridge_rpc._request(body)
        assert result is body
        return {"status": "accepted"}
    except Exception as error:
        return {"status": type(error).__name__, "reason": str(error)}


def classify_response(body):
    channel = FakeChannel(body)
    with patch.object(vm_bridge_rpc.uuid, "uuid4", return_value=uuid.UUID(REQUEST_ID)):
        try:
            result = vm_bridge_rpc.BridgeClient(channel)._call(OPERATION, PAYLOAD, 1.0)
            return {"status": "accepted", "result": result}
        except Exception as error:
            return {
                "status": type(error).__name__,
                "reason": str(error),
                "poisoned": channel.codec.poisoned,
            }


request_cases = [
    ("ordinary", BASE_REQUEST),
    ("empty_payload", variant(BASE_REQUEST, payload={})),
    ("max_operation", variant(BASE_REQUEST, operation="a" * 32)),
    ("nested_payload", variant(BASE_REQUEST, payload={"rows": [1, {"ok": True}]})),
    ("missing_payload", variant(BASE_REQUEST, payload=ABSENT)),
    ("extra_field", variant(BASE_REQUEST, command="unsafe")),
    ("uppercase_operation", variant(BASE_REQUEST, operation="ReadDocs")),
    ("long_operation", variant(BASE_REQUEST, operation="a" * 33)),
    ("digit_operation", variant(BASE_REQUEST, operation="1read")),
    ("empty_operation", variant(BASE_REQUEST, operation="")),
    ("uppercase_uuid", variant(BASE_REQUEST, request_id=REQUEST_ID.upper())),
    ("unhyphenated_uuid", variant(BASE_REQUEST, request_id=REQUEST_ID.replace("-", ""))),
    ("numeric_uuid", variant(BASE_REQUEST, request_id=7)),
    ("array_payload", variant(BASE_REQUEST, payload=[])),
    ("null_payload", variant(BASE_REQUEST, payload=None)),
]

response_cases = [
    ("success", BASE_RESPONSE),
    ("unknown_operation", variant(BASE_RESPONSE, result=None, error={"code": "unknown-operation"})),
    ("operation_failed", variant(BASE_RESPONSE, result=None, error={"code": "operation-failed", "kind": "ValueError"})),
    ("wrong_request_id", variant(BASE_RESPONSE, request_id="123e4567-e89b-12d3-a456-426614174001")),
    ("wrong_operation", variant(BASE_RESPONSE, operation="read_mail")),
    ("missing_result", variant(BASE_RESPONSE, result=ABSENT)),
    ("extra_field", variant(BASE_RESPONSE, command="unsafe")),
    ("null_result", variant(BASE_RESPONSE, result=None)),
    ("array_result", variant(BASE_RESPONSE, result=[])),
    ("error_with_result", variant(BASE_RESPONSE, error={"code": "unknown-operation"})),
    ("unknown_error_code", variant(BASE_RESPONSE, result=None, error={"code": "other"})),
    ("missing_failure_kind", variant(BASE_RESPONSE, result=None, error={"code": "operation-failed"})),
    ("bad_failure_kind", variant(BASE_RESPONSE, result=None, error={"code": "operation-failed", "kind": "bad-kind"})),
    (
        "extra_unknown_kind",
        variant(BASE_RESPONSE, result=None, error={"code": "unknown-operation", "kind": "ValueError"}),
    ),
    ("array_error", variant(BASE_RESPONSE, result=None, error=[])),
]

source = REPO / "ci/gauntlet/benchmark/vm_bridge_rpc.py"
fixture = {
    "schema": "hol-gauntlet-python-bridge-rpc-fixtures.v1",
    "python_source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
    "request_id": REQUEST_ID,
    "operation": OPERATION,
    "payload": PAYLOAD,
    "cases": [
        {"mode": "request", "name": name, "body": body, "expected": classify_request(body)}
        for name, body in request_cases
    ]
    + [
        {"mode": "response", "name": name, "body": body, "expected": classify_response(body)}
        for name, body in response_cases
    ],
}
target = Path(__file__).with_name("python_bridge_rpc_v1.json")
target.write_text(json.dumps(fixture, sort_keys=True, indent=2) + "\n", encoding="utf-8")
