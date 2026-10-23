"""Freeze signed provider-budget verifier outcomes from the pinned Python code."""

from __future__ import annotations

import base64
import hashlib
import json
from copy import deepcopy
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ci.gauntlet.benchmark.business_model_budget import verify_model_budget
from ci.gauntlet.benchmark.contracts import canonical_json
from ci.gauntlet.benchmark.model_endpoint import DEFAULT_BASE_URL, model_endpoint

ROOT = Path(__file__).resolve().parents[3]
OUTPUT = ROOT / "ci/gauntlet-rs/crates/gauntlet-evidence/tests/fixtures/model_budget_v1.json"
SOURCE = ROOT / "ci/gauntlet/benchmark/business_model_budget.py"
KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
PUBLIC_KEY = KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
NAMES = ("developer_budget.py", "developer_model_relay.py", "business_model_budget.py", "model_endpoint.py")
SOURCES = {name: hashlib.sha256(SOURCE.with_name(name).read_bytes()).hexdigest() for name in NAMES}


def base_record():
    rows = [
        {"sequence": 1, "kind": "model-request", "model_id": "qwen3.6", "model_request_id": 1},
        {
            "sequence": 2,
            "kind": "model-response",
            "model_id": "qwen3.6",
            "model_request_id": 1,
            "method": "POST",
            "provider_tokens": 17,
            "complete": True,
            "error": None,
            "status": 200,
            "cumulative_tokens": 17,
        },
    ]
    return {
        "schema": "gauntlet-business-model-budget.v1",
        "mode": "provider-relay",
        "sdk_stdout_authoritative": False,
        "qualification": False,
        "public_config_digest": "a" * 64,
        "sources": deepcopy(SOURCES),
        "provider": model_endpoint(DEFAULT_BASE_URL),
        "cleanup": {"server_thread_stopped": True, "socket_removed": True, "connections_drained": True},
        "budget": {
            "model_id": "qwen3.6",
            "max_tokens": 100,
            "maximum_requests": 5,
            "model_requests": 1,
            "observed_tokens": 17,
            "usage_known": True,
            "threshold_overrun": 0,
            "cleanup_complete": True,
            "provider": model_endpoint(DEFAULT_BASE_URL),
            "records": rows,
        },
    }


def no_requests(record):
    record["budget"].update(records=[], model_requests=0, observed_tokens=0)


def no_launch(record):
    no_requests(record)
    record["mode"] = "not-launched"


def startup_incomplete(record):
    no_requests(record)
    record["mode"] = "relay-startup-incomplete"
    record["budget"].update(usage_known=False, cleanup_complete=False)
    record["cleanup"] = {key: False for key in record["cleanup"]}


def overrun(record):
    record["budget"].update(observed_tokens=110, threshold_overrun=10)
    record["budget"]["records"][1].update(provider_tokens=110, cumulative_tokens=110)


def pending(record):
    record["budget"].update(records=record["budget"]["records"][:1], usage_known=False, observed_tokens=0)


def partial(record):
    record["budget"]["records"][1]["complete"] = False
    record["budget"]["usage_known"] = False


def legacy(record):
    record["provider"] = {"host": "192.168.5.2", "port": 8001}
    record["sources"].pop("model_endpoint.py")


def protocol(record):
    record["mcp_protocol_profile"] = {"schema": "gauntlet-mcp-protocol-profile.v1", "id": "tool-description"}
    for name in ("mcp_protocol_campaign.py", "mcp_protocol_profiles.py"):
        record["sources"][name] = hashlib.sha256(SOURCE.with_name(name).read_bytes()).hexdigest()


def agent(record):
    record["mcp_agent_surfaces"] = "mcp-agent-surfaces.v1"
    record["budget"]["mcp_agent_surfaces"] = "mcp-agent-surfaces.v1"
    name = "mcp_agent_profile.py"
    record["sources"][name] = hashlib.sha256(SOURCE.with_name(name).read_bytes()).hexdigest()


def both_profiles(record):
    protocol(record)
    agent(record)


def discovery(record):
    row = {
        "sequence": 1,
        "kind": "model-response",
        "model_id": "qwen3.6",
        "model_request_id": None,
        "method": "GET",
        "provider_tokens": None,
        "complete": True,
        "error": None,
        "status": 200,
        "cumulative_tokens": 0,
    }
    for existing in record["budget"]["records"]:
        existing["sequence"] += 1
    record["budget"]["records"].insert(0, row)


def second_request(record):
    record["budget"].update(model_requests=2, observed_tokens=24)
    record["budget"]["records"].extend(
        [
            {"sequence": 3, "kind": "model-request", "model_id": "qwen3.6", "model_request_id": 2},
            {
                "sequence": 4,
                "kind": "model-response",
                "model_id": "qwen3.6",
                "model_request_id": 2,
                "method": "POST",
                "provider_tokens": 7,
                "complete": True,
                "error": None,
                "status": 200,
                "cumulative_tokens": 24,
            },
        ]
    )


def unknown_cost_allowed(record):
    record["budget"].update(usage_known=False, observed_tokens=0)
    record["budget"]["records"][1].update(provider_tokens=None, cumulative_tokens=0)


def signed(record):
    return {"record": record, "signature": base64.b64encode(KEY.sign(canonical_json(record).encode())).decode()}


def classify(name, change=None, *, envelope_change=None):
    record = base_record()
    if change is not None:
        change(record)
    envelope = signed(record)
    outside_sources = (
        record["sources"]
        if name
        in {
            "legacy",
            "protocol",
            "agent",
            "both_profiles",
            "bad_protocol_id",
            "agent_missing_budget",
            "wrong_agent_profile",
        }
        else SOURCES
    )
    if envelope_change is not None:
        envelope_change(envelope)
    try:
        outcome = verify_model_budget(
            envelope,
            trusted_public_key=PUBLIC_KEY,
            model_id="qwen3.6",
            max_tokens=100,
            config_digest="a" * 64,
            maximum_requests=5,
            expected_sources=outside_sources,
            base_url=DEFAULT_BASE_URL,
        )
        result = {"accepted": True, "usage": outcome}
    except Exception as error:
        result = {"accepted": False, "error_type": type(error).__name__}
    return {"name": name, "envelope": envelope, "outside_sources": outside_sources, "expected": result}


cases = [
    classify("complete"),
    classify("no_launch", no_launch),
    classify("startup_incomplete", startup_incomplete),
    classify("overrun", overrun),
    classify("pending", pending),
    classify("partial", partial),
    classify("legacy", legacy),
    classify("protocol", protocol),
    classify("agent", agent),
    classify("both_profiles", both_profiles),
    classify("bad_protocol_id", lambda r: (protocol(r), r["mcp_protocol_profile"].update(id="unknown"))),
    classify("agent_missing_budget", lambda r: (agent(r), r["budget"].pop("mcp_agent_surfaces"))),
    classify("wrong_agent_profile", lambda r: (agent(r), r.update(mcp_agent_surfaces="unknown"))),
    classify("discovery", discovery),
    classify("second_request", second_request),
    classify("unknown_cost_allowed", unknown_cost_allowed),
    classify("wrong_signature", envelope_change=lambda e: e.update(signature="A" * 88)),
    classify("bad_mode", lambda r: r.update(mode="sdk-claimed")),
    classify("sdk_claimed", lambda r: r.update(sdk_stdout_authoritative=True)),
    classify("wrong_config", lambda r: r.update(public_config_digest="b" * 64)),
    classify("wrong_source", lambda r: r["sources"].update({"business_model_budget.py": "b" * 64})),
    classify("wrong_provider", lambda r: r["provider"].update(port=8002)),
    classify("wrong_budget_provider", lambda r: r["budget"]["provider"].update(port=8002)),
    classify("wrong_model", lambda r: r["budget"].update(model_id="other")),
    classify("wrong_max", lambda r: r["budget"].update(max_tokens=101)),
    classify("wrong_request_limit", lambda r: r["budget"].update(maximum_requests=6)),
    classify("duplicate_sequence", lambda r: r["budget"]["records"][1].update(sequence=1)),
    classify("missing_response", lambda r: r["budget"].update(records=r["budget"]["records"][:1])),
    classify("bad_cost", lambda r: r["budget"]["records"][1].update(cumulative_tokens=18)),
    classify("bad_aggregate", lambda r: r["budget"].update(observed_tokens=18)),
    classify("unknown_cost", lambda r: r["budget"]["records"][1].update(provider_tokens=None, cumulative_tokens=0)),
    classify("false_overrun", lambda r: r["budget"].update(threshold_overrun=1)),
    classify("no_launch_with_request", lambda r: r.update(mode="not-launched")),
    classify("bad_cleanup", lambda r: r["cleanup"].update(socket_removed=False)),
    classify("bad_sampling", lambda r: r["budget"]["records"][0].update(generation_parameters={"temperature": "warm"})),
    classify(
        "valid_sampling",
        lambda r: r["budget"]["records"][0].update(generation_parameters={"temperature": 0.7, "top_p": None}),
    ),
    classify("unmatched_response", lambda r: r["budget"]["records"][1].update(model_request_id=2)),
    classify("bad_response_model", lambda r: r["budget"]["records"][1].update(model_id="other")),
    classify("bad_discovery_tokens", lambda r: (discovery(r), r["budget"]["records"][0].update(provider_tokens=1))),
]

fixture = {
    "schema": "hol-gauntlet-python-model-budget-fixtures.v1",
    "python_source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
    "model_endpoint_source_sha256": SOURCES["model_endpoint.py"],
    "public_key_hex": PUBLIC_KEY.hex(),
    "expected_sources": SOURCES,
    "cases": cases,
}
OUTPUT.write_text(json.dumps(fixture, sort_keys=True, indent=2) + "\n", encoding="utf-8")
