"""Freeze Python's side-effect-free live-provider admission branch with mocks."""

from __future__ import annotations

import ast
import hashlib
import json
import re
import tempfile
from contextlib import nullcontext
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

from ci.gauntlet.control_plane import live_provider

ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "ci/gauntlet/control_plane/live_provider.py"
OUTPUT = ROOT / "ci/gauntlet-rs/crates/gauntlet-host-state/tests/python_live_provider_preflight_v1.json"


def extract():
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "start")
    root_index = next(
        index
        for index, node in enumerate(function.body)
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "root" for target in node.targets)
    )
    selected = deepcopy(function.body[1:root_index])
    if len(selected) != 13:
        raise ValueError("Python provider preflight branch shape changed")
    module = ast.fix_missing_locations(ast.Module(body=selected, type_ignores=[]))
    source = ast.unparse(module)
    return compile(module, str(SOURCE), "exec"), hashlib.sha256(source.encode()).hexdigest()


BRANCH, BRANCH_SHA = extract()
BASE = {
    "job_id": "0123456789abcdef",
    "profile": "feature-ai",
    "template_sha": live_provider.TEMPLATE_SHA,
    "allowance_sha": live_provider.ALLOWANCE_SHA,
    "requested_candidate_source_sha": "c1d18f931eaba02a37a2c9515db769fc2219bee8",
    "allowance": {
        "schema": "gauntlet-local-allowance-authorization.v1",
        "previous_charged_tokens": live_provider.ALLOWANCE_START,
        "additional_tokens": 5_000_000,
        "total_tokens": live_provider.CEILING,
        "candidate_source_sha": "c1d18f931eaba02a37a2c9515db769fc2219bee8",
    },
    "quota": {
        "known_tokens": 13_746_906,
        "charged_tokens": 13_746_906,
        "halted": False,
        "pending_requests": 0,
        "reserved_tokens": 0,
        "token_cap": live_provider.CEILING,
    },
    "port_busy": False,
}


def classify(value):
    with tempfile.TemporaryDirectory(prefix="gauntlet-provider-preflight-") as name:
        root = Path(name)
        template = root / "template"
        template.mkdir()
        binding = template / "binding.json"
        binding.write_text(json.dumps({"quota_root": "/synthetic/quota", "quota_config_digest": "a" * 64}))
        allowance = root / "allowance.json"
        allowance.write_text(json.dumps(value["allowance"]))

        def pinned_sha(path):
            if path == binding:
                return value["template_sha"]
            if path == allowance:
                return value["allowance_sha"]
            raise ValueError("unexpected provider preflight path")

        def connect(address, timeout):
            if address != ("127.0.0.1", 8002) or timeout != 1:
                raise ValueError("unexpected provider preflight port")
            if value["port_busy"]:
                return nullcontext()
            raise OSError("synthetic unused port")

        scope = {
            "job_id": value["job_id"],
            "candidate_source_sha": value["requested_candidate_source_sha"],
            "profile": value["profile"],
            "re": re,
            "sha": pinned_sha,
            "TEMPLATE": template,
            "TEMPLATE_SHA": live_provider.TEMPLATE_SHA,
            "ALLOWANCE": allowance,
            "ALLOWANCE_SHA": live_provider.ALLOWANCE_SHA,
            "ALLOWANCE_START": live_provider.ALLOWANCE_START,
            "CEILING": live_provider.CEILING,
            "RESERVATIONS": live_provider.RESERVATIONS,
            "json": json,
            "Path": Path,
            "ProviderQuota": lambda *args, **kwargs: SimpleNamespace(snapshot=lambda: value["quota"]),
            "socket": SimpleNamespace(create_connection=connect),
        }
        try:
            exec(BRANCH, scope)
            return {
                "accepted": True,
                "reservation": scope["reservation"],
                "known_tokens_before": scope["before"]["known_tokens"],
            }
        except Exception as error:
            return {"accepted": False, "error_type": type(error).__name__, "reason": str(error)}


def case(name, *, allowance=None, quota=None, **changes):
    value = deepcopy(BASE)
    if allowance:
        value["allowance"].update(allowance)
    if quota:
        value["quota"].update(quota)
    value.update(changes)
    return {"name": name, "input": value, "expected": classify(value)}


cases = [
    case("feature_ai"),
    case("feature_ai_protocol", profile="feature-ai-protocol"),
    case("beta_e2e_too_large", profile="beta-e2e"),
    case("job_id_wrong_length", job_id="bad"),
    case("job_id_uppercase", job_id="ABCDEF0123456789"),
    case("other_requested_candidate", requested_candidate_source_sha="b" * 40),
    case("unknown_profile", profile="full"),
    case("changed_template", template_sha="b" * 64),
    case("changed_allowance", allowance_sha="b" * 64),
    case("wrong_allowance_schema", allowance={"schema": "other"}),
    case("wrong_previous", allowance={"previous_charged_tokens": 0}),
    case("wrong_additional", allowance={"additional_tokens": 1}),
    case("wrong_ceiling", allowance={"total_tokens": 0}),
    case("wrong_candidate", allowance={"candidate_source_sha": "b" * 40}),
    case("charged_unknown", quota={"charged_tokens": 13_746_905}),
    case("halted", quota={"halted": True}),
    case("pending", quota={"pending_requests": 1}),
    case("reserved", quota={"reserved_tokens": 1}),
    case("quota_cap", quota={"token_cap": 14_468_884}),
    case("below_allowance_start", quota={"known_tokens": 9_468_884, "charged_tokens": 9_468_884}),
    case("feature_reservation_too_large", quota={"known_tokens": 14_300_000, "charged_tokens": 14_300_000}),
    case("port_busy", port_busy=True),
]

fixture = {
    "schema": "hol-gauntlet-python-live-provider-preflight-fixtures.v1",
    "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
    "branch_ast_sha256": BRANCH_SHA,
    "cases": cases,
}
OUTPUT.write_text(json.dumps(fixture, sort_keys=True, indent=2) + "\n", encoding="utf-8")
