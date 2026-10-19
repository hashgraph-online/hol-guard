"""Sample count varies with scheduling; exact bindings and cleanup cannot vary."""

import hashlib
import json
from pathlib import Path

import pytest

from ci.gauntlet.benchmark.local_executor_controls import _cancel, verify_control
from ci.gauntlet.benchmark.private_cell_runtime_custody import verify_private_cell_runtime


@pytest.fixture
def case():
    raw = (Path(__file__).parent / "fixtures/workflow_benchmark/private_cell_cancel_059.json").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == "49cac68b229bfc1de62b885077359859b45f81b3e1a852bcf3bbae9b4e3d11a7"
    value = json.loads(raw)
    record = value["developer_runtime"]["record"]
    builtin = record["native_builtin_audit"]["record"]
    plane = builtin["product_plane"]
    root = "/opt/hol-private-cell-plane-control-20261014-059"
    bound = value["sdk_gate"]["observation"]
    options = {
        "trusted_public_key": bytes.fromhex(value["controller_public_key_hex"]),
        "expected_settings": record["settings"],
        "expected_session_id": record["controller_session_id"],
        "expected_prompt_digest": record["public_prompt_digest"],
        "workspace_source": root + "/tasks/checkout",
        "provider_mounts": (root + "/tasks/remote", root + "/tasks/home"),
        "agent_identity": value["agent_identity"],
        "sdk_pid": bound["pid"],
        "sdk_identity": bound["identity"],
        "require_mcp": True,
    }
    return value, record, builtin, plane, options


def test_actual_eight_sample_cancellation_is_negative_conformance_not_complete_work(case):
    value, record, _, plane, options = case
    failure = next(row for row in plane["observations"] if row["kind"] == "actual-native-capture-failure")
    assert len(failure["kernel_process_samples"]) == 8
    result = verify_control("cancel", value, public_key=value["controller_public_key_hex"], expected=record["settings"])
    assert result["synthetic"] is True and result["model_tokens"] == 0
    with pytest.raises(ValueError):
        verify_private_cell_runtime(value["developer_runtime"], **options)


@pytest.mark.parametrize("mutation", ["empty", "duplicate", "unbounded", "wrong-command", "privilege", "child-alive"])
def test_partial_sample_invariants_cannot_be_replaced_by_a_count_assertion(case, mutation):
    value, record, builtin, plane, options = case
    # Direct helper mutations exercise negative interpretation after signature
    # validation; these derivatives are unit inputs, never execution evidence.
    failure = next(row for row in plane["observations"] if row["kind"] == "actual-native-capture-failure")
    samples = failure["kernel_process_samples"]
    if mutation == "empty":
        failure["kernel_process_samples"] = []
    elif mutation == "duplicate":
        samples.append(samples[0])
    elif mutation == "unbounded":
        failure["kernel_process_samples"] = [samples[0]] * 1001
    elif mutation == "wrong-command":
        for row in samples:
            row["command_sha256"] = "0" * 64
    elif mutation == "privilege":
        samples[0]["identity"]["effective_uid"] = 0
    else:
        value["detached_child_alive_before_cell_teardown"] = True
    with pytest.raises(ValueError):
        _cancel(value, record, builtin, plane, options["trusted_public_key"], options)
