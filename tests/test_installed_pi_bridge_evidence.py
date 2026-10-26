"""The installed Pi probe holds each case to one Guard request on its lane."""

from __future__ import annotations

import json
import shutil
import sys
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from ci.native_runtime import probe_installed_pi_output as probe
from ci.native_runtime.pi_probe_guard_evidence import (
    BRIDGE,
    FETCH,
    ProbeError,
    assert_bridge_routes,
    assert_guard_requests,
    assert_unavailable_results,
    bridge_route_counts,
    capture_log_size,
    generated_transport,
    read_capture_records,
    text_digest,
    wait_for_bridge_native_routes,
)


def _result(case: dict[str, object]) -> dict[str, object]:
    return {"id": case["id"], "preserved": True, "result": None, "input_content_unchanged": True}


def _bridge_request(case: dict[str, object]) -> dict[str, object]:
    return {
        "case_id": case["id"],
        "transport": BRIDGE,
        "harness": "omp",
        "exit_code": 0,
        "status": 200,
        "decision": "allow",
        "model_output_action": "allow_original",
        "reviewed_output_sha256": text_digest(case["content"])[0],
    }


def test_generated_source_names_its_lane() -> None:
    declaration = "const GUARD_NATIVE_HOOK_RUNTIME: string | null = {};\n"
    assert generated_transport(declaration.format("null")) == FETCH
    assert generated_transport(declaration.format(json.dumps("/opt/guard/hol-guard-runtime"))) == BRIDGE
    with pytest.raises(ProbeError, match="does not declare"):
        generated_transport("const GUARD_HOME = null;\n")
    with pytest.raises(ProbeError, match="does not declare"):
        generated_transport(declaration.format("null") * 2)
    with pytest.raises(ProbeError, match="invalid native hook runtime"):
        generated_transport(declaration.format('""'))


def test_bridge_lane_requires_one_completed_bridge_reply_with_exact_proof() -> None:
    case = probe._cases()[0]
    request = _bridge_request(case)

    evidence = assert_guard_requests([request], [_result(case)], [case], transport=BRIDGE)
    assert evidence[str(case["id"])]["transport"] == BRIDGE
    assert evidence[str(case["id"])]["exit_code"] == 0

    fetched = {
        "case_id": case["id"],
        "transport": FETCH,
        "method": "POST",
        "pathname": "/v1/hooks/omp",
        "status": 200,
    }
    with pytest.raises(ProbeError, match="did not use the pi-hook-bridge lane"):
        assert_guard_requests([fetched], [_result(case)], [case], transport=BRIDGE)
    with pytest.raises(ProbeError, match="exactly one Guard request per real case"):
        assert_guard_requests([request, deepcopy(request)], [_result(case)], [case], transport=BRIDGE)
    with pytest.raises(ProbeError, match="exactly one Guard request per real case"):
        assert_guard_requests([], [_result(case)], [case], transport=BRIDGE)
    for field, value, message in (
        ("exit_code", 1, "did not complete"),
        ("exit_code", None, "did not complete"),
        ("harness", "pi", "did not complete"),
        ("status", 0, "not successful"),
        ("reviewed_output_sha256", "0" * 64, "proof mismatch"),
    ):
        broken = {**request, field: value}
        with pytest.raises(ProbeError, match=message):
            assert_guard_requests([broken], [_result(case)], [case], transport=BRIDGE)
    with pytest.raises(ProbeError, match="unapproved fields"):
        assert_guard_requests([{**request, "body": "{}"}], [_result(case)], [case], transport=BRIDGE)


def test_bridge_routes_count_resident_answers_and_native_daemon_routes_once() -> None:
    counts = bridge_route_counts(
        {"routes": {"native_resident": 1}},
        {"resident": {"omp": {"answer": 3, "binding_incomplete": 1}, "codex": {"answer": 9}}},
    )
    assert counts == {"native_resident": 1, "daemon_other": 0, "resident_direct": 3}
    assert assert_bridge_routes(counts, 4) == counts

    with pytest.raises(ProbeError, match="exactly once"):
        assert_bridge_routes(counts, 5)
    python_route = bridge_route_counts({"routes": {"native_resident": 1, "python_semantic": 1}}, {"resident": {}})
    with pytest.raises(ProbeError, match="exactly once"):
        assert_bridge_routes(python_route, 2)
    with pytest.raises(ProbeError, match="invalid route counts"):
        bridge_route_counts({"routes": {"native_resident": True}}, {})


def test_bridge_route_wait_reads_the_installed_daemon_counters() -> None:
    snapshots = iter([{"resident": {}}, {"resident": {"omp": {"answer": 2}}}])
    worker = SimpleNamespace(
        metrics=SimpleNamespace(snapshot=lambda: {"routes": {"native_resident": 1}}),
        hook_counters=SimpleNamespace(snapshot=lambda: next(snapshots, {"resident": {"omp": {"answer": 2}}})),
    )
    daemon = SimpleNamespace(_server=SimpleNamespace(hook_worker=worker))
    assert wait_for_bridge_native_routes(daemon, 3)["resident_direct"] == 2

    with pytest.raises(ProbeError, match="timed out"):
        wait_for_bridge_native_routes(daemon, 4, timeout_seconds=0.05)
    with pytest.raises(ProbeError, match="did not expose"):
        wait_for_bridge_native_routes(SimpleNamespace(), 1)


def test_unavailable_service_fails_closed_and_only_recovers_the_daemon() -> None:
    cases = probe._negative_cases()
    results = [
        {"id": case["id"], "preserved": False, "result": {"isError": True}, "input_content_unchanged": True}
        for case in cases
    ]
    recoveries = {str(case["id"]): [{"case_id": "unknown", "invocation_kind": "recovery"}] for case in cases}

    evidence = assert_unavailable_results(results, recoveries, cases)
    assert all(case_evidence["is_error"] for case_evidence in evidence.values())

    reviewed = deepcopy(recoveries)
    reviewed["negative-observe"] = [{"case_id": "negative-observe", "invocation_kind": "hook"}]
    with pytest.raises(ProbeError, match="CLI review"):
        assert_unavailable_results(results, reviewed, cases)
    # Two recoveries for one case must not stand in for a case that never recovered.
    shifted = deepcopy(recoveries)
    shifted["negative-empty"] *= 2
    del shifted["negative-observe"]
    with pytest.raises(ProbeError, match="recovery once for negative-empty"):
        assert_unavailable_results(results, shifted, cases)
    with pytest.raises(ProbeError, match="unexpected unavailable-service case"):
        assert_unavailable_results(results, {**recoveries, "unknown": recoveries["negative-empty"]}, cases)
    preserved = deepcopy(results)
    preserved[0]["preserved"] = True
    with pytest.raises(ProbeError, match="silently preserved"):
        assert_unavailable_results(preserved, recoveries, cases)
    unblocked = deepcopy(results)
    unblocked[1]["result"] = None
    with pytest.raises(ProbeError, match="visibly block"):
        assert_unavailable_results(unblocked, recoveries, cases)
    with pytest.raises(ProbeError, match="duplicate"):
        assert_unavailable_results([results[0]] * len(cases), recoveries, cases)


def test_capture_records_read_only_what_a_run_appended(tmp_path: Path) -> None:
    log = tmp_path / "cli.jsonl"
    assert capture_log_size(log) == 0
    log.write_text(json.dumps({"case_id": "unknown", "invocation_kind": "recovery"}) + "\n", encoding="utf-8")
    offset = capture_log_size(log)
    with log.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"case_id": "negative-empty", "invocation_kind": "hook"}) + "\n")

    assert [record["case_id"] for record in read_capture_records(log)] == ["unknown", "negative-empty"]
    assert read_capture_records(log, offset) == [{"case_id": "negative-empty", "invocation_kind": "hook"}]
    with pytest.raises(ProbeError, match="capture log"):
        read_capture_records(tmp_path / "missing.jsonl")


@pytest.mark.skipif(sys.platform == "win32" or shutil.which("node") is None, reason="POSIX Node bridge capture")
def test_node_runner_records_each_spawned_bridge_reply(tmp_path: Path) -> None:
    home, guard_home, workspace = tmp_path / "home", tmp_path / "guard-home", tmp_path / "workspace"
    for directory in (home, guard_home, workspace):
        directory.mkdir()
    extension = tmp_path / "extension.ts"
    probe._generate_extension(extension, guard_home=guard_home, home=home, settings_path=tmp_path / "s.json")
    case = probe._cases()[0]
    body = {**_bridge_request(case), "token": "never-copied"}
    for key in ("case_id", "transport", "harness", "exit_code", "status"):
        body.pop(key)
    runtime = tmp_path / "fake-runtime"
    reply = json.dumps({"status": 200, "body": json.dumps(body)})
    runtime.write_text(f"#!/bin/sh\ncat >/dev/null\nprintf '%s\\n' '{reply}'\n", encoding="utf-8")
    runtime.chmod(0o755)
    source = extension.read_text(encoding="utf-8")
    fetch_lane = "const GUARD_NATIVE_HOOK_RUNTIME: string | null = null;"
    assert fetch_lane in source
    extension.write_text(
        source.replace(fetch_lane, f"const GUARD_NATIVE_HOOK_RUNTIME: string | null = {json.dumps(str(runtime))};"),
        encoding="utf-8",
    )
    runner = tmp_path / "run-extension.mjs"
    probe._write_node_runner(runner)
    cases_path = tmp_path / "cases.json"
    cases_path.write_text(json.dumps([case]), encoding="utf-8")

    results, requests = probe._run_node_cases(
        node=probe._node_command(),
        extension=extension,
        runner=runner,
        cases=cases_path,
        cwd=workspace,
        env=probe._isolated_env(home=home, python_path=Path(sys.executable)),
    )

    transport = generated_transport(extension.read_text(encoding="utf-8"))
    assert transport == BRIDGE
    assert requests == [_bridge_request(case)]
    assert assert_guard_requests(requests, results, [case], transport=transport)[str(case["id"])]["preserved"]
