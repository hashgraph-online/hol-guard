"""Independent process counterexamples for the diagnostic-only observer.

Every observer runs in its own interpreter. Tests never install a persistent
audit/profile hook into pytest or substitute a baseline runtime function.
"""

from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from scripts.ci.installed_transition_observer_receipt import collect
from scripts.ci.verify_installed_artifact_transitions import public_transition_report
from scripts.native_slo_contract import MAX_EVIDENCE_BYTES, assert_privacy_safe

_ROOT = Path(__file__).resolve().parents[1]
_DRIVER = """\
from __future__ import annotations

import atexit
import json
import os
import subprocess
import sys
import threading
from multiprocessing import process as multiprocessing_process
from pathlib import Path

sys.path.insert(0, ROOT)

def native_resident_client_request():
    return "safe-test-native-entry"

def _send_review_to_slot():
    return "safe-test-review-entry"

def retire_worker_slot():
    if sys.argv[3] == "cleanup_true":
        return True
    return False if sys.argv[3] == "cleanup_false" else 1

def run_isolated_hook_process(command):
    from types import SimpleNamespace
    return SimpleNamespace(
        returncode=0,
        timed_out=False,
        containment_failed=False,
        output_limit_exceeded=False,
    )

_native_alias = native_resident_client_request
_native_before = native_resident_client_request
_review_before = _send_review_to_slot
_popen_before = subprocess.Popen
_start_before = multiprocessing_process.BaseProcess.start

_existing_thread = None
_existing_thread_release = None
_existing_profile_proof = {}
_custom_profile_calls = 0
if __name__ == "__main__" and sys.argv[3] in {"existing_thread", "existing_profile"}:
    _existing_thread_release = threading.Event()
    _existing_thread_ready = threading.Event()
    def existing_custom_profile(frame, event, value):
        global _custom_profile_calls
        if event == "call" and frame.f_code is _native_alias.__code__:
            _custom_profile_calls += 1
    def existing_thread_work():
        if sys.argv[3] == "existing_profile":
            sys.setprofile(existing_custom_profile)
        _existing_thread_ready.set()
        if _existing_thread_release.wait(timeout=15):
            before_calls = _custom_profile_calls
            _existing_profile_proof["profile_preserved"] = sys.getprofile() is existing_custom_profile
            _native_alias()
            _existing_profile_proof["calls_after_bootstrap"] = _custom_profile_calls - before_calls
    _existing_thread = threading.Thread(target=existing_thread_work, daemon=True)
    _existing_thread.start()
    if not _existing_thread_ready.wait(timeout=5):
        raise RuntimeError("test profile was not installed before bootstrap")

if sys.argv[3] == "after_seal":
    atexit.register(_native_alias)

from scripts.ci.installed_transition_observer import bootstrap

bootstrap(
    __name__,
    argv=["--phase", sys.argv[2], "--fixture-root", sys.argv[1]]
    if __name__ == "__main__" else None,
)

assert native_resident_client_request is _native_before
assert _send_review_to_slot is _review_before
assert subprocess.Popen is _popen_before
assert multiprocessing_process.BaseProcess.start is _start_before

def child_ready(connection, linger, native_entry):
    import time
    if native_entry:
        _native_alias()
    connection.send(os.getpid())
    connection.close()
    if linger:
        time.sleep(30)

def main():
    case = sys.argv[3]
    result = {"pid": os.getpid(), "case": case}
    if case == "native_alias":
        result["native_result"] = _native_alias()
    elif case == "review_send":
        result["review_result"] = _send_review_to_slot()
    elif case in {"cleanup_false", "cleanup_nonboolean", "cleanup_true"}:
        result["cleanup_result"] = retire_worker_slot()
    elif case == "before_exit":
        atexit.register(_native_alias)
    elif case == "bounded_result":
        result["probe_return_code"] = run_isolated_hook_process([sys.executable, "capabilities"]).returncode
    elif case in {"existing_thread", "existing_profile"}:
        _existing_thread_release.set()
        _existing_thread.join(timeout=5)
        if _existing_thread.is_alive():
            raise RuntimeError("test thread did not stop")
        result.update(_existing_profile_proof)
    elif case == "spawnv_before_slot":
        if os.name == "nt":
            raise RuntimeError("POSIX-only test case")
        from multiprocessing import util
        pid = None
        try:
            pid = util.spawnv_passfds(
                os.fsencode(sys.executable),
                [sys.executable, "-I", "-c", "pass"],
                [],
            )
            raise RuntimeError("test failure before registering any worker slot")
        except RuntimeError as error:
            result["raised_after_create"] = str(error)
        finally:
            if pid is not None:
                result["child_pid"] = pid
                _, status = os.waitpid(pid, 0)
                result["child_exit"] = os.waitstatus_to_exitcode(status)
    elif case in {"spawn", "kill_child", "child_native"}:
        import multiprocessing
        context = multiprocessing.get_context("spawn")
        reader, writer = context.Pipe(duplex=False)
        child = context.Process(target=child_ready, args=(writer, case == "kill_child", case == "child_native"))
        try:
            child.start()
            writer.close()
            if not reader.poll(10):
                raise RuntimeError("test child did not complete entry replay")
            result["child_pid"] = reader.recv()
            if case == "kill_child":
                child.kill()
            child.join(timeout=5)
            if child.is_alive():
                raise RuntimeError("test child did not exit")
            result["child_exit"] = child.exitcode
        finally:
            writer.close()
            reader.close()
            if child.is_alive():
                child.kill()
                child.join(timeout=5)
    print(json.dumps(result, sort_keys=True), flush=True)

if __name__ == "__main__":
    main()
"""


def _run(tmp_path: Path, case: str = "empty", *, phase: str = "baseline_rollback") -> tuple[dict, dict, Path]:
    fixture = tmp_path / "fixture"
    fixture.mkdir(mode=0o700)
    driver = tmp_path / "observer_driver.py"
    driver.write_text(_DRIVER.replace("ROOT", repr(str(_ROOT)), 1), encoding="utf-8")
    completed = subprocess.run(
        [sys.executable, "-I", str(driver), str(fixture), phase, case],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=25,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    report = collect(fixture)
    assert report["diagnostic_only"] is True
    assert report["proof_verified"] is False
    return report, result, fixture


def _process(report: dict, pid: int) -> dict:
    matches = [process for process in report["processes"] if process.get("pid") == pid]
    assert len(matches) == 1, report
    return matches[0]


def test_observer_does_not_treat_an_empty_diagnostic_as_retirement_proof(tmp_path):
    report, result, _ = _run(tmp_path)
    assert report["counts"]["native_client_entries"] == 0
    assert report["counts"]["review_send_entries"] == 0
    assert _process(report, result["pid"])["sealed"] is True


@pytest.mark.parametrize(
    ("case", "counter", "result_key", "result_value"),
    [
        ("native_alias", "native_client_entries", "native_result", "safe-test-native-entry"),
        ("review_send", "review_send_entries", "review_result", "safe-test-review-entry"),
    ],
)
def test_observer_counts_entries_without_replacing_the_called_function(
    tmp_path, case, counter, result_key, result_value
):
    report, result, _ = _run(tmp_path, case)
    assert result[result_key] == result_value
    assert report["counts"][counter] == 1
    assert report["incomplete"], "An unknown test source cannot supply a qualified witness."


def test_spawn_child_replays_entry_and_has_its_own_observation(tmp_path):
    report, result, _ = _run(tmp_path, "spawn")
    assert result["child_exit"] == 0
    assert report["counts"]["process_launch_attempts"] >= 1
    assert _process(report, result["child_pid"])["sealed"] is True
    assert _process(report, result["pid"])["sealed"] is True


def test_spawned_interpreter_native_entry_is_not_hidden_by_outer_zero_count(tmp_path):
    report, result, _ = _run(tmp_path, "child_native")
    assert result["child_exit"] == 0
    assert report["counts"]["native_client_entries"] == 1
    assert _process(report, result["child_pid"])["sealed"] is True


def test_existing_thread_gets_profile_coverage_without_function_replacement(tmp_path):
    if not hasattr(threading, "setprofile_all_threads"):
        pytest.skip("Python 3.12 adds profile installation in existing Python threads.")
    report, _, _ = _run(tmp_path, "existing_thread")
    assert report["counts"]["native_client_entries"] == 1


def test_existing_thread_keeps_its_own_profile_callback_and_observes_application_calls(tmp_path):
    report, result, _ = _run(tmp_path, "existing_profile")
    assert result["profile_preserved"] is True
    assert result["calls_after_bootstrap"] == 1
    assert report["counts"]["native_client_entries"] == 1


def test_killed_child_exit_cannot_substitute_for_its_missing_seal(tmp_path):
    report, result, _ = _run(tmp_path, "kill_child")
    assert result["child_exit"] != 0
    assert _process(report, result["child_pid"])["sealed"] is False
    assert report["incomplete"]


@pytest.mark.skipif(os.name == "nt", reason="CPython POSIX multiprocessing uses spawnv_passfds.")
def test_low_level_spawn_remains_recorded_when_no_worker_slot_is_registered(tmp_path):
    report, result, _ = _run(tmp_path, "spawnv_before_slot")
    assert result["child_exit"] == 0
    assert result["raised_after_create"] == "test failure before registering any worker slot"
    assert report["counts"]["process_launch_attempts"] >= 1
    assert _process(report, result["child_pid"])["sealed"] is False
    assert report["incomplete"]


def test_native_activity_in_atexit_is_still_observed(tmp_path):
    report, _, _ = _run(tmp_path, "before_exit")
    assert report["counts"]["native_client_entries"] == 1
    assert report["incomplete"]


def test_native_activity_after_an_early_seal_invalidates_completeness(tmp_path):
    report, _, _ = _run(tmp_path, "after_seal")
    assert report["counts"]["native_client_entries"] == 1
    assert any("seal" in reason or "late" in reason for reason in report["incomplete"]), report


def test_truncated_process_observation_is_retained_as_incomplete(tmp_path):
    _, _, fixture = _run(tmp_path)
    receipts = sorted((fixture.parent / "producer-observation").glob("*.jsonl"))
    assert receipts
    with receipts[0].open("ab") as stream:
        stream.write(b'{"unfinished_record":')
    report = collect(fixture)
    assert report["diagnostic_only"] is True
    assert report["proof_verified"] is False
    assert report["incomplete"]


def test_observer_is_disabled_outside_exact_legacy_phase(tmp_path):
    report, _, fixture = _run(tmp_path, "native_alias", phase="candidate_restore")
    assert report["counts"]["native_client_entries"] == 0
    assert not list((fixture.parent / "producer-observation").glob("*.jsonl"))
    assert report["incomplete"]


@pytest.mark.parametrize("case", ["cleanup_false", "cleanup_nonboolean"])
def test_unsuccessful_cleanup_result_is_retained_and_marks_diagnostic_incomplete(tmp_path, case):
    report, _, _ = _run(tmp_path, case)
    returned = [
        event
        for event in report["events"]
        if event["event"] == "call_returned" and event.get("function") == "retire_worker_slot"
    ]
    assert len(returned) == 1
    assert returned[0]["contained"] is (False if case == "cleanup_false" else None)
    assert any("cleanup" in reason or "containment" in reason for reason in report["incomplete"]), report


@pytest.mark.parametrize(
    "mutation",
    [
        "duplicate_sequence",
        "boolean_pid",
        "unknown_event",
        "nonlist_seal_errors",
        "missing_run_identity",
        "unmatched_call",
        "return_without_start",
        "unattributed_launch",
        "duplicate_pid_ledger",
    ],
)
def test_collector_detects_malformed_evidence_independently_of_source_attestation(tmp_path, mutation):
    before, result, fixture = _run(tmp_path, "cleanup_true")
    directory = fixture.parent / "producer-observation"
    receipt = directory / f"{result['pid']}.jsonl"
    records = [json.loads(line) for line in receipt.read_text().splitlines()]
    if mutation == "duplicate_sequence":
        records[1]["sequence"] = records[0]["sequence"]
    elif mutation == "boolean_pid":
        records[0]["pid"] = True
    elif mutation == "unknown_event":
        records[1]["event"] = "not_a_known_observation"
    elif mutation == "nonlist_seal_errors":
        records[-1]["incomplete"] = False
    elif mutation == "missing_run_identity":
        del records[0]["run_id"]
    elif mutation in {"unmatched_call", "return_without_start"}:
        removed = "call_returned" if mutation == "unmatched_call" else "call_started"
        records = [record for record in records if record["event"] != removed]
        for sequence, record in enumerate(records, 1):
            record["sequence"] = sequence
    elif mutation == "unattributed_launch":
        event = {
            "event": "process_launch_attempt",
            "pid": result["pid"],
            "thread_id": records[-1]["thread_id"],
            "at_ns": records[-1]["at_ns"] - 1,
            "launch_api": "fork_exec",
        }
        records.insert(-1, event)
        for sequence, record in enumerate(records, 1):
            record["sequence"] = sequence
    elif mutation == "duplicate_pid_ledger":
        duplicate = directory / f"000{result['pid']}.jsonl"
        duplicate.write_bytes(receipt.read_bytes())
        duplicate.chmod(0o600)
    receipt.write_text("".join(json.dumps(record, sort_keys=True) + "\n" for record in records))
    after = collect(fixture)
    assert after["diagnostic_only"] is True
    assert after["proof_verified"] is False
    assert set(after["incomplete"]) - set(before["incomplete"]), (mutation, after)


def test_public_phase_projection_preserves_error_facts_and_bounded_process_flags(tmp_path):
    _, result, fixture = _run(tmp_path, "bounded_result")
    assert result["probe_return_code"] == 0
    receipt = fixture.parent / "producer-observation" / f"{result['pid']}.jsonl"
    records = [json.loads(line) for line in receipt.read_text().splitlines()]
    assert records[-1]["event"] == "sealed"
    records[-1]["incomplete"].append("synthetic_cleanup_gap")
    receipt.write_text("".join(json.dumps(record, sort_keys=True) + "\n" for record in records))
    report = collect(fixture)
    public = assert_privacy_safe({"phases": [{"producer_observation": report}]})["phases"][0]["producer_observation"]
    assert public == report
    assert public["diagnostic_only"] is True
    assert public["proof_verified"] is False
    assert public["bootstrap_attestation_qualified"] is False
    errors = [event for event in public["events"] if event["event"] == "observer_error"]
    assert any("synthetic_cleanup_gap" in event.values() for event in errors)
    returned = [
        event
        for event in public["events"]
        if event["event"] == "call_returned" and event.get("function") == "run_isolated_hook_process"
    ]
    assert len(returned) == 1
    assert returned[0]["return_code"] == 0
    assert returned[0]["timed_out"] is False
    assert returned[0]["containment_failed"] is False
    assert returned[0]["limit_exceeded"] is False
    assert returned[0]["nonspawning_attested"] is False


def _aggregate(headroom: int | None = None) -> dict:
    report = {
        "passed": False,
        "phases": [
            {
                "phase": "baseline_rollback",
                "passed": False,
                "verified_legacy_rejection": False,
                "worker": {"retirement_verification": {"verified": False, "return_code": 2}},
            }
        ],
        "suite_acceptance": {"passed": False},
    }
    if headroom is None:
        return report

    def padded(character_count):
        chunks = ["x" * min(96, character_count - offset) for offset in range(0, character_count, 96)]
        return report | {"padding": [chunks[offset : offset + 256] for offset in range(0, len(chunks), 256)]}

    low, high = 0, MAX_EVIDENCE_BYTES
    while low < high:
        middle = (low + high + 1) // 2
        size = len(json.dumps(padded(middle), separators=(",", ":"), sort_keys=True).encode())
        if size <= MAX_EVIDENCE_BYTES - headroom:
            low = middle
        else:
            high = middle - 1
    result = padded(low)
    assert assert_privacy_safe(result) == result
    return result


def test_public_projection_retains_diagnostics_when_original_aggregate_has_room(tmp_path):
    observation, _, _ = _run(tmp_path)
    report = _aggregate()
    report["phases"][0]["producer_observation"] = observation
    before = copy.deepcopy(report)
    public = public_transition_report(report)
    assert public == assert_privacy_safe(before)
    assert public["phases"][0]["producer_observation"] == observation
    assert report == before


def test_public_projection_preserves_exact_original_when_diagnostics_exceed_remaining_budget(tmp_path):
    observation, _, _ = _run(tmp_path)
    original = _aggregate(headroom=128)
    original_size = len(json.dumps(original, separators=(",", ":"), sort_keys=True).encode())
    assert MAX_EVIDENCE_BYTES - 512 < original_size < MAX_EVIDENCE_BYTES
    combined = copy.deepcopy(original)
    combined["phases"][0]["producer_observation"] = observation
    before = copy.deepcopy(combined)
    with pytest.raises(ValueError, match="aggregate size bound"):
        assert_privacy_safe(combined)
    public = public_transition_report(combined)
    assert public == original
    assert combined == before


def test_public_projection_does_not_rescue_an_already_invalid_original_aggregate():
    original = _aggregate(headroom=128)
    original["overflow"] = ["z" * 96] * 256
    original["phases"][0]["producer_observation"] = {"diagnostic_only": True, "proof_verified": False}
    before = copy.deepcopy(original)
    with pytest.raises(ValueError, match="aggregate size bound"):
        public_transition_report(original)
    assert original == before
