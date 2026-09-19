"""Exercise the actual non-breakaway Windows Job descendant boundary."""

from __future__ import annotations

import json
import runpy
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows Job Object kernel boundary")
_ROOT = Path(__file__).resolve().parents[1]
_MEMBERSHIP = _ROOT / "tests/test_installed_transition_windows_membership_support.py"
_SUPERVISOR = """
import json, os, sys, time
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from scripts.ci.installed_transition_owner import run_owned
from scripts.ci import installed_transition_windows_owner as owner
options = json.loads(sys.argv[3])
membership = options.pop('membership_witness', None)
finish_membership = None
if membership:
    import runpy
    helper = runpy.run_path(str(Path(sys.argv[1]) / 'tests/test_installed_transition_windows_membership_support.py'))
    finish_membership = helper['install'](owner, membership)
pause = options.pop('pause_after_empty', 0)
if pause:
    original_accounting = owner._accounting
    delayed = False
    def accounting(*args):
        global delayed
        value = original_accounting(*args)
        if value['total'] and value['active'] == 0 and not delayed:
            delayed = True
            time.sleep(pause)
        return value
    owner._accounting = accounting
if options.pop('reject_assignment', False):
    api = owner._job_api()
    def reject(*args):
        raise OSError('injected assignment failure before resume')
    api._assign_and_resume = reject
result = run_owned((sys.executable, '-I', '-c', sys.argv[2]),
                   cwd=Path.cwd(), environment=dict(os.environ), **options)
print(json.dumps({'stdout': result.stdout.decode(), 'stderr': result.stderr.decode(),
                  'returncode': result.returncode, 'evidence': result.evidence,
                  'membership': finish_membership() if finish_membership else None}))
"""


def _run(code: str, **options) -> dict:
    result = subprocess.run(
        [sys.executable, "-I", "-c", _SUPERVISOR, str(_ROOT), textwrap.dedent(code), json.dumps(options)],
        capture_output=True,
        text=True,
        timeout=15,
        check=True,
    )
    return json.loads(result.stdout)


@pytest.mark.parametrize("exit_code", [0, 1, 7])
def test_original_worker_exit_and_output_survive_job_observation(exit_code):
    result = _run(f"print('original failure', flush=True); raise SystemExit({exit_code})")
    assert result["stdout"] == "original failure\r\n"
    assert result["returncode"] == exit_code
    evidence = result["evidence"]
    assert evidence["verified"] is True
    assert evidence["worker_return_code"] == exit_code
    # A Windows venv redirector can add its base interpreter to the same Job.
    assert evidence["total_process_count"] >= 1
    assert evidence["job_empty_before_close"] is True
    assert evidence["termination_requests"] == 0
    assert evidence["breakaway_disabled"] is True


def test_child_in_another_process_group_cannot_escape_after_worker_exit():
    result = _run("""
        import subprocess, sys
        subprocess.Popen([sys.executable, '-I', '-c',
            "import time; time.sleep(0.2); print('child finished', flush=True)"],
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
        print('original failure', flush=True)
        raise SystemExit(1)
    """)
    assert result["returncode"] == 1
    assert "original failure" in result["stdout"]
    assert "child finished" in result["stdout"]
    assert result["evidence"]["verified"] is True
    assert result["evidence"]["total_process_count"] >= 2
    assert result["evidence"]["job_empty_before_close"] is True
    assert result["evidence"]["termination_requests"] == 0


def test_descendant_can_spawn_again_after_original_worker_exit():
    grandchild = "import time; time.sleep(0.2); print('late grandchild finished', flush=True)"
    child = (
        "import subprocess,sys,time; time.sleep(0.2); "
        f"subprocess.Popen([sys.executable, '-I', '-c', {grandchild!r}], "
        "creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)"
    )
    result = _run(
        f"import subprocess,sys; subprocess.Popen([sys.executable, '-I', '-c', {child!r}], "
        "creationflags=subprocess.CREATE_NEW_PROCESS_GROUP); raise SystemExit(1)"
    )
    assert result["returncode"] == 1
    assert result["stdout"] == "late grandchild finished\r\n"
    assert result["evidence"]["verified"] is True
    assert result["evidence"]["total_process_count"] >= 3
    assert result["evidence"]["termination_requests"] == 0


def test_surviving_child_requires_failed_cleanup_even_after_output_eof():
    result = _run(
        """
        import subprocess, sys
        subprocess.Popen([sys.executable, '-I', '-c', 'import time; time.sleep(60)'],
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print('original failure', flush=True)
        raise SystemExit(1)
        """,
        drain_seconds=0.1,
    )
    assert result["returncode"] == 1
    assert result["stdout"] == "original failure\r\n"
    evidence = result["evidence"]
    assert evidence["verified"] is False
    assert evidence["timed_out"] is True
    assert evidence["termination_requests"] == 1
    assert evidence["descendants_exhausted"] is True
    assert evidence["job_empty_before_close"] is True
    assert evidence["containment_failed"] is False


def test_job_breakaway_request_cannot_escape_retained_owner(tmp_path):
    witness = str(tmp_path / "child-identity.json")
    child = runpy.run_path(str(_MEMBERSHIP))["CHILD"]
    result = _run(
        f"""
        import subprocess, sys
        try:
            subprocess.Popen([sys.executable, '-I', '-c', {child!r}, {witness!r}],
                creationflags=subprocess.CREATE_BREAKAWAY_FROM_JOB)
        except OSError as error:
            assert error.winerror == 5
            print('breakaway denied', flush=True)
        raise SystemExit(1)
    """,
        membership_witness=witness,
    )
    # A nested Job can permit creation while breakaway stops at our retained
    # non-breakaway ancestor. Creation success alone is not an escape witness.
    # https://learn.microsoft.com/en-us/windows/win32/procthread/nested-jobs
    if result["stdout"] == "breakaway denied\r\n":
        assert result["membership"] == {}
    else:
        assert result["stdout"] == "retained child finished\r\n", result
        membership = result["membership"]
        assert membership["birth_matches"] is True, result
        assert membership["alive_during_query"] is True, result
        assert membership["in_retained_job"] is True, result
        assert membership["active_at_query"] >= 1, result
        assert membership["child_exit_observed"] is True, result
        assert "query_failure" not in membership, result
        assert result["evidence"]["total_process_count"] >= 2, result
    assert result["stderr"] == "", result
    assert result["returncode"] == 1
    assert result["evidence"]["verified"] is True
    assert result["evidence"]["total_process_count"] >= 1
    assert result["evidence"]["job_empty_before_close"] is True
    assert result["evidence"]["termination_requests"] == 0


def test_late_empty_observation_never_earns_a_deadline_certificate():
    result = _run(
        "print('original failure', flush=True); raise SystemExit(1)",
        timeout_seconds=0.5,
        drain_seconds=0.1,
        pause_after_empty=0.6,
    )
    assert result["stdout"] == "original failure\r\n"
    assert result["returncode"] == 1
    assert result["evidence"]["job_empty_before_close"] is True
    assert result["evidence"]["timed_out"] is True
    assert result["evidence"]["verified"] is False


def test_output_limit_keeps_only_the_original_bounded_prefix():
    result = _run("print('x' * 10000, flush=True)", output_limit=128)
    assert result["stdout"] == "x" * 128
    assert result["evidence"]["limit_exceeded"] is True
    assert result["evidence"]["verified"] is False


def test_failed_assignment_never_runs_the_suspended_worker(tmp_path):
    marker = tmp_path / "must-not-exist"
    result = _run(
        f"from pathlib import Path; Path({str(marker)!r}).write_text('executed')",
        reject_assignment=True,
    )
    assert not marker.exists()
    assert result["stdout"] == ""
    assert result["evidence"]["containment_failed"] is True
    assert result["evidence"]["verified"] is False
