"""Exercise real Linux descendant adoption, normal exhaustion, and failed cleanup."""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux kernel child-subreaper boundary")
_ROOT = Path(__file__).resolve().parents[1]
_SUPERVISOR = """
import json, os, sys, time
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from scripts.ci.installed_transition_owner import run_owned
options = json.loads(sys.argv[3])
pause = options.pop('pause_after_output', 0)
if pause:
    original_read, original_waitpid = os.read, os.waitpid
    seen, delayed = False, False
    def read(*args):
        global seen
        value = original_read(*args)
        if value == b'prefix\\n':
            seen = True
        return value
    def waitpid(*args):
        global delayed
        if seen and not delayed:
            delayed = True
            time.sleep(pause)
        return original_waitpid(*args)
    os.read, os.waitpid = read, waitpid
result = run_owned((sys.executable, '-I', '-c', sys.argv[2]),
                   cwd=Path.cwd(), environment=dict(os.environ), **options)
print(json.dumps({'stdout': result.stdout.decode(), 'stderr': result.stderr.decode(),
                  'returncode': result.returncode, 'evidence': result.evidence}))
"""


def _run(code: str, **options) -> dict:
    result = subprocess.run(
        [sys.executable, "-I", "-c", _SUPERVISOR, str(_ROOT), textwrap.dedent(code), json.dumps(options)],
        capture_output=True,
        text=True,
        timeout=12,
        check=True,
    )
    return json.loads(result.stdout)


@pytest.mark.parametrize("exit_code", [0, 1, 7])
def test_normal_exit_is_observed_without_reinterpreting_worker_failure(exit_code):
    result = _run(f"print('original prefix', flush=True); raise SystemExit({exit_code})")
    assert result["stdout"] == "original prefix\n"
    assert result["returncode"] == exit_code
    assert result["evidence"]["verified"] is True
    assert result["evidence"]["termination_signals_sent"] == 0
    assert result["evidence"]["worker_return_code"] == exit_code
    assert result["evidence"]["reaped_process_count"] == 1


def test_detached_double_fork_is_owned_after_original_worker_exits():
    result = _run("""
        import os, time
        if os.fork() == 0:
            os.setsid()
            if os.fork() != 0:
                os._exit(0)
            time.sleep(0.15)
            print('detached child finished', flush=True)
            os._exit(0)
        print('original failed start', flush=True)
        os._exit(1)
    """)
    assert "original failed start" in result["stdout"]
    assert "detached child finished" in result["stdout"]
    assert result["returncode"] == 1
    assert result["evidence"]["verified"] is True
    assert result["evidence"]["descendants_exhausted"] is True
    assert result["evidence"]["reaped_process_count"] == 3


def test_child_can_spawn_again_after_worker_exit_without_escaping_owner():
    result = _run("""
        import os, time
        if os.fork() == 0:
            os.setsid()
            time.sleep(0.1)
            if os.fork() == 0:
                os.close(1)
                os.close(2)
                time.sleep(0.1)
            os._exit(0)
        os._exit(1)
    """)
    assert result["returncode"] == 1
    assert result["evidence"]["verified"] is True
    assert result["evidence"]["reaped_process_count"] == 3


def test_surviving_detached_child_requires_failed_cleanup_even_after_pipe_eof():
    result = _run(
        """
        import os, time
        if os.fork() == 0:
            os.setsid()
            os.close(1)
            os.close(2)
            time.sleep(60)
            os._exit(0)
        print('original failed start', flush=True)
        os._exit(1)
        """,
        drain_seconds=0.05,
    )
    assert result["returncode"] == 1
    assert result["stdout"] == "original failed start\n"
    assert result["evidence"]["verified"] is False
    assert result["evidence"]["timed_out"] is True
    assert result["evidence"]["termination_signals_sent"] >= 1
    assert result["evidence"]["descendants_exhausted"] is True
    assert result["evidence"]["containment_failed"] is False


def test_signal_death_is_never_normal_worker_completion():
    result = _run("import os, signal; print('prefix', flush=True); os.kill(os.getpid(), signal.SIGTERM)")
    assert result["stdout"] == "prefix\n"
    assert result["returncode"] == -15
    assert result["evidence"]["verified"] is False


def test_deadline_still_applies_when_scheduler_resumes_after_exit_and_eof():
    result = _run(
        "import time; print('prefix', flush=True); time.sleep(0.08); raise SystemExit(1)",
        timeout_seconds=0.05,
        drain_seconds=0.03,
        pause_after_output=0.15,
    )
    assert result["stdout"] == "prefix\n"
    assert result["returncode"] == 1
    assert result["evidence"]["descendants_exhausted"] is True
    assert result["evidence"]["termination_signals_sent"] == 0
    assert result["evidence"]["timed_out"] is True
    assert result["evidence"]["verified"] is False


def test_output_limit_retains_only_the_bounded_failed_prefix():
    result = _run("print('x' * 10000, flush=True)", output_limit=128)
    assert len(result["stdout"]) == 128
    assert result["evidence"]["verified"] is False
    assert result["evidence"]["limit_exceeded"] is True


def test_supervisor_refuses_preexisting_children():
    code = """
import os, sys, time
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from scripts.ci.installed_transition_owner import run_owned
pid = os.fork()
if pid == 0:
    time.sleep(0.05)
    os._exit(0)
try:
    run_owned((sys.executable, '-c', 'pass'), cwd=Path.cwd(), environment=dict(os.environ))
except RuntimeError as error:
    assert str(error) == 'transition_owner_initial_boundary_invalid'
else:
    raise AssertionError('existing children were adopted as worker proof')
finally:
    os.waitpid(pid, 0)
"""
    subprocess.run([sys.executable, "-I", "-c", code, str(_ROOT)], check=True, timeout=5)
