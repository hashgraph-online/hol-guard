from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
from pathlib import Path

import pytest

from tests import guard_command_corpus_diagnostics as diagnostic
from tests import guard_command_corpus_runner as runner


def _facts(error: Exception, stage: str = "worker_process", index: int | None = 2) -> dict[str, object]:
    text = diagnostic._failure_text(error, stage, index)
    assert "private-canary" not in text
    result = diagnostic._decode_facts(text)
    assert result is not None
    return result


@pytest.mark.parametrize("returncode", [1, 7, -9, 3221225477])
def test_nonzero_exit_preserves_numeric_code_without_inventing_timeout(returncode):
    error = subprocess.CalledProcessError(
        returncode, "private-canary-command", "private-canary-output", "private-canary-error"
    )
    facts = _facts(error)
    assert facts["reason"] == "nonzero_exit"
    assert facts["returncode"] == returncode
    assert facts["worker_index"] == 2


@pytest.mark.parametrize(
    "error,reason,exception,errno",
    [
        (
            subprocess.TimeoutExpired("private-canary", 60, b"private-canary", b"private-canary"),
            "timeout",
            "TimeoutExpired",
            None,
        ),
        (PermissionError(1, "private-canary", "private-canary"), "os_error", "PermissionError", 1),
        (FileNotFoundError(2, "private-canary", "private-canary"), "os_error", "FileNotFoundError", 2),
        (MemoryError("private-canary"), "exception", "MemoryError", None),
    ],
)
def test_known_failures_have_exact_finite_categories(error, reason, exception, errno):
    facts = _facts(error)
    assert (facts["reason"], facts["exception"], facts["errno"]) == (reason, exception, errno)


def test_unknown_exception_subclass_has_no_string_or_attribute_callbacks():
    class Hostile(subprocess.CalledProcessError):
        def __str__(self):
            pytest.fail("Unknown exception was rendered")

        def __getattribute__(self, name):
            if name in {"returncode", "stderr"}:
                pytest.fail("Unknown exception field was read")
            return super().__getattribute__(name)

    facts = _facts(Hostile(1, "private-canary"))
    assert facts["exception"] == "other" and facts["returncode"] is None


@pytest.mark.parametrize("value", [True, 2**64, "private-canary", object()])
def test_invalid_numeric_fields_are_not_coerced(value):
    error = subprocess.CalledProcessError(value, "private-canary")
    assert _facts(error)["returncode"] is None


def test_finite_nested_worker_cause_and_both_physical_exit_codes_survive():
    worker = diagnostic._failure_text(MemoryError("private-canary"), "worker_evaluation", 2)
    process = diagnostic._failure_text(
        subprocess.CalledProcessError(-9, "private-canary", stderr=worker), "worker_process", 2
    )
    facts = _facts(subprocess.CalledProcessError(1, "private-canary", stderr=process), "coordinator_process", None)
    assert facts["stage"] == "worker_process"
    assert facts["returncode"] == -9 and facts["coordinator_returncode"] == 1
    assert facts["worker_reason"] == "exception" and facts["worker_exception"] == "MemoryError"


@pytest.mark.parametrize("field", sorted(diagnostic._KEYS))
def test_nested_report_rejects_sensitive_or_invalid_fields(field):
    event = _facts(RuntimeError("private-canary"))
    event[field] = "private-canary"
    text = diagnostic._PREFIX + json.dumps(event)
    facts = _facts(subprocess.CalledProcessError(1, "private-canary", stderr=text), "coordinator_process", None)
    assert facts["stage"] == "coordinator_process"
    assert facts["worker_reason"] is None


@pytest.mark.parametrize("text", ["private-canary", "corpus_diagnostic={", "corpus_diagnostic=" + "[" * 2100])
def test_opaque_or_oversized_child_output_is_never_reprinted(text):
    facts = _facts(subprocess.CalledProcessError(1, "private-canary", stderr=text))
    assert facts["worker_reason"] is None


def test_actual_worker_boundary_preserves_success_call_and_result(monkeypatch):
    calls = []
    report = {"groups": {}, "elapsed": 1.25, "rss_mib": 3.5}

    def run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, json.dumps(report), "")

    monkeypatch.setattr(runner.subprocess, "run", run)
    assert runner._run_worker(2) == report
    assert calls == [
        (
            [sys.executable, str(Path(runner.__file__).resolve()), "--worker", "2"],
            {"check": True, "capture_output": True, "text": True, "timeout": 60},
        )
    ]


def test_actual_worker_invalid_json_is_distinct_from_process_failure(monkeypatch):
    monkeypatch.setattr(
        runner.subprocess, "run", lambda *a, **kw: subprocess.CompletedProcess(a[0], 0, "private-canary", "")
    )
    with pytest.raises(diagnostic.CorpusDiagnosticError) as caught:
        runner._run_worker(1)
    facts = diagnostic._decode_facts(str(caught.value))
    assert facts and facts["stage"] == "worker_report" and facts["reason"] == "invalid_report"
    assert facts["returncode"] is None


@pytest.mark.parametrize("worker", [False, True])
def test_actual_main_emits_finite_failure_and_original_exit_one(monkeypatch, capsys, worker):
    def fail(*args):
        raise MemoryError("private-canary")

    monkeypatch.setattr(runner, "_worker_report" if worker else "_coordinator_report", fail)
    monkeypatch.setattr(sys, "argv", ["private-canary", "--worker", "1"] if worker else ["private-canary"])
    with pytest.raises(SystemExit) as caught:
        runner._main()
    assert caught.value.code == 1
    capture = capsys.readouterr()
    assert capture.out == "" and "private-canary" not in capture.err
    facts = diagnostic._decode_facts(capture.err)
    assert facts and facts["exception"] == "MemoryError"
    assert facts["stage"] == ("worker_evaluation" if worker else "coordinator_evaluation")


@pytest.mark.parametrize("worker", [False, True])
def test_actual_main_success_json_remains_unchanged(monkeypatch, capsys, worker):
    report = {"groups": {}, "elapsed": 1.0, "rss_mib": 2.0} if worker else {"actual": {}, "elapsed": 1.0}
    calls = []

    def succeed(*args):
        calls.append(args)
        return report

    monkeypatch.setattr(runner, "_worker_report" if worker else "_coordinator_report", succeed)
    monkeypatch.setattr(sys, "argv", ["synthetic", "--worker", "2"] if worker else ["synthetic"])
    runner._main()
    captured = capsys.readouterr()
    assert captured.out == json.dumps(report, sort_keys=True) + "\n" and captured.err == ""
    assert calls == [(2, 4)] if worker else calls == [()]


@pytest.mark.parametrize("error", [SystemExit(7), KeyboardInterrupt()])
def test_process_control_exceptions_are_not_reclassified(error):
    with pytest.raises(type(error)) as caught, diagnostic.corpus_failure_boundary("worker_evaluation", 0):
        raise error
    assert caught.value is error


@pytest.mark.parametrize("mode", ["exit", "signal", "timeout"])
def test_real_child_process_outcomes_are_distinct(mode):
    if mode == "signal" and sys.platform == "win32":
        pytest.skip("POSIX signal exit control")
    programs = {
        "exit": "raise SystemExit(7)",
        "signal": "import os,signal;os.kill(os.getpid(),signal.SIGTERM)",
        "timeout": "import time;time.sleep(30)",
    }
    with (
        pytest.raises(diagnostic.CorpusDiagnosticError) as caught,
        diagnostic.corpus_failure_boundary("worker_process", 0),
    ):
        subprocess.run(
            [sys.executable, "-c", programs[mode]],
            check=True,
            capture_output=True,
            text=True,
            timeout=0.1 if mode == "timeout" else 5,
        )
    facts = diagnostic._decode_facts(str(caught.value))
    assert facts is not None
    assert facts["reason"] == ("timeout" if mode == "timeout" else "nonzero_exit")
    assert facts["returncode"] == {"exit": 7, "signal": -signal.SIGTERM, "timeout": None}[mode]


def test_real_worker_main_failure_survives_actual_process_capture(monkeypatch):
    real_run = subprocess.run
    command = (
        "from tests import guard_command_corpus_runner as runner; import sys;"
        "sys.argv=['synthetic','--worker','2'];"
        "exec(\"def fail(*args):\\n raise MemoryError('private-canary')\");"
        "runner._worker_report=fail;runner._main()"
    )

    def launch_controlled_worker(_command, **kwargs):
        # The runner retains its actual subprocess options, including the 60-second timeout.
        return real_run([sys.executable, "-c", command], **kwargs)

    monkeypatch.setattr(runner.subprocess, "run", launch_controlled_worker)
    with pytest.raises(diagnostic.CorpusDiagnosticError) as caught:
        runner._run_worker(2)
    facts = diagnostic._decode_facts(str(caught.value))
    assert facts and facts["returncode"] == 1
    assert facts["worker_exception"] == "MemoryError" and facts["worker_index"] == 2
    assert "private-canary" not in str(caught.value)


@pytest.mark.parametrize("mode", ["exit", "timeout", "invalid_json"])
def test_original_selector_long_traceback_never_renders_captured_canaries(tmp_path, mode):
    # Invoke the actual unchanged selector body under a controlled process failure.
    root = Path(__file__).resolve().parents[1]
    canary = "private-" + "canary"
    test = tmp_path / "test_finite_failure.py"
    config = tmp_path / "pytest.ini"
    config.write_text("[pytest]\n", encoding="utf-8")
    assert config.is_file() and config.read_text(encoding="utf-8") == "[pytest]\n"
    test.write_text(
        "import subprocess\nfrom tests import test_guard_command_corpus as original\n"
        "def test_original_failure(monkeypatch):\n"
        "    def fail(*args, **kwargs):\n"
        + (
            {
                "exit": "        raise subprocess.CalledProcessError(7, '"
                + canary
                + "', '"
                + canary
                + "', '"
                + canary
                + "')\n",
                "timeout": "        raise subprocess.TimeoutExpired('"
                + canary
                + "', 90, '"
                + canary
                + "', '"
                + canary
                + "')\n",
                "invalid_json": "        return subprocess.CompletedProcess('"
                + canary
                + "', 0, '"
                + canary
                + "', '')\n",
            }[mode]
        )
        + "    monkeypatch.setattr(original.subprocess, 'run', fail)\n"
        "    original.test_full_guard_evaluation_matches_exact_non_widening_known_gap_baseline()\n",
        encoding="utf-8",
    )
    completed = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "--tb=long", "--showlocals", "-c", str(config), str(test)],
        cwd=root,
        env={
            **os.environ,
            "PYTHONPATH": os.pathsep.join((str(root / "src"), str(root))),
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        },
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 1
    assert "corpus_diagnostic=" in completed.stdout
    assert canary not in completed.stdout + completed.stderr
    assert (
        '"reason": "' + {"exit": "nonzero_exit", "timeout": "timeout", "invalid_json": "invalid_report"}[mode]
        in completed.stdout
    )
