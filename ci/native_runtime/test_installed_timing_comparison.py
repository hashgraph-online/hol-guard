"""Evidence must retain failed observations and preserve the fixed workload."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from scripts.ci import compare_installed_timing as subject


class ComparisonTests(unittest.TestCase):
    def test_counter_failures_do_not_change_the_measured_call(self) -> None:
        calls = []
        observations = []
        token = object()

        def measured(*args, **kwargs):
            calls.append((args, kwargs))
            return token

        with patch.object(subject, "capacity_state", side_effect=RuntimeError("PRIVATE")):
            wrapped = subject.observed_call(measured, observations, "c16", capacity=True)
            self.assertIs(wrapped(token, include_capacity=True), token)
        self.assertEqual(calls, [((token,), {"include_capacity": True})])
        self.assertEqual(len(observations), 1)
        self.assertIs(observations[0]["completed"], True)
        self.assertEqual(observations[0]["before"], {"available": False})
        self.assertNotIn("PRIVATE", json.dumps(observations))

    def test_original_failure_is_preserved(self) -> None:
        observations = []
        failure = RuntimeError("controlled failure")

        def fail(*args, **kwargs):
            raise failure

        with self.assertRaises(RuntimeError) as caught:
            subject.observed_call(fail, observations, "cold")()
        self.assertIs(caught.exception, failure)
        self.assertNotIn("completed", observations[0])
        self.assertIn("elapsed_ms", observations[0])

    def test_numeric_observations_reject_strings_booleans_and_nonfinite_values(self) -> None:
        for value in (True, "1", "PRIVATE", float("nan"), float("inf"), -1, 4097, 2**10000):
            self.assertIsNone(subject.bounded_number(value, 4096))
        self.assertEqual(subject.bounded_number(4096, 4096), 4096)

    def test_fixed_schedule_retains_a_failed_observation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "results"
            calls = []

            def execute(command, **kwargs):
                if "--worker" not in command:
                    return subprocess.CompletedProcess(command, 0)
                name = command[command.index("--worker") + 1]
                path = Path(command[command.index("--output") + 1])
                calls.append(name)
                passed = len(calls) != 2
                result = {
                    "schema": "guard-installed-timing-observation.v1",
                    "build": name,
                    **subject.BUILDS[name],
                    "runtimeAcceptance": False,
                    "slo": {"passed": passed},
                    "failure_type": None,
                    "phases": [
                        {"phase": phase, "completed": True}
                        for phase in ("cold", "warm", "sizes", "recovery", "c16", "rss_and_c64")
                    ],
                }
                path.write_text(json.dumps(result), encoding="utf-8")
                return subprocess.CompletedProcess(command, 0 if passed else 1)

            wheels = {name: Path(name) for name in subject.BUILDS}
            with patch.object(subject, "verify_wheel", return_value={}):
                self.assertEqual(subject.run_schedule(wheels, output, execute), 1)
            self.assertEqual(tuple(calls), subject.SCHEDULE)
            report = json.loads((output / "comparison.json").read_text())
            self.assertFalse(report["all_observations_passed"])
            self.assertFalse(report["runtimeAcceptance"])
            self.assertFalse(report["observations"][1]["gates_passed"])
            self.assertEqual(len(report["observations"]), 4)

    def test_last_observation_timeout_cannot_produce_a_green_summary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "results"
            calls = 0

            def execute(command, **kwargs):
                nonlocal calls
                if "--worker" not in command:
                    return subprocess.CompletedProcess(command, 0)
                calls += 1
                if calls == 4:
                    raise subprocess.TimeoutExpired(command, 480)
                name = command[command.index("--worker") + 1]
                path = Path(command[command.index("--output") + 1])
                path.write_text(
                    json.dumps(
                        {
                            "schema": "guard-installed-timing-observation.v1",
                            "build": name,
                            **subject.BUILDS[name],
                            "runtimeAcceptance": False,
                            "slo": {"passed": True},
                            "failure_type": None,
                            "phases": [
                                {"phase": phase, "completed": True}
                                for phase in ("cold", "warm", "sizes", "recovery", "c16", "rss_and_c64")
                            ],
                        }
                    )
                )
                return subprocess.CompletedProcess(command, 0)

            with patch.object(subject, "verify_wheel", return_value={}), self.assertRaises(subprocess.TimeoutExpired):
                subject.run_schedule({name: Path(name) for name in subject.BUILDS}, output, execute)
            report = json.loads((output / "comparison.json").read_text())
            self.assertFalse(report["all_observations_passed"])
            self.assertEqual(len(report["observations"]), 4)

    def test_observation_timeout_reaps_the_owned_process(self) -> None:
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(subprocess.TimeoutExpired):
            subject.run_isolated(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                cwd=Path(directory),
                check=False,
                capture_output=True,
                timeout=0.05,
            )

    def test_outer_digest_and_duplicate_members_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            wheel = Path(directory) / "sample.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr(subject.MANIFEST_MEMBER, "{}")
                archive.writestr(subject.RUNTIME_MEMBER, b"synthetic")
            expected = {**subject.BUILDS["previous"]}
            with self.assertRaisesRegex(ValueError, "wheel_digest_mismatch"):
                subject.verify_wheel(wheel, expected)
            expected["wheel_sha256"] = hashlib.sha256(wheel.read_bytes()).hexdigest()
            with self.assertRaisesRegex(ValueError, "manifest_mismatch"):
                subject.verify_wheel(wheel, expected)
            with zipfile.ZipFile(wheel, "a") as archive, self.assertWarns(UserWarning):
                archive.writestr(subject.MANIFEST_MEMBER, "{}")
            expected["wheel_sha256"] = hashlib.sha256(wheel.read_bytes()).hexdigest()
            with self.assertRaisesRegex(ValueError, "member_invalid"):
                subject.verify_wheel(wheel, expected)


if __name__ == "__main__":
    unittest.main()
