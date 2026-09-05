from __future__ import annotations

import subprocess
from collections.abc import Sequence

from scripts.retry_verify_published import is_retryable_incomplete_error, wait_for_published

INCOMPLETE = (
    "Registry release is not the exact Guard artifact set: "
    "missing=['hol_guard-3.0.96-py3-none-win_amd64.whl'], extra=[], mismatched=[]\n"
)
MISMATCH = (
    "Registry release is not the exact Guard artifact set: "
    "missing=[], extra=[], mismatched=['hol_guard-3.0.96.tar.gz']\n"
)


class FakeRunner:
    def __init__(self, returncodes: Sequence[int], stderrs: Sequence[str]) -> None:
        self.returncodes = list(returncodes)
        self.stderrs = list(stderrs)
        self.calls = 0
        self.commands: list[Sequence[str]] = []

    def __call__(self, command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        self.calls += 1
        self.commands.append(command)
        index = min(self.calls - 1, len(self.returncodes) - 1)
        return subprocess.CompletedProcess(
            command,
            self.returncodes[index],
            stdout='{"status":"exact"}\n' if self.returncodes[index] == 0 else "",
            stderr=self.stderrs[index],
        )


def test_incomplete_missing_set_is_retryable() -> None:
    assert is_retryable_incomplete_error(INCOMPLETE)
    assert not is_retryable_incomplete_error(MISMATCH)
    assert not is_retryable_incomplete_error("Registry request failed with HTTP 500\n")


def test_wait_retries_incomplete_then_succeeds() -> None:
    sleeps: list[float] = []
    runner = FakeRunner([1, 0], [INCOMPLETE, ""])
    assert wait_for_published(["--registry", "pypi"], runner=runner, sleeper=sleeps.append) == 0
    assert runner.calls == 2
    assert sleeps == [5.0]


def test_wait_fails_immediately_on_digest_mismatch() -> None:
    sleeps: list[float] = []
    runner = FakeRunner([1], [MISMATCH])
    assert wait_for_published(["--registry", "pypi"], runner=runner, sleeper=sleeps.append) == 1
    assert runner.calls == 1
    assert sleeps == []
