"""Native round trips one CLI PreToolUse hook may spend.

``tests/test_guard_hook_rpc_budget.py`` bounds the daemon's pi PostToolUse
path. The CLI hook is a different composition — ``commands_hook`` builds its
own worker and runs the native pipeline in the calling process — so nothing
bounded how many times it asked the resident, and a port that added one more
un-memoized call per request landed straight in the CLI hook's p95.

Measured on the fixture below, a `git status --short` PreToolUse hook spends
26 round trips, of which 24 are on the hook's own path. Three of them hold
most of the time: the raw-envelope edge review and the ``compose_current``
and ``finalize`` decisions. The remaining calls are individually under a
millisecond, so this budget is a ceiling on growth rather than a latency
target — it catches a new call per request, not the cost of the three.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import shutil
import sys
import tempfile
from collections import Counter
from collections.abc import Iterator
from itertools import pairwise
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli import commands_hook
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.hook_execution_environment import collect_hook_execution_environment
from codex_plugin_scanner.guard.store import GuardStore
from tests.benign_fp_gate_connectors import allow_ready_cli
from tests.benign_fp_gate_fixture import BenignFixture, build_fixture
from tests.benign_fp_gate_projects import host_tool_path

# Round trips one CLI PreToolUse hook may spend on its own path. A new port
# must fold its work into these or memoize it for the invocation. The runtime
# snapshot digest is one such memoized call: the resident computes it once per
# hook process, however many times the hook builds the snapshot.
_RESIDENT_ROUND_TRIPS_PER_CLI_PRE_TOOL_HOOK = 25

# Work the hook does not drive request by request: the direct-hook evidence
# drain pages on its own wake-ups and the snapshot publisher runs on its own
# thread, so how often either lands in a batch is a matter of timing. They are
# still on the hook's clock — a one-shot CLI hook starts a worker that waits
# for the publisher to report ready and closes it afterwards — so they are
# counted on their own rather than exempted.
_BACKGROUND_OPERATIONS = frozenset({"hook_direct_evidence_drain", "policy_snapshot_push"})

# Each is bounded on its own, because they vary for different reasons and one
# must not spend the other's room. Every allowance is per batch rather than per
# hook: it is there for a thread that lands out of step, and growth that tracks
# the request count exhausts a fixed allowance however little it adds per
# request. That is what makes a port that publishes per request fail here.
#
# A one-shot CLI hook's worker waits for one publication and closes, so the
# count follows the hooks exactly; the allowance covers a publisher that
# republishes once while the worker is still up.
_PUBLICATIONS_PER_CLI_PRE_TOOL_HOOK = 1
_PUBLICATION_JITTER_PER_BATCH = 1

# The direct-hook evidence drain pages on its own wake-ups, so how many land
# while a batch runs is timing rather than a count the hook drives. It is held
# to a rate instead of being exempted.
_DRAIN_ROUND_TRIPS_PER_CLI_PRE_TOOL_HOOK = 2
_DRAIN_JITTER_PER_BATCH = 2

_BATCH = 3


def _measured_operations(log_path: Path) -> list[str]:
    """Every operation the resident request log holds, warmup markers removed."""

    if not log_path.is_file():
        return []
    return [line.decode() for line in log_path.read_bytes().splitlines() if line != b"W"]


def _hook_path_operations(log_path: Path) -> Counter[str]:
    return Counter(name for name in _measured_operations(log_path) if name not in _BACKGROUND_OPERATIONS)


def _background_operations(log_path: Path) -> Counter[str]:
    return Counter(name for name in _measured_operations(log_path) if name in _BACKGROUND_OPERATIONS)


def _assert_growth_within(samples: list[Counter[str]], ceiling: int) -> None:
    """Every batch between two samples stays within one absolute ceiling."""

    for before, after in pairwise(samples):
        growth = after - before
        assert sum(growth.values()) <= ceiling, growth


def _assert_round_trip_growth(samples: list[Counter[str]]) -> None:
    _assert_growth_within(samples, _BATCH * _RESIDENT_ROUND_TRIPS_PER_CLI_PRE_TOOL_HOOK)


def _assert_background_growth(samples: list[Counter[str]]) -> None:
    """Each background operation answers to its own ceiling, not to a total."""

    ceilings = {
        "policy_snapshot_push": _BATCH * _PUBLICATIONS_PER_CLI_PRE_TOOL_HOOK + _PUBLICATION_JITTER_PER_BATCH,
        "hook_direct_evidence_drain": _BATCH * _DRAIN_ROUND_TRIPS_PER_CLI_PRE_TOOL_HOOK + _DRAIN_JITTER_PER_BATCH,
    }
    for name, ceiling in ceilings.items():
        _assert_growth_within([Counter({name: sample[name]}) for sample in samples], ceiling)


@pytest.fixture(scope="module")
def cli_hook_environment(tmp_path_factory: pytest.TempPathFactory) -> Iterator[tuple[BenignFixture, GuardStore, Path]]:
    """The benign gate's sealed home, driven through the CLI hook entry point.

    Same reasoning as ``test_guard_benign_false_positive_gate``: a macOS pytest
    temp dir is not a place a real HOME lives, and the native Git proofs fail
    closed on any ``GIT_*``, ``LD_*`` or ``DYLD_*`` override the agent carries.
    """

    root = (
        Path(tempfile.mkdtemp(prefix="cli-hook-rpc-", dir="/tmp")).resolve()
        if sys.platform == "darwin"
        else tmp_path_factory.mktemp("cli-hook-rpc")
    )
    fixture = build_fixture(root)
    patch = pytest.MonkeyPatch()
    patch.setenv("HOME", str(fixture.home))
    for name in list(os.environ):
        if name.upper().startswith(("GIT_", "LD_", "DYLD_")) or name.upper() == "RIPGREP_CONFIG_PATH":
            patch.delenv(name)
    patch.setenv("XDG_CONFIG_HOME", str(fixture.home / ".config"))
    patch.setenv("HOL_GUARD_NATIVE", "force")
    binary = os.environ.get("HOL_GUARD_NATIVE_BINARY")
    if not binary:
        pytest.fail("HOL_GUARD_NATIVE_BINARY must name the compiled native runtime")
    patch.setenv("HOL_GUARD_NATIVE_BINARY", binary)
    patch.setenv("PATH", host_tool_path(fixture.home, os.environ.get("PATH", "")))
    log_path = root / "resident-requests.log"
    patch.setenv("HOL_GUARD_RESIDENT_REQUEST_LOG", os.fspath(log_path))
    store = GuardStore(fixture.guard_home)
    allow_ready_cli(store, fixture.home)
    try:
        yield fixture, store, log_path
    finally:
        patch.undo()
        fixture.cleanup()
        if sys.platform == "darwin":
            shutil.rmtree(root, ignore_errors=True)


def _decision(response: dict[str, object]) -> str:
    """The effective verdict in a claude-code hook response.

    A response that names no verdict reads as ``unspecified`` rather than as an
    allow: a hook that exits 0 with nothing to say has not allowed the command,
    and counting it as one would let a hook stop short and still pass a budget
    that only measures round trips.
    """

    specific = response.get("hookSpecificOutput")
    permission = specific.get("permissionDecision") if isinstance(specific, dict) else None
    permission = permission or response.get("permission") or response.get("decision")
    if response.get("continue") is False or response.get("policy_action") == "block":
        return "deny"
    if permission in {"deny", "block"}:
        return "deny"
    if permission == "ask":
        return "ask"
    if permission == "allow":
        return "allow"
    return "unspecified"


def _run_hook(fixture: BenignFixture, store: GuardStore, index: int) -> None:
    """Run one hook and fail unless it reached the decision the budget measures.

    A ceiling alone passes when a hook stops short: a regression that fails
    closed after its first resident request spends fewer round trips, not more.
    Each invocation has to come back a quiet allow for its requests to count.
    """

    cwd = Path(str(fixture.cwd("worktree")))
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "git status --short"},
        "session_id": "cli-hook-rpc-budget",
        "tool_call_id": f"cli-rpc-{index}",
        "cwd": str(cwd),
        "home_dir": str(fixture.home),
        "guard_execution_environment": collect_hook_execution_environment(),
    }
    output_stream = io.StringIO()
    status = commands_hook._run_guard_hook_command(
        argparse.Namespace(
            artifact_id=None,
            artifact_name=None,
            event_file=None,
            harness="claude-code",
            json=True,
            policy_action=None,
            runtime_harness=None,
        ),
        guard_home=fixture.guard_home,
        workspace=cwd,
        context=HarnessContext(fixture.home, cwd, fixture.guard_home),
        store=store,
        config=GuardConfig(guard_home=fixture.guard_home, workspace=fixture.worktree, default_action="review"),
        input_text=json.dumps(payload),
        output_stream=output_stream,
    )
    rendered = output_stream.getvalue().strip()
    assert status == 0, f"hook {index} exited {status}: {rendered}"
    response = json.loads(rendered) if rendered else {}
    assert isinstance(response, dict), f"hook {index} wrote no response object: {rendered}"
    assert _decision(response) == "allow", f"hook {index} did not allow: {rendered}"


def test_cli_pre_tool_hook_resident_round_trips_per_request_are_bounded(
    cli_hook_environment: tuple[BenignFixture, GuardStore, Path],
) -> None:
    fixture, store, log_path = cli_hook_environment
    # The first hooks in this process pay one-time resident startup. Sampling
    # prefixes afterwards makes that traffic common to every sample, so the
    # growth between two samples is the batch's own round trips.
    for index in range(_BATCH):
        _run_hook(fixture, store, index)
    samples: list[Counter[str]] = [_hook_path_operations(log_path)]
    background: list[Counter[str]] = [_background_operations(log_path)]
    for batch in range(1, 4):
        for index in range(_BATCH):
            _run_hook(fixture, store, batch * _BATCH + index)
        samples.append(_hook_path_operations(log_path))
        background.append(_background_operations(log_path))
    assert sum(samples[0].values()) > 0, "no resident request was recorded"
    _assert_round_trip_growth(samples)
    # Publication and the evidence drain are on the hook's clock too, so they
    # answer to a ceiling of their own rather than to none at all. Counting
    # them apart keeps either budget from spending the other's room.
    _assert_background_growth(background)


def _replay(
    log_path: Path, *, extra: bytes, once: bool = False, batches: int = 3
) -> tuple[list[Counter[str]], list[Counter[str]]]:
    """Write a hook-shaped request log and sample it the way the budget does.

    Each request spends the hook's own budget plus the one publication and one
    drain its worker accounts for. ``extra`` is what a regression would add: on
    every request after the first batch, or, with ``once``, on a single request,
    which is the shape of a thread that landed out of step.
    """

    log_path.write_bytes(b"W\npolicy_snapshot_push\n")
    samples: list[Counter[str]] = [_hook_path_operations(log_path)]
    background: list[Counter[str]] = [_background_operations(log_path)]
    for batch in range(batches):
        with log_path.open("ab") as output:
            for index in range(_BATCH):
                output.write(b"hook_decide\n" * _RESIDENT_ROUND_TRIPS_PER_CLI_PRE_TOOL_HOOK)
                # What the background budgets account for per hook.
                output.write(
                    b"hook_direct_evidence_drain\n" * _DRAIN_ROUND_TRIPS_PER_CLI_PRE_TOOL_HOOK
                    + b"policy_snapshot_push\n" * _PUBLICATIONS_PER_CLI_PRE_TOOL_HOOK
                )
                if extra and ((batch, index) == (1, 0) if once else (batch, index) >= (1, 0)):
                    output.write(extra)
        samples.append(_hook_path_operations(log_path))
        background.append(_background_operations(log_path))
    return samples, background


@pytest.mark.parametrize("extra", ["none", "per-request"])
def test_growth_tolerates_background_jitter_but_detects_an_extra_call(tmp_path: Path, extra: str) -> None:
    """The measurement itself: a new call on the hook's path fails the budget."""

    added = b"" if extra == "none" else b"hook_render\n"
    samples, _ = _replay(tmp_path / "resident-requests.log", extra=added)
    assert sum(samples[0].values()) == 0
    if extra == "none":
        _assert_round_trip_growth(samples)
        return
    with pytest.raises(AssertionError):
        _assert_round_trip_growth(samples)


@pytest.mark.parametrize("extra", ["none", "one-more-publication", "per-request"])
def test_publication_growth_answers_to_the_background_ceiling(tmp_path: Path, extra: str) -> None:
    """Publication is counted, with room for a thread that runs out of step.

    One extra push in a whole batch is timing and passes. One extra push on
    every request is a port, and it fails however few it adds per request,
    because the allowance it eats is fixed per batch rather than per hook.
    """

    added = b"" if extra == "none" else b"policy_snapshot_push\n"
    _, background = _replay(tmp_path / "resident-requests.log", extra=added, once=extra == "one-more-publication")
    if extra == "per-request":
        with pytest.raises(AssertionError):
            _assert_background_growth(background)
        return
    _assert_background_growth(background)
