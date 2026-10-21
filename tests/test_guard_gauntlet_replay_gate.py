"""Gauntlet replay lane: strict interruption judging through the real native hook path.

Unlike the benign false-positive gate, a warning or rendered reason text on ordinary work fails here,
and every case also runs under a realistic environment (library path, git-lfs filter, gpg program and
hooks path in the global gitconfig). Run it like the benign gate: HOL_GUARD_NATIVE_BINARY names the
compiled native runtime. ``known_gaps`` in the case file lists cases expected to fail on the current
product. A gap's value is the reason code it is expected to fail with: it xfails only when the failure
carries that code, so a new regression on a listed case still fails. On Linux CI a listed case that
passes fails as stale.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from ci.gauntlet.approval_rows import approval_rows
from ci.gauntlet.input_evidence import redact_value
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.hook_execution_environment import collect_hook_execution_environment
from codex_plugin_scanner.guard.store import GuardStore
from tests.benign_fp_gate_connectors import allow_ready_cli
from tests.benign_fp_gate_fixture import BenignFixture, build_fixture, route_codex
from tests.benign_fp_gate_projects import host_tool_path
from tests.gauntlet_replay import (
    ENVIRONMENTS,
    GATE_DOCUMENT,
    REPLAY_DOCUMENT,
    ReplayCase,
    cursor_hook_fields,
    environment_overlay,
    expand,
    failure_reasons,
    judge,
    payload_input,
    source_ref_payload,
    write_global_gitconfig,
)
from tests.native_gate_retry import review_with_unavailable_retry

_CASES = expand()
# The benign gate already records, per Linux CI result, which ordinary cases still warn or review.
# Those are the same product gaps here (a mirrored Pi case shares omp's), so they are known gaps of this lane too.
_PI_IDS = {case.case_id for case in _CASES if case.harness == "pi"}
_GAPS: dict[str, str] = {
    **{key: reason for key, reason in GATE_DOCUMENT["pending_fix"].items()},
    **{
        key.replace("@omp", "@pi"): reason
        for key, reason in GATE_DOCUMENT["pending_fix"].items()
        if key.endswith("@omp") and key.replace("@omp", "@pi") in _PI_IDS
    },
    **REPLAY_DOCUMENT["known_gaps"],
}
_ENFORCE_STALE = bool(os.environ.get("CI")) and sys.platform != "darwin"


@pytest.fixture(scope="module", params=ENVIRONMENTS)
def replay_environment(
    request: pytest.FixtureRequest, tmp_path_factory: pytest.TempPathFactory
) -> Iterator[tuple[str, BenignFixture, HookWorker]]:
    # macOS pytest temp dirs sit under /private/var, which real sessions never use for sibling
    # worktrees; root the fixture under /tmp as a Linux runner and real developer hosts do.
    root = (
        Path(tempfile.mkdtemp(prefix=f"gauntlet-replay-{request.param}-", dir="/tmp")).resolve()
        if sys.platform == "darwin"
        else tmp_path_factory.mktemp(f"gauntlet-replay-{request.param}")
    )
    fixture = build_fixture(root)
    write_global_gitconfig(request.param, fixture.home)
    patch = pytest.MonkeyPatch()
    patch.setenv("HOME", str(fixture.home))
    # Git finds the fixture ~/.gitconfig through HOME, as on a real host. The native Git
    # proofs fail closed on any inherited GIT_*, LD_* or DYLD_* override, so the clean
    # lane starts without them; the realistic overlay adds back what developer shells carry.
    for name in list(os.environ):
        if name.upper().startswith(("GIT_", "LD_", "DYLD_")):
            patch.delenv(name)
    patch.setenv("XDG_CONFIG_HOME", str(fixture.home / ".config"))
    patch.setenv("HOL_GUARD_NATIVE", "force")
    binary = os.environ.get("HOL_GUARD_NATIVE_BINARY")
    if not binary:
        pytest.fail("HOL_GUARD_NATIVE_BINARY must name the compiled native runtime")
    patch.setenv("HOL_GUARD_NATIVE_BINARY", binary)
    for key, value in environment_overlay(request.param, fixture.home).items():
        patch.setenv(key, value)
    # Match the Gauntlet replay environment in both replay gates: the host tools a hosted runner
    # cannot offer, such as Bun for the native `bun -e` proof and a Node the sandbox may run.
    patch.setenv("PATH", host_tool_path(fixture.home, os.environ.get("PATH", "")))
    store = GuardStore(fixture.guard_home)
    allow_ready_cli(store, fixture.home)
    worker = HookWorker(store=store, workspace=fixture.worktree)
    try:
        yield request.param, fixture, worker
    finally:
        worker.close()
        patch.undo()
        fixture.cleanup()
        if sys.platform == "darwin":
            shutil.rmtree(root, ignore_errors=True)


def _replay(case: ReplayCase, fixture: BenignFixture, worker: HookWorker) -> tuple[dict[str, object], list[dict]]:
    known = {str(row.get("request_id")) for row in worker.store.list_approval_requests(status=None, limit=500)}
    resolved = redact_value(case.tool_input, fixture.tokens())
    assert isinstance(resolved, dict)
    payload: dict[str, object] = {
        "hook_event_name": case.event,
        "tool_name": case.tool_name,
        "tool_input": payload_input(case, resolved),
        "session_id": "gauntlet-replay",
        "tool_call_id": case.case_id,
        "cwd": str(fixture.cwd(case.cwd)),
        "guard_execution_environment": collect_hook_execution_environment(),
    }
    if case.tool_response is not None:
        payload["tool_response"] = case.tool_response
    if case.source_ref:
        spelled = str(resolved.get("path") or resolved["file_path"])
        payload["guard_source_ref"] = source_ref_payload(spelled, fixture.cwd(case.cwd))
    if case.harness == "cursor":
        payload.update(cursor_hook_fields(case.tool, payload))
    # Approval baselines stay from before the first attempt, so a retry never hides a row.
    result = review_with_unavailable_retry(
        case.case_id,
        lambda: worker.review_http_payload(
            payload=payload,
            params={},
            default_harness=case.harness,
            home_dir=fixture.home,
            guard_home=fixture.guard_home,
            workspace=fixture.cwd(case.cwd),
        ),
    )
    if case.harness == "codex":
        result = route_codex(result, payload, fixture)
    return result, approval_rows(worker.store, known)


@pytest.mark.usefixtures("native_hook_force")
@pytest.mark.parametrize("case", _CASES, ids=lambda case: case.case_id)
def test_replayed_payload_is_quiet_offers_always_or_blocks(
    case: ReplayCase, replay_environment: tuple[str, BenignFixture, HookWorker]
) -> None:
    kind, fixture, worker = replay_environment
    result, rows = _replay(case, fixture, worker)
    failure = judge(case, result, rows)
    label = f"{case.case_id}/{kind}"
    # A gap may name one harness and environment, one harness, every harness in one environment, or the case.
    gap_key = next((k for k in (label, case.case_id, f"{case.base_id}/{kind}", case.base_id) if k in _GAPS), None)
    if gap_key is not None:
        reason = _GAPS[gap_key]
        reasons = failure_reasons(case, result, rows)
        # macOS offers protected read-only test execution where the Linux runner that recorded
        # these gaps can only review; either outcome is the same recorded gap.
        if sys.platform == "darwin" and any(r.endswith("_readonly_containment_required") for r in reasons):
            reasons = {*reasons, "native_command_review_required"}
        if failure and reason in reasons:
            pytest.xfail(f"known gap ({reason}): {failure}")
        if failure:
            pytest.fail(f"{label}: failed differently than its known gap ({reason}): {failure}")
        if _ENFORCE_STALE:
            pytest.fail(f"stale known gap: {label} now behaves; remove it ({reason})")
        pytest.skip(f"known gap {label} behaves on this host; CI decides staleness")
    assert failure is None, f"{label}: {failure} reasons={sorted(failure_reasons(case, result, rows))}"


def test_every_harness_and_attack_class_is_covered() -> None:
    assert {case.harness for case in _CASES} == {"codex", "zcode", "claude-code", "omp", "pi", "cursor"}
    attacks = {
        "neg-read-aws-credentials",
        "neg-env-exfil-curl",
        "neg-curl-pipe-sh",
        "neg-rm-rf-outside",
        "neg-encoded-exec",
        "neg-injection-exfil",
        "neg-cat-ssh-key",
    }
    for harness in {case.harness for case in _CASES}:
        blocked = {case.base_id for case in _CASES if case.expect == "block" and case.harness == harness}
        assert attacks <= blocked, f"{harness} misses attacks {sorted(attacks - blocked)}"
    assert {
        "omp-eval-promise-all-reads",
        "omp-eval-py-print-read",
        "omp-todo-phases",
        "zcode-read-git-head",
        "zcode-read-git-ref-main",
        "pytest-contained",
    } <= {c.base_id for c in _CASES}


def test_known_gaps_name_real_cases() -> None:
    ids = {case.case_id for case in _CASES} | {case.base_id for case in _CASES}
    stripped = {key.rsplit("/", 1)[0] if key.rsplit("/", 1)[-1] in ENVIRONMENTS else key for key in _GAPS}
    assert stripped <= ids, sorted(stripped - ids)
