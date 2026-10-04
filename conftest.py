"""Repository-level pytest safeguards for process-isolated regressions."""

from __future__ import annotations

import json
import multiprocessing
import traceback

import pytest

_PACKAGE_SHIM_SQLITE_LOCK_TEST = (
    "tests/test_guard_package_shims.py::test_package_manager_shim_waits_out_transient_store_writer_lock"
)


@pytest.fixture(autouse=True)
def _spawn_package_shim_sqlite_lock_holder(
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Avoid forking the SQLite lock holder from pytest's multithreaded process."""
    if request.node.nodeid != _PACKAGE_SHIM_SQLITE_LOCK_TEST:
        return

    context = multiprocessing.get_context("spawn")
    module = request.node.module
    monkeypatch.setattr(module, "Event", context.Event)
    monkeypatch.setattr(module, "Process", context.Process)


_GUARD_POST_TOOL_DIAGNOSTIC_TEST = (
    "tests/test_guard_runtime.py::TestGuardRuntime::"
    "test_codex_post_tool_use_blocks_double_quoted_command_substitution_search"
)


def _guard_post_tool_failure_diagnostic(payload: dict[str, object]) -> dict[str, object]:
    from codex_plugin_scanner.guard.config import VALID_GUARD_ACTIONS
    from codex_plugin_scanner.guard.daemon.hook_availability_policy import (
        _INTEGRITY_FAIL_CLOSED_REASON_CODES,
        _REVIEW_CANNOT_FINISH_REASON_CODES,
    )

    diagnostic: dict[str, object] = {}
    reason_code = payload.get("reason_code")
    if isinstance(reason_code, str) and reason_code in (
        _REVIEW_CANNOT_FINISH_REASON_CODES | _INTEGRITY_FAIL_CLOSED_REASON_CODES
    ):
        diagnostic["reason_code"] = reason_code
    policy_action = payload.get("policy_action")
    if isinstance(policy_action, str) and policy_action in VALID_GUARD_ACTIONS:
        diagnostic["policy_action"] = policy_action
    continues = payload.get("continue")
    if isinstance(continues, bool):
        diagnostic["continue"] = continues
    approval_requests = payload.get("approval_requests")
    if isinstance(approval_requests, list):
        diagnostic["approval_request_count"] = len(approval_requests)
    return diagnostic


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo[None]):
    outcome = yield
    if item.nodeid != _GUARD_POST_TOOL_DIAGNOSTIC_TEST or call.when != "call":
        return
    report = outcome.get_result()
    if not report.failed or call.excinfo is None or call.excinfo.type is not AssertionError:
        return
    for frame, _lineno in traceback.walk_tb(call.excinfo.tb):
        if frame.f_code is item.function.__code__:
            output = frame.f_locals.get("output")
            if isinstance(output, dict):
                diagnostic = _guard_post_tool_failure_diagnostic(output)
                if diagnostic:
                    report.sections.append(("Guard post-tool status", json.dumps(diagnostic, sort_keys=True)))
            break
