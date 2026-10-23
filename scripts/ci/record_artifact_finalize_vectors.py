#!/usr/bin/env python3
"""Record artifact-hook final-action vectors from the Python settle.

After the artifact hook has a verdict, three paths can still change it: a
Watch-mode record that executes the policy it observed, a silent denial, and a
browser approval that resolved the review. Each path called
``set_native_artifact_hook_final_action`` (``commands_hook_native_state.py``),
and the browser path first decided in ``finalize_native_artifact_hook``
(``commands_hook_native_finish.py``) whether the outcome settled the hook at
all. The resident decides all of that now: ``artifact_finalize`` and
``artifact_browser_outcome`` in ``hook_decision_artifact_finalize.rs``.

``artifact_finalize_oracle.py`` keeps that Python code as it stood at
3b8ac2e848, so the oracle never calls the code it checks. The two
collaborators that only render (``build_decision_v2`` and
``build_incident_context``) are stubs that echo their arguments, so a vector
records which arguments the settle chose. Regenerate with:

    PYTHONPATH=src .venv/bin/python scripts/ci/record_artifact_finalize_vectors.py

A ``settle`` vector holds the resident's inputs (``facts``), the answer the
recorded behaviour exhibits (``answer``), the receipt the settle persists
(``receipt``: the fields and the exact text of its ``scanner_evidence``), the
text of the two ordered objects the resident must write in Python's key order
(``wire``) and the whole observable outcome (``outcome``, an index into
``outcomes``). A ``browser`` vector holds the outcome facts, the effects the
old section ran and the answer they exhibit.

The Rust ``hook_decision_artifact_finalize_tests`` replays facts to answers and
pins the wire text; the ``tests/test_artifact_finalize_*.py`` suites run the new
executor with the resident stubbed from the vectors and check that it leaves
the same state, receipt bytes and effects.
"""

from __future__ import annotations

import gzip
import itertools
import json
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

if __package__ is None:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.ci.artifact_finalize_oracle import (
    RISK0,
    Envelope,
    Receipt,
    SettleCase,
    outcome_of,
    receipt_pins,
    recorded_browser_outcome,
    recorded_settle_call,
    stub_decision_v2,
    stub_incident_context,
)

__all__ = [
    "Envelope",
    "Receipt",
    "SettleCase",
    "browser_cases",
    "build",
    "main",
    "outcome_of",
    "receipt_pins",
    "record_browser",
    "record_settle",
    "settle_cases",
    "stub_decision_v2",
    "stub_incident_context",
]

OUTPUT = Path("rust/crates/guard-runtime/tests/fixtures/artifact_finalize_vectors.json.gz")

ACTIONS = ("allow", "warn", "review", "require-reapproval", "sandbox-required", "block", "ask", "unrecognized")
OBSERVED = (None, *ACTIONS)
CLOUD_CODES = (
    None,
    "cloud_auth_error",
    "cloud_http_error",
    "cloud_timeout",
    "cloud_validation_error",
    "cloud_unrelated",
    "",
)
INITIAL_ACTIONS = ("review", "require-reapproval", "block")


def observed_answer(case: SettleCase, after: SimpleNamespace) -> tuple[dict[str, Any], dict[str, str | None]]:
    """The resident's answer the recorded behaviour exhibits, and its wire text."""

    pre = case.state()
    response = after.response_payload
    observed = response.get("observed_policy_action")
    detail_refreshed = after.risk_summary != RISK0
    carried = after.decision_v2_payload.get("package_review_cloud_reason_code")
    supply_chain = response.get("supply_chain_evaluation")
    observed_supply_chain = supply_chain.get("observed_policy_action") if isinstance(supply_chain, dict) else None
    reason = str(after.decision_v2_payload["reason"])
    probe = after.scanner_evidence_payload[1]
    fields = {key: value for key, value in probe.items() if key != "source"}
    fields_text = json.dumps(fields, separators=(",", ":"))
    pre_receipt = pre.receipt
    appended = after.receipt.scanner_evidence[len(pre_receipt.scanner_evidence) :]
    assert len(appended) <= 1
    answer = {
        "action": after.policy_action,
        "observed_action": observed,
        "decision_reason": reason,
        "cloud_reason_code": carried,
        "refresh_copy": detail_refreshed,
        "observed_supply_chain_action": observed_supply_chain,
        "drop_terminal_action": "terminal_action" not in response,
        "evidence_patch": {"source": "policy_composition", "fields": json.loads(fields_text)},
        "receipt": {
            "policy_decision": after.receipt.policy_decision,
            "approval_source": after.receipt.approval_source,
            "approval_request_id": after.receipt.approval_request_id,
            "user_override": after.receipt.user_override,
            "appended_evidence": [dict(entry) for entry in appended],
        },
    }
    wire = {
        "fields": fields_text,
        "resolution": json.dumps(appended[0], separators=(",", ":")) if appended else None,
    }
    return answer, wire


def record_settle(
    case: SettleCase,
    run: Callable[[SettleCase], SimpleNamespace] = recorded_settle_call,
) -> dict[str, Any]:
    after = run(case)
    answer, wire = observed_answer(case, after)
    return {
        "facts": case.facts(),
        "answer": answer,
        "receipt": receipt_pins(after.receipt),
        "wire": wire,
        "outcome": outcome_of(after),
    }


def settle_cases() -> Iterator[SettleCase]:
    """Every fact combination the settle can observe, in four sweeps.

    Each sweep varies the facts that interact with each other and holds the
    rest at a representative value. A browser resolution decides ``allow``,
    ``block`` or ``sandbox-required`` and never observes a policy, so the
    browser sweeps stay on those; the other paths pass no source or request.
    """

    browser_actions = ("allow", "block", "sandbox-required")
    # Action normalization: previous, final and observed actions.
    for previous, action, observed in itertools.product(ACTIONS, ACTIONS, OBSERVED):
        yield SettleCase(previous_action=previous, policy_action=action, observed_policy_action=observed)
    for previous, action, request, queued in itertools.product(
        ACTIONS, browser_actions, (None, "req-1"), (None, "queued-1")
    ):
        yield SettleCase(
            previous_action=previous,
            policy_action=action,
            approval_source="browser",
            approval_request_id=request,
            queued_request_id=queued,
        )
    # The receipt: who resolved it, with which request, over which prior values.
    priors = list(itertools.product((None, "cli"), (None, "prior-1"), (None, "user")))
    for action, request, queued, initial, (prior_source, prior_request, prior_override) in itertools.product(
        browser_actions, (None, "", "req-1"), (None, "", "queued-1"), INITIAL_ACTIONS, priors
    ):
        yield SettleCase(
            previous_action="review",
            policy_action=action,
            approval_source="browser",
            approval_request_id=request,
            queued_request_id=queued,
            initial_policy_action=initial,
            receipt_approval_source=prior_source,
            receipt_approval_request_id=prior_request,
            receipt_user_override=prior_override,
        )
    for action, observed, source, request, (prior_source, prior_request, prior_override) in itertools.product(
        ("allow", "block", "review"), (None, "allow"), (None, "", "daemon"), (None, "", "req-1"), priors
    ):
        yield SettleCase(
            previous_action="review",
            policy_action=action,
            observed_policy_action=observed,
            approval_source=source,
            approval_request_id=request,
            queued_request_id="queued-1",
            receipt_approval_source=prior_source,
            receipt_approval_request_id=prior_request,
            receipt_user_override=prior_override,
        )
    # The package evaluation and the cloud reason code the new decision keeps.
    supply_chains = [(False, None), (True, None), *((True, action) for action in ACTIONS)]
    for previous, action, observed, code, (present, package_action) in itertools.product(
        ("review", "allow"), ("allow", "block"), (None, "review"), CLOUD_CODES, supply_chains
    ):
        yield SettleCase(
            previous_action=previous,
            policy_action=action,
            observed_policy_action=observed,
            package_review_cloud_reason_code=code,
            supply_chain_present=present,
            supply_chain_action=package_action,
        )
    # The package evaluation under every final and observed action.
    for action, observed, (present, package_action) in itertools.product(ACTIONS, OBSERVED, supply_chains):
        yield SettleCase(
            previous_action="review",
            policy_action=action,
            observed_policy_action=observed,
            supply_chain_present=present,
            supply_chain_action=package_action,
        )


# ---- the browser outcome ---------------------------------------------------

DECISIONS = ("allow", "block", "sandbox-required", "review", "require-reapproval", "timeout", "", "ALLOW", "Block")
EVENTS = ("PreToolUse", "PostToolUse", "UserPromptSubmit", "PermissionRequest", "Stop", "", "pretooluse")


def observed_outcome(trace: list[list[object]]) -> dict[str, Any]:
    """The outcome fields the recorded trace exhibits."""

    outcome: dict[str, Any] = {
        "settle": False,
        "action": None,
        "approval_source": None,
        "emit_native_allow": False,
        "finish_without_render": False,
    }
    for entry in trace:
        if entry[0] == "settle":
            outcome.update(settle=True, action=entry[1], approval_source=entry[2])
        elif entry[0] == "native_allow":
            outcome["emit_native_allow"] = True
        elif entry[0] == "return":
            outcome["finish_without_render"] = True
    return outcome


def record_browser(
    decision: str,
    event: str,
    run: Callable[[str, str], list[list[object]]] = recorded_browser_outcome,
) -> dict[str, Any]:
    trace = run(decision, event)
    return {
        "facts": {"decision": decision, "event": event},
        "trace": trace,
        "answer": observed_outcome(trace),
    }


def browser_cases() -> Iterator[tuple[str, str]]:
    yield from itertools.product(DECISIONS, EVENTS)


def build() -> dict[str, Any]:
    pool: dict[str, int] = {}
    outcomes: list[str] = []
    settle: list[dict[str, Any]] = []
    for case in settle_cases():
        vector = record_settle(case)
        text = json.dumps(vector["outcome"], sort_keys=True, separators=(",", ":"))
        if text not in pool:
            pool[text] = len(outcomes)
            outcomes.append(text)
        vector["outcome"] = pool[text]
        settle.append(vector)
    browser = [record_browser(decision, event) for decision, event in browser_cases()]
    return {"settle": settle, "browser": browser, "outcomes": outcomes}


def main() -> int:
    vectors = build()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    body = json.dumps(vectors, sort_keys=True, separators=(",", ":")).encode()
    OUTPUT.write_bytes(gzip.compress(body, compresslevel=9, mtime=0))
    print(
        f"wrote {len(vectors['settle'])} settle and {len(vectors['browser'])} browser vectors "
        f"({len(vectors['outcomes'])} outcomes) to {OUTPUT}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
