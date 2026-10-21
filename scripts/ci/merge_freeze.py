#!/usr/bin/env python3
"""Merge freeze: one policy for the CI aggregate gate and the toggle workflow.

The freeze is a repository Actions variable (``MERGE_FREEZE``). A pull request
cannot merge while it is ``true`` because ``hol-guard / required`` fails. Two
paths keep that result honest:

* ``gate`` runs inside the ``hol-guard / required`` job, so every new or
  re-run CI result reflects the flag at the moment it is computed.
* ``reconcile`` runs from ``merge-freeze.yml`` after the flag is toggled and
  re-evaluates pull requests whose CI already finished. A finished check cannot
  be changed by flipping a variable, and a re-run reuses the workflow file the
  run started with, so reconcile posts a failing check run with the aggregate's
  own name while frozen.

GitHub keeps the newest run of each check suite and the required check passes
only when every one of them passes. The freeze check run usually lands in a
suite of its own, where no later CI run can replace it, so lifting the freeze
marks it neutral; CI's own runs still have to pass in their suites. When it
shares a suite with CI, lifting re-runs the real aggregate instead, whose newer
result replaces it there. Neither path lets a pull request pass without a real
CI result.

The gate runs the copy of this file from the pull request's base revision, so a
pull request cannot change the policy that decides whether it may merge.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

FREEZE_VARIABLE = "MERGE_FREEZE"
ALLOW_VARIABLE = "MERGE_FREEZE_ALLOW"
TOGGLE_WORKFLOW = "merge-freeze.yml"
# The name and app of the required check the rulesets enforce.
AGGREGATE_CHECK = "hol-guard / required"
ACTIONS_APP_ID = 15368
GATE_STEP_NAME = "Merge freeze gate"
OVERLAY_EXTERNAL_ID = "merge-freeze/v1"
PASSING_CONCLUSIONS = frozenset({"success", "neutral", "skipped"})
MAX_PAGES = 30


def clean(text: str, limit: int = 80) -> str:
    """Make operator-supplied text safe to echo into logs and annotations."""
    printable = "".join(ch if ch.isprintable() else "?" for ch in text)
    return printable if len(printable) <= limit else printable[: limit - 3] + "..."


@dataclass(frozen=True)
class Freeze:
    """The parsed ``MERGE_FREEZE`` flag. An invalid value is active and fails closed."""

    active: bool
    error: str | None = None


def parse_freeze(raw: str | None) -> Freeze:
    value = (raw or "").strip()
    if not value:
        return Freeze(False)
    lowered = value.lower()
    if lowered == "true":
        return Freeze(True)
    if lowered == "false":
        return Freeze(False)
    return Freeze(True, f"{FREEZE_VARIABLE} is {clean(value)!r}; it must be exactly true or false, or be unset")


def parse_allowlist(raw: str | None) -> tuple[frozenset[int], str | None]:
    """Parse ``MERGE_FREEZE_ALLOW``. One bad entry discards the list (fail closed)."""
    numbers: set[int] = set()
    for token in re.split(r"[,\s]+", (raw or "").strip()):
        if not token:
            continue
        match = re.fullmatch(r"#?([1-9][0-9]{0,8})", token)
        if match is None:
            return frozenset(), f"{ALLOW_VARIABLE} entry {clean(token, 24)!r} is not a pull request number; ignoring it"
        numbers.add(int(match.group(1)))
    return frozenset(numbers), None


@dataclass(frozen=True)
class Pull:
    number: int
    head_sha: str


@dataclass(frozen=True)
class Verdict:
    blocked: bool
    reason: str


def decide(freeze_raw: str | None, allow_raw: str | None, pull: Pull) -> Verdict:
    """Decide whether the freeze blocks one pull request.

    The only exemption is an admin-set ``MERGE_FREEZE_ALLOW`` entry. Anything a
    pull request author controls, such as a branch name, could be chosen to
    claim an exemption, so none of it is consulted.
    """
    freeze = parse_freeze(freeze_raw)
    if freeze.error is not None:
        return Verdict(True, freeze.error)
    if not freeze.active:
        return Verdict(False, "Merge freeze is not active.")
    allowed, allow_error = parse_allowlist(allow_raw)
    if pull.number in allowed:
        return Verdict(False, f"Pull request #{pull.number} is in {ALLOW_VARIABLE}; exempt from the merge freeze.")
    reason = "Merge freeze active."
    if allow_error is not None:
        reason += f" {allow_error}."
    return Verdict(True, reason)


def lift_command(repository: str) -> str:
    return (
        f"gh variable set {FREEZE_VARIABLE} --body false --repo {repository} "
        f"&& gh workflow run {TOGGLE_WORKFLOW} --repo {repository}"
    )


def freeze_summary(reason: str, repository: str) -> str:
    return (
        "## Merge freeze active\n\n"
        f"{reason}\n\n"
        "This pull request cannot merge until the freeze is lifted. A repository admin lifts it with:\n\n"
        f"    {lift_command(repository)}\n\n"
        f"Deleting the variable (`gh variable delete {FREEZE_VARIABLE} --repo {repository}`) also lifts it. "
        f"To let specific pull requests through, set {ALLOW_VARIABLE} to a comma-separated list of numbers.\n"
    )


# Runs that only ever check a commit already on a protected branch.
_UNGATED_EVENTS = frozenset({"push", "schedule"})

# Maintenance branches CI builds on push, besides the default branch. A
# dispatched run on one of them feeds the release publish workflows. Keep this
# in step with the push branches in ci.yml; a prefix such as release/ would also
# match pull request branches.
_MAINTENANCE_BRANCHES = frozenset({"release/3.0", "release/3.1", "release/3.2"})


def _default_branch_ref(env: Mapping[str, str]) -> str | None:
    try:
        with Path(env.get("GITHUB_EVENT_PATH", "")).open(encoding="utf-8") as handle:
            branch = json.load(handle)["repository"]["default_branch"]
    except (OSError, ValueError, KeyError, TypeError):
        return None
    return f"refs/heads/{branch}" if isinstance(branch, str) and branch else None


def _gate_applies(env: Mapping[str, str]) -> bool:
    event = env.get("EVENT_NAME")
    if event == "pull_request":
        return True
    if event in _UNGATED_EVENTS:
        return False
    # A dispatched run on a pull request branch reports the same required check
    # on the pull request's head commit, so it must not turn green during a
    # freeze. Only a run on the default branch or a maintenance branch is
    # exempt; if the default branch cannot be read, the gate applies.
    ref = env.get("GITHUB_REF")
    if ref is None:
        return True
    if ref.startswith("refs/heads/") and ref.removeprefix("refs/heads/") in _MAINTENANCE_BRANCHES:
        return False
    return ref != _default_branch_ref(env)


def run_gate(env: Mapping[str, str], summary_path: str | None) -> int:
    """Fail the aggregate for a pull request while the freeze is active."""
    if not _gate_applies(env):
        print("Not a pull request run; the merge freeze does not apply.")
        return 0
    repository = env.get("REPOSITORY", "")
    number = env.get("PR_NUMBER", "") if env.get("EVENT_NAME") == "pull_request" else ""
    # A run outside a pull request has no number, so no allowlist entry exempts it.
    pull = Pull(number=int(number) if number.isdecimal() else 0, head_sha="")
    verdict = decide(env.get(FREEZE_VARIABLE), env.get(ALLOW_VARIABLE), pull)
    print(verdict.reason)
    if not verdict.blocked:
        return 0
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as handle:
            handle.write(freeze_summary(verdict.reason, repository))
    print(f"::error title=Merge freeze active::{verdict.reason} Lift it with: {lift_command(repository)}")
    return 1


class ApiError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(f"HTTP {status}: {message}")
        self.status = status


class Api:
    """Minimal GitHub REST client for one repository."""

    def __init__(self, repository: str, token: str, base: str = "https://api.github.com") -> None:
        self.root = f"{base}/repos/{repository}"
        self.token = token

    def call(self, method: str, path: str, body: Mapping[str, Any] | None = None) -> Any:
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(
            f"{self.root}/{path}",
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                payload = response.read()
        except urllib.error.HTTPError as exc:
            raise ApiError(exc.code, exc.read().decode(errors="replace")[:200]) from exc
        return json.loads(payload) if payload else None

    def pages(self, path: str, key: str | None = None) -> list[dict[str, Any]]:
        joiner = "&" if "?" in path else "?"
        items: list[dict[str, Any]] = []
        for page in range(1, MAX_PAGES + 1):
            batch = self.call("GET", f"{path}{joiner}per_page=100&page={page}")
            batch = batch[key] if key else batch
            items.extend(batch)
            if len(batch) < 100:
                return items
        raise ApiError(0, f"more than {MAX_PAGES} pages for {path.split('?')[0]}")


@dataclass
class Outcome:
    number: int
    action: str
    detail: str = ""
    error: bool = False


@dataclass
class Plan:
    outcomes: list[Outcome] = field(default_factory=list)

    @property
    def failed(self) -> bool:
        return any(outcome.error for outcome in self.outcomes)


def _aggregate_path(sha: str, view: str) -> str:
    name = urllib.parse.quote(AGGREGATE_CHECK, safe="")
    return f"commits/{sha}/check-runs?check_name={name}&filter={view}&app_id={ACTIONS_APP_ID}"


def _is_overlay(run: Mapping[str, Any]) -> bool:
    return run.get("external_id") == OVERLAY_EXTERNAL_ID


def _passes(run: Mapping[str, Any]) -> bool:
    return run.get("status") == "completed" and run.get("conclusion") in PASSING_CONCLUSIONS


def _finished_failing(run: Mapping[str, Any]) -> bool:
    return run.get("status") == "completed" and run.get("conclusion") not in PASSING_CONCLUSIONS


def _newest(runs: list[dict[str, Any]]) -> dict[str, Any] | None:
    return max(runs, key=lambda run: (run.get("completed_at") or run.get("started_at") or "", run["id"]), default=None)


def _suite(run: Mapping[str, Any]) -> Any:
    return (run.get("check_suite") or {}).get("id")


def _current(runs: list[dict[str, Any]]) -> tuple[dict[str, Any], ...]:
    """The newest run of each check suite, which is what the required check reads."""
    latest: dict[Any, dict[str, Any]] = {}
    for run in runs:
        held = latest.get(_suite(run))
        if held is None or run["id"] > held["id"]:
            latest[_suite(run)] = run
    return tuple(latest.values())


@dataclass(frozen=True)
class Aggregate:
    """The aggregate check runs on one head commit, read the way GitHub ranks them."""

    runs: tuple[dict[str, Any], ...]
    # The newest run of each check suite. The required check passes only when
    # every one of them passes.
    current: tuple[dict[str, Any], ...]
    # The newest finished run from CI itself, never a freeze check run.
    real: dict[str, Any] | None
    # CI runs still going.
    in_flight: bool

    def failing_overlays(self) -> list[dict[str, Any]]:
        return [run for run in self.current if _is_overlay(run) and _finished_failing(run)]

    def shares_suite_with_ci(self, overlay: Mapping[str, Any]) -> bool:
        return any(not _is_overlay(run) and _suite(run) == _suite(overlay) for run in self.runs)


def _aggregate(api: Api, sha: str) -> Aggregate:
    runs = tuple(api.pages(_aggregate_path(sha, "all"), key="check_runs"))
    real = [run for run in runs if not _is_overlay(run)]
    return Aggregate(
        runs=runs,
        current=_current(list(runs)),
        real=_newest([run for run in real if run.get("status") == "completed"]),
        in_flight=any(run.get("status") != "completed" for run in real),
    )


def _gate_failed(api: Api, job_id: int) -> bool:
    job = api.call("GET", f"actions/jobs/{job_id}")
    return any(
        step.get("name") == GATE_STEP_NAME and step.get("conclusion") == "failure" for step in job.get("steps") or []
    )


IN_FLIGHT_AFTER_LIFT = (
    "lifted the freeze check run; CI is still running, so re-run this workflow if it fails at the merge freeze gate"
)
IN_FLIGHT_WHILE_FROZEN = (
    "CI is still running and could finish green after the freeze took effect; re-run this workflow once it finishes"
)
LIFTED_TITLE = "Merge freeze lifted"
LIFTED_SUMMARY = (
    "The merge freeze was lifted. This check run no longer blocks the pull request; "
    "CI's own `hol-guard / required` result still has to pass."
)


def _hold(api: Api, pull: Pull, reason: str, repository: str, dry_run: bool) -> Outcome:
    aggregate = _aggregate(api, pull.head_sha)
    if any(_finished_failing(run) for run in aggregate.current):
        if aggregate.in_flight:
            return Outcome(pull.number, "held", IN_FLIGHT_WHILE_FROZEN, error=True)
        return Outcome(pull.number, "held", "a current aggregate result already fails")
    if dry_run:
        return Outcome(pull.number, "would block", "post a failing aggregate check run")
    api.call(
        "POST",
        "check-runs",
        {
            "name": AGGREGATE_CHECK,
            "head_sha": pull.head_sha,
            "status": "completed",
            "conclusion": "failure",
            "external_id": OVERLAY_EXTERNAL_ID,
            "output": {"title": "Merge freeze active", "summary": freeze_summary(reason, repository)},
        },
    )
    if not _aggregate(api, pull.head_sha).failing_overlays():
        return Outcome(pull.number, "blocked", "the freeze check run is not among the current results", error=True)
    if aggregate.in_flight:
        return Outcome(pull.number, "blocked", IN_FLIGHT_WHILE_FROZEN, error=True)
    return Outcome(pull.number, "blocked", "posted a failing aggregate check run")


def _rerun(api: Api, pull: Pull, job: Mapping[str, Any]) -> Outcome | None:
    try:
        api.call("POST", f"actions/jobs/{job['id']}/rerun")
    except ApiError as exc:
        # Keep the block: a pull request must never go green on a stale result.
        return Outcome(pull.number, "release failed", f"could not re-run the aggregate ({exc})", error=True)
    return None


def _release(api: Api, pull: Pull, dry_run: bool) -> Outcome:
    aggregate = _aggregate(api, pull.head_sha)
    overlays = aggregate.failing_overlays()
    # CI runs that failed only because the freeze gate saw the flag set. One can
    # sit beside a freeze check run when CI was re-run during the freeze.
    gate_failures = [
        run
        for run in aggregate.current
        if not _is_overlay(run) and _finished_failing(run) and _gate_failed(api, run["id"])
    ]
    if not overlays:
        # A genuine CI failure, a pass, or a run still going needs nothing here.
        if aggregate.in_flight or not gate_failures:
            return Outcome(pull.number, "unchanged", "")
        if dry_run:
            return Outcome(pull.number, "would release", "re-run the aggregate")
        for run in gate_failures:
            failed = _rerun(api, pull, run)
            if failed is not None:
                return failed
        return Outcome(pull.number, "released", "re-ran the aggregate")
    if aggregate.real is None and not aggregate.in_flight:
        # A fork awaiting approval or a pull request whose CI never started
        # stays blocked until CI reports; nothing here may stand in for it.
        return Outcome(pull.number, "waiting", "no CI result yet; the freeze check run stays until CI reports")
    own = [overlay for overlay in overlays if not aggregate.shares_suite_with_ci(overlay)]
    shared = [overlay for overlay in overlays if aggregate.shares_suite_with_ci(overlay)]
    if shared and aggregate.in_flight:
        # The running aggregate reads the lifted flag and its result replaces the
        # freeze check run in their shared suite.
        return Outcome(pull.number, "waiting", "CI is still running; its result replaces the freeze check run")
    if dry_run:
        return Outcome(pull.number, "would release", "lift the freeze check run")
    for overlay in own:
        # Alone in its suite, the freeze check run is the only thing it can
        # block. Marking it neutral leaves CI's runs to decide on their own.
        api.call(
            "PATCH",
            f"check-runs/{overlay['id']}",
            {
                "status": "completed",
                "conclusion": "neutral",
                "output": {"title": LIFTED_TITLE, "summary": LIFTED_SUMMARY},
            },
        )
    rerun_suites: set[int] = set()
    for overlay in shared:
        job = _newest([run for run in aggregate.runs if not _is_overlay(run) and _suite(run) == _suite(overlay)])
        if job is None:
            continue
        failed = _rerun(api, pull, job)
        if failed is not None:
            return failed
        rerun_suites.add(_suite(job))
    for run in gate_failures:
        if _suite(run) in rerun_suites:
            continue
        failed = _rerun(api, pull, run)
        if failed is not None:
            return failed
    if aggregate.in_flight:
        # The running job may already have passed its gate step while frozen.
        return Outcome(pull.number, "released", IN_FLIGHT_AFTER_LIFT)
    return Outcome(pull.number, "released", "lifted the freeze check run")


def reconcile(
    api: Api,
    repository: str,
    freeze_raw: str | None,
    allow_raw: str | None,
    *,
    dry_run: bool = False,
    log: Callable[[str], None] = print,
) -> Plan:
    """Bring every open pull request's aggregate result in line with the flag.

    Check runs belong to a commit, not a pull request, so pull requests that
    share a head commit share one decision: the commit stays blocked while any
    of them is blocked.
    """
    plan = Plan()
    pulls = [Pull(item["number"], item["head"]["sha"]) for item in api.pages("pulls?state=open")]
    blocking: dict[str, Verdict] = {}
    for pull in pulls:
        verdict = decide(freeze_raw, allow_raw, pull)
        if verdict.blocked:
            blocking.setdefault(pull.head_sha, verdict)
    decided: dict[str, Outcome] = {}
    for pull in pulls:
        first = decided.get(pull.head_sha)
        if first is not None:
            outcome = Outcome(pull.number, first.action, f"shares its head commit with #{first.number}", first.error)
        else:
            verdict = blocking.get(pull.head_sha)
            try:
                outcome = (
                    _hold(api, pull, verdict.reason, repository, dry_run)
                    if verdict is not None
                    else _release(api, pull, dry_run)
                )
            except ApiError as exc:
                outcome = Outcome(pull.number, "error", str(exc), error=True)
            decided[pull.head_sha] = outcome
        plan.outcomes.append(outcome)
        if outcome.action != "unchanged":
            log(f"#{outcome.number}: {outcome.action} {outcome.detail}".rstrip())
    return plan


def render_report(plan: Plan, freeze_raw: str | None, repository: str, dry_run: bool) -> str:
    freeze = parse_freeze(freeze_raw)
    state = freeze.error or ("active" if freeze.active else "not active")
    lines = [f"## Merge freeze: {state}" + (" (dry run)" if dry_run else ""), ""]
    counts: dict[str, int] = {}
    for outcome in plan.outcomes:
        counts[outcome.action] = counts.get(outcome.action, 0) + 1
    lines.append(f"Open pull requests evaluated: {len(plan.outcomes)}")
    lines.extend(f"- {action}: {count}" for action, count in sorted(counts.items()))
    problems = [outcome for outcome in plan.outcomes if outcome.error]
    if problems:
        lines += ["", "Needs attention (re-run this workflow to retry):"]
        lines.extend(f"- #{outcome.number}: {outcome.action} - {outcome.detail}" for outcome in problems)
    if freeze.active:
        lines += ["", f"Lift the freeze with: `{lift_command(repository)}`"]
    return "\n".join(lines) + "\n"


def run_reconcile(env: Mapping[str, str], summary_path: str | None, *, dry_run: bool) -> int:
    repository = env["REPOSITORY"]
    api = Api(repository, env["GITHUB_TOKEN"])
    freeze_raw, allow_raw = env.get(FREEZE_VARIABLE), env.get(ALLOW_VARIABLE)
    plan = reconcile(api, repository, freeze_raw, allow_raw, dry_run=dry_run)
    report = render_report(plan, freeze_raw, repository, dry_run)
    print(report)
    if summary_path:
        with Path(summary_path).open("a", encoding="utf-8") as handle:
            handle.write(report)
    return 1 if plan.failed else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("gate", help="fail while the freeze applies to this pull request")
    reconcile_parser = commands.add_parser("reconcile", help="re-evaluate every open pull request")
    reconcile_parser.add_argument("--dry-run", action="store_true", help="report without writing")
    args = parser.parse_args(argv)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if args.command == "gate":
        return run_gate(os.environ, summary)
    return run_reconcile(os.environ, summary, dry_run=args.dry_run)


if __name__ == "__main__":
    sys.exit(main())
