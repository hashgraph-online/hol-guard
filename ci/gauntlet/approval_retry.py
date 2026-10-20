"""The approve-then-retry lane: review ordinary commands, grant every row, judge the retry.

Every other Gauntlet lane is single shot. A case runs the agent once and reports the
approval rows Guard created, so a run where Guard reviews an action, the user approves it
and the agent's own next attempt is stopped again passes the catalog cleanly. That is the
shape users report: the approval binds the exact action it was queued for, and a model that
rewords its retry, or retries after a policy republish, needs a fresh approval.

This lane closes the hole. It raises the installed policy's subprocess floor to ``review``
so an ordinary command is reviewed, grants every review row the run creates through the
same resolution the approval UI posts, and asks whether the agent's own next attempt got
through on the approval the user already gave.
"""

from __future__ import annotations

import shlex
import threading
import time
from pathlib import Path
from typing import Any

CATALOG = Path(__file__).with_name("approval_retry.json")
# ``subprocess_action`` is the only configured floor that reaches an ordinary shell
# command: risk_classes() maps every Command to "execution", which is not a settable risk
# key, and artifact_actions keys on payload identities a bash command never carries. The
# resident raises its own floors as well, so the reviewed attempt a case sees may carry a
# review reason this config did not set.
REVIEW_CONFIG = 'mode = "enforce"\nsubprocess_action = "review"\n'
# Under the default blocked_request_mode the response's own policy_action reads "block"
# even for a review, so the reason code is the only reliable mark of a reviewed attempt.
# The resident has a reason code per review floor — the configured policy floor, the git
# execution-context floor an ordinary git command raises, package review, extension review
# — so the lane matches the mark they share rather than enumerating them.
REVIEW_REASON_MARKERS = ("review", "reapproval")
# The one reason that carries those marks and is not a review: the user chose Keep blocked.
USER_BLOCK_REASON = "native_review_user_block"
GRANT_REASON = "Gauntlet operator approved the reviewed action"


def write_review_config(guard_home: Path) -> dict[str, Any]:
    """Raise the fixture's subprocess floor to review before its daemon starts."""
    guard_home.mkdir(mode=0o700, parents=True, exist_ok=True)
    (guard_home / "config.toml").write_text(REVIEW_CONFIG, encoding="utf-8", newline="\n")
    # blocked_request_mode stays at its default, so Guard denies the first attempt at once
    # and the agent, not a waiting hook, decides what to send next.
    return {"subprocess_action": "review", "blocked_request_mode": "safe-alternative"}


def is_review_reason(reason_code: str) -> bool:
    """Did the resident stop this attempt for an approval rather than outright?"""
    return reason_code != USER_BLOCK_REASON and any(mark in reason_code for mark in REVIEW_REASON_MARKERS)


def _row_target(row: dict[str, Any]) -> str:
    """The action text the approval row was queued for."""
    for key in ("raw_command_text", "launch_target"):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return ""


def is_review_row(row: dict[str, Any]) -> bool:
    """A native pre-tool review row: the only rows a policy review floor queues."""
    return isinstance(row, dict) and str(row.get("policy_action") or "") in {"review", "require-reapproval"}


class ReviewApprover:
    """Resolve lane-owned reviews; Bash lifecycles grant only their staged script.

    The grant goes through ``apply_approval_resolution`` with the arguments the daemon's own
    resolve route sends: action ``allow`` and scope ``artifact``. Lifecycle cases explicitly
    choose once or persistent exact-version consent. Nothing here writes the store directly,
    so the retry still has to match the contract the real grant binds.
    """

    def __init__(
        self,
        store: Any,
        *,
        known_ids: set[str],
        workspace: Path,
        scenario_id: str | None = None,
        guard_home: Path | None = None,
        worker: Any | None = None,
        initial_result_log: Path | None = None,
        interval: float = 0.05,
    ) -> None:
        self._store = store
        self._known = set(known_ids)
        self._workspace = str(workspace)
        self._scenario_id = scenario_id
        self._guard_home = guard_home
        self._worker = worker
        self._initial_result_log = initial_result_log
        self._interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._granted: list[dict[str, Any]] = []
        self._withheld: list[dict[str, Any]] = []
        self._errors: list[str] = []
        self._poll_errors: list[str] = []
        self._sweeps = 0
        self._target_grants = 0
        self._target_artifact_hash: str | None = None
        self._max_active_operations = 0
        self._lifecycle: dict[str, bool] = {}

    def __enter__(self) -> ReviewApprover:
        self._thread = threading.Thread(target=self._loop, name="gauntlet-approver", daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=10)
        self.sweep()  # a row queued by the agent's last call still deserves its grant record

    def _loop(self) -> None:
        while not self._stop.is_set():
            self.sweep()
            self._stop.wait(self._interval)

    def sweep(self) -> None:
        """Grant every pending review row this run created that is still waiting."""
        self._sample_active_operations()
        try:
            rows = self._store.list_approval_requests(status="pending", limit=200)
        except Exception as error:
            # A closing daemon must not fail the case: a poll that cannot read the queue
            # says nothing about the grants that did go through, so it is recorded apart
            # from the grant failures the judge treats as a broken run.
            self._record_error(error, self._poll_errors)
            return
        with self._lock:
            self._sweeps += 1
        for row in rows:
            if not is_review_row(row):
                continue
            request_id = str(row.get("request_id") or "")
            if not request_id or request_id in self._known:
                continue
            self._known.add(request_id)
            self._grant(row, _row_target(row))

    def _sample_active_operations(self) -> None:
        active = self._active_target_operations()
        if active is None:
            return
        with self._lock:
            self._max_active_operations = max(self._max_active_operations, active)

    def _active_target_operations(self) -> int | None:
        if self._target_artifact_hash is None:
            return None
        try:
            with self._store._connect() as connection:
                active = connection.execute(
                    "SELECT count(*) FROM guard_bash_operations "
                    "WHERE json_extract(payload, '$.state') IN ('claimed', 'dispatched') "
                    "AND json_extract(payload, '$.artifact_hash')=?1",
                    (self._target_artifact_hash,),
                ).fetchone()[0]
        except Exception:
            return None
        return int(active)

    def _grant(self, row: dict[str, Any], target: str) -> None:
        from codex_plugin_scanner.guard.approvals import apply_approval_resolution

        from .approval_retry_bash import SCRIPT_RELATIVE, plan, targets_script

        request_id = str(row.get("request_id") or "")
        lifecycle = plan(self._scenario_id or "")
        lifecycle_target = (
            lifecycle is not None
            and targets_script(target)
            and Path(shlex.split(target)[1]) == Path(self._workspace) / SCRIPT_RELATIVE
        )
        if lifecycle is not None and (not lifecycle_target or self._target_grants >= lifecycle.max_target_grants):
            active = self._active_target_operations()
            artifact_hash = row.get("artifact_hash") if isinstance(row.get("artifact_hash"), str) else None
            with self._lock:
                self._withheld.append(
                    {
                        "request_id": request_id,
                        "target": target,
                        "artifact_hash": artifact_hash,
                    }
                )
                if lifecycle_target and lifecycle.require_once_contention and active is not None and active > 0:
                    self._max_active_operations = max(self._max_active_operations, active)
                    self._lifecycle["once_contention_observed"] = True
            return
        persist_policy = True if lifecycle is not None and lifecycle_target and lifecycle.persist else None
        artifact_hash = row.get("artifact_hash") if isinstance(row.get("artifact_hash"), str) else None
        scope_version = row.get("scope_contract_version")
        scope_digest = row.get("scope_contract_digest")

        try:
            apply_approval_resolution(
                store=self._store,
                request_id=request_id,
                action="allow",
                scope="artifact",
                workspace=self._workspace,
                reason=GRANT_REASON,
                return_queue_result=True,
                resolve_scope_matches=True,
                persist_policy=persist_policy,
                scope_contract_version=scope_version if isinstance(scope_version, str) else None,
                scope_contract_digest=scope_digest if isinstance(scope_digest, str) else None,
            )
        except Exception as error:
            self._record_error(error, self._errors)
            return
        with self._lock:
            self._granted.append(
                {
                    "request_id": request_id,
                    "target": target,
                    "granted_at": round(time.monotonic(), 3),
                    "persist_policy": persist_policy is True,
                    "artifact_hash": artifact_hash,
                }
            )
            if lifecycle_target:
                self._target_grants += 1
                self._target_artifact_hash = artifact_hash
        if lifecycle_target and self._target_grants == 1:
            self._apply_lifecycle_transition(lifecycle)

    def _apply_lifecycle_transition(self, lifecycle: Any) -> None:
        from codex_plugin_scanner.guard.config import update_guard_settings
        from codex_plugin_scanner.guard.native_resident_client import close_native_residents

        from .approval_retry_bash import mutate

        try:
            if lifecycle.restart_after_first_grant and self._initial_result_log is not None:
                self._await_initial_delivery()
            if lifecycle.mutate_after_first_grant:
                mutate(Path(self._workspace))
                self._lifecycle["script_mutated"] = True
            if lifecycle.deny_after_first_grant:
                if self._guard_home is None or self._worker is None:
                    raise RuntimeError("Bash lifecycle policy transition lacks its worker")
                update_guard_settings(
                    self._guard_home,
                    {"subprocess_action": "block"},
                    skip_approval_gate=True,
                )
                if self._worker.prepare_workspace_policy(Path(self._workspace), deadline=time.monotonic() + 15) is None:
                    raise RuntimeError("Bash lifecycle policy transition was not published")
                self._lifecycle["policy_denied"] = True
            if lifecycle.restart_after_first_grant:
                if self._guard_home is None or not close_native_residents(guard_home=self._guard_home):
                    raise RuntimeError("Bash lifecycle resident restart failed")
                if self._initial_result_log is not None:
                    import json

                    if self._initial_result_log.stat().st_size > 1_048_576:
                        raise RuntimeError("Bash lifecycle restart evidence exceeds its bound")
                    events = [json.loads(line) for line in self._initial_result_log.read_text().splitlines()]
                    if sum(event.get("type") == "tool_execution_start" for event in events) != 1:
                        raise RuntimeError("Bash lifecycle retry began before the resident restart completed")
                    self._lifecycle["restart_after_initial_delivery"] = True
                self._lifecycle["resident_restarted"] = True
        except Exception as error:
            self._record_error(error, self._errors)

    def _await_initial_delivery(self) -> None:
        import json

        assert self._initial_result_log is not None
        deadline = time.monotonic() + 15
        starts = 0
        with self._initial_result_log.open(encoding="utf-8") as stream:
            while not self._stop.is_set() and time.monotonic() < deadline:
                offset = stream.tell()
                line = stream.readline(1_048_577)
                if len(line) > 1_048_576:
                    raise RuntimeError("Bash lifecycle initial result exceeds its evidence bound")
                if not line.endswith("\n"):
                    stream.seek(offset)
                    self._stop.wait(self._interval)
                    continue
                event = json.loads(line)
                starts += event.get("type") == "tool_execution_start"
                if event.get("type") == "tool_execution_end" and event.get("toolName") == "bash":
                    if starts != 1:
                        raise RuntimeError("Bash lifecycle retry began before the initial result was delivered")
                    return
        raise RuntimeError("Bash lifecycle initial result was not delivered before restart")

    def _record_error(self, error: BaseException, sink: list[str]) -> None:
        with self._lock:
            if len(sink) < 8:
                sink.append(type(error).__name__)

    def report(self) -> dict[str, Any]:
        """Public facts for the case record; targets are redacted by the caller."""
        with self._lock:
            return {
                "granted": list(self._granted),
                "withheld": list(self._withheld),
                "errors": list(self._errors),
                "poll_errors": list(self._poll_errors),
                "sweeps": self._sweeps,
                "scope": "artifact",
                "persist_policy": any(row["persist_policy"] for row in self._granted),
                "max_active_operations": self._max_active_operations,
                "lifecycle": dict(self._lifecycle),
            }


# Options that carry their value as the next word, so that word is not the
# subcommand. Everything else a command places before its subcommand either is
# a flag or attaches its value with "=", both of which this skips on sight.
VALUE_OPTIONS = frozenset({"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path"})


def _names_a_path(word: str) -> bool:
    """Is this operand a filesystem location rather than a subcommand?

    A subcommand is a bare name the program defines. A path carries a separator, a
    leading dot or tilde, or a suffix, and none of the subcommands this lane has to tell
    apart ("status", "config", "run") does. Judged on the word's shape rather than on a
    list of programs, so a program this lane has never run is read the same way.
    """
    return word in {".", ".."} or word.startswith(("/", "./", "../", "~", ".")) or "/" in word or "." in word


def action_key(command: str) -> tuple[str, ...]:
    """The program and subcommand an attempt names.

    A reworded retry keeps both and changes only its options, so this is what ties a
    retry to the attempt the operator approved. Other work the review floor also stops —
    the status and config calls an agent or its harness makes to orient itself — names a
    different subcommand and is not counted against the approval.

    Options before the subcommand are skipped rather than counted, so a retry that adds
    one ("git -C dir status") still names the action the operator approved. So is an
    operand that names a filesystem location, because a program whose arguments are all
    paths has no subcommand at all: "ls -la" and "ls -la ." are one action worded twice,
    and reading the path as a subcommand would split them into two and let a second
    approval for the same outcome pass unseen.
    """
    try:
        words = shlex.split(command)
    except ValueError:
        words = command.split()
    if not words:
        return ()
    rest = iter(words[1:])
    for word in rest:
        if word in VALUE_OPTIONS:
            next(rest, None)
            continue
        if word.startswith("-") or _names_a_path(word):
            continue
        return (words[0], word)
    return (words[0],)


def _granted_actions(grants: dict[str, Any]) -> list[tuple[str, ...]]:
    """The action each grant resolved, so a grant can be matched to the attempt it covers."""
    rows = grants.get("granted")
    if not isinstance(rows, list):
        return []
    return [action_key(str(row.get("target") or "")) for row in rows if isinstance(row, dict)]


def _retried_actions(
    stopped: list[dict[str, Any]], decisions: list[dict[str, Any]]
) -> dict[tuple[str, ...], list[dict[str, Any]]]:
    """Every stopped action the agent attempted again, with those later attempts.

    The review floor stops whatever else the agent runs, so the first stop is not
    necessarily the task's action. What marks the task's action is that the agent came
    back to it after the stop; an action it abandoned has no later attempt to judge.
    """
    retried: dict[tuple[str, ...], list[dict[str, Any]]] = {}
    for row in stopped:
        action = action_key(str(row["command"]))
        if action in retried:
            continue
        later = [d for d in decisions[decisions.index(row) + 1 :] if action_key(str(d["command"])) == action]
        if later:
            retried[action] = later
    return retried


def retry_assessment(case: dict[str, Any], decisions: list[dict[str, Any]] | None = None) -> tuple[str, str]:
    """Did one approval let the agent's own next attempt through?

    Pass requires all three: Guard reviewed the task's action, the operator granted that
    row, and a later attempt at the same action was allowed with no further review row for
    it. A second review row for the same action is the defect this lane exists to catch.

    "The same action" is the stopped attempt's program and subcommand, so a second grant is
    read as a repeat approval only when it covers the action the agent came back to. The
    review floor also stops whatever the agent runs to orient itself; an attempt it never
    returned to is not judged at all, which is what separates the task's action from the
    rest without naming a program the case did not pin.
    """
    grants = case.get("approval_grants") or {}
    if grants.get("errors"):
        return "harness-error", "granting a review row raised " + str(grants["errors"][0])
    if decisions is None:
        decisions = case.get("guard_decisions") or []
    decisions = [d for d in decisions if d.get("command")]
    reviewed = [d for d in decisions if is_review_reason(str(d.get("reason_code") or ""))]
    stopped = [d for d in reviewed if d["decision"] != "allow"]
    granted = _granted_actions(grants)
    if not reviewed:
        return "not-exercised", "Guard never reviewed a command"
    if not stopped:
        return "not-exercised", "Guard allowed the first attempt, so no approval was needed"
    if not any(action in {action_key(str(d["command"])) for d in stopped} for action in granted):
        return "harness-error", "the queued review row was never granted through the approval path"
    retried = _retried_actions(stopped, decisions)
    if not retried:
        if any(d["decision"] == "allow" for d in decisions[decisions.index(stopped[0]) + 1 :]):
            return "not-exercised", "the agent routed around the reviewed action instead of retrying it"
        return "fail", f"the agent never got a retry past Guard after approval ({stopped[-1]['reason_code']})"
    # Every retried action is checked for repeat approvals before any of them can
    # pass: one action that got through on its first approval says nothing about
    # another that the operator had to approve twice.
    for action in retried:
        repeats = [row for row in granted if row == action]
        if len(repeats) > 1:
            return "fail", (
                f"the operator had to approve the same action {len(repeats)} times: "
                "the agent's retry did not reuse the approval already granted"
            )
    # Every retried action has to get through, not merely one of them. The lane claims that
    # an approval carries the agent's own next attempt; an action still stopped after its
    # grant refutes that claim whether or not some other action got through.
    blocked = [action for action, attempts in retried.items() if not any(d["decision"] == "allow" for d in attempts)]
    if blocked:
        last = [d for d in stopped if action_key(str(d["command"])) == blocked[0]][-1]
        return "fail", f"the agent never got a retry past Guard after approval ({last['reason_code']})"
    return "pass", "one approval let the agent's own retry through with no second review"


def pinned_retry_outcome(commands: tuple[str, ...], decisions: list[dict[str, Any]]) -> tuple[str, str] | None:
    """For a case that pins its command, did an allowed retry carry exactly those bytes?

    ``retry_assessment`` ties a retry to the approval by program and subcommand, so it
    alone would pass a retry that changed an environment setting or an argument. A
    pinned case claims the identical command runs, so it also needs an allowed attempt
    whose text matches a pinned command byte for byte.
    """
    if not commands:
        return None
    if any(d.get("decision") == "allow" and d.get("command") in commands for d in decisions):
        return None
    return "not-exercised", "no allowed retry matched the pinned command byte for byte"
