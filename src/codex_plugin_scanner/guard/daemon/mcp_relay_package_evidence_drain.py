"""Record the receipt of a package call the native relay decided.

A relayed ``tools/call`` the resident answers through its package lane leaves a
different receipt from a plain tool call: ``_record_package_block``
(``runtime_mcp.py:2327``) and ``_record_package_forward`` (:2025) write the
block and allow receipts against the *package request's* artifact and the
approval-context token that request hashed to, with the evaluation's reason
signals and the package scanner evidence. The tool legs of the same lane are
recorded as the plain tool-policy blocks they are, so they keep the
``mcp_tool_call`` record :mod:`mcp_relay_evidence_drain` writes.

The resident cannot ship the artifact itself -- ``GuardArtifact.to_dict``
redacts args, url and metadata, and a receipt written from redacted fields is
not the receipt the proxy writes. So its record names the artifact by id and
carries the workspace the intent was parsed against, and the artifact is
rebuilt here from the same parser input the resident read
(``_package_request_artifact``). A record whose rebuilt artifact is not the one
the resident decided is dropped, never recorded against a different package.

That parser input includes the ``PATH`` the intent was resolved under, which
decides the manager a command names. This runs in the daemon, whose own
``PATH`` is not the relaying proxy's, so the record carries the proxy's and the
parse here binds it. A record naming none is dropped: the resident parsed that
call with no search path at all, and ``_resident_environment`` has no way to
ask for the same.

A request the package policy wants reviewed is answered by the proxy's bound
blocked-request mode. Under ``safe-alternative`` the resident blocks it in
place, and its record carries the receipt redaction level the silent inbox row
is written with, as a relayed tool call's does. It is recorded as
``_queue_package_approval_response`` records that branch: the
``policy-safe-alternative`` block receipt against the package artifact, with
the risk categories of the call projected with it, and then the inbox row
``record_unprompted_review`` leaves.

Under ``ask`` the resident writes the package-shaped approval request itself
and blocks the call on it, so its record carries that request's surface rather
than an inbox row. The ``ask`` branch of ``_queue_package_approval_response``
leaves the ``approval-center-pending`` block receipt against the package
artifact and nothing else: it projects the call without the artifact and so
records no risk categories, and it writes no unprompted review. What is left
for the drain is the desktop notice and the approval center the proxy raises
once the row is written, which is best effort there and here.

Under ``mode = "observe"`` the call is forwarded under the action the policies
would have *executed* and the requests the enforced actions would have blocked
it on are queued beside it (``_queue_observed_approval_requests``, :3365). That
forward's receipt is the ordinary allow receipt, recorded under ``policy-observe``
rather than the action's own source, so its record names that source and carries
the desktop notices those rows raised. There is no approval center to open for
them: nothing is waiting on an answer, because the call already reached the
child.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .mcp_relay_evidence_drain import (
    _APPROVAL_KEY,
    _APPROVAL_PENDING_SOURCE,
    _BLOCK_SOURCE,
    _FORWARD_ACTIONS,
    _NOTICE_KEYS,
    _RELAY_HARNESSES,
    _SAFE_ALTERNATIVE_SOURCE,
    _decision,
    _ordered_params,
    _queued_approval,
    _raise_approval_surface,
    _raise_notices,
    _record_unprompted_review,
    _redaction_level,
)

MCP_PACKAGE_CALL_EVIDENCE_KIND = "mcp_package_call"
_RECORD_KEYS = frozenset(
    {
        "kind",
        "harness",
        "outcome",
        "decision_source",
        "policy_action",
        "tool_name",
        "params",
        "arguments",
        "identity",
        "decision",
        "package",
    }
)
# The package facts the receipt is written from. `path` is always stated, as
# `null` when the relay parsed under none. `policy_workspace` is bound only by
# the allow receipt, so only a forward's record carries it.
_PACKAGE_KEYS = frozenset(
    {
        "artifact_id",
        "artifact_hash",
        "workspace",
        "path",
        "evaluation",
        "evidence",
        "signals",
    }
)
_POLICY_WORKSPACE_KEY = "policy_workspace"
# The silent inbox row, present only on a safe-alternative block's record.
_REVIEW_KEY = "review"
# The observed approval requests, present only on an observed forward's record.
_OBSERVED_KEY = "observed"
_OPTIONAL_KEYS = frozenset({_REVIEW_KEY, _APPROVAL_KEY, _OBSERVED_KEY})
# `decision_source="policy-observe"`: the source an observed forward is
# recorded under, which names the mode rather than the action it forwarded with.
_OBSERVE_SOURCE = "policy-observe"


def is_mcp_relay_package_evidence(record: object) -> bool:
    return isinstance(record, Mapping) and record.get("kind") == MCP_PACKAGE_CALL_EVIDENCE_KIND


def record_mcp_relay_package_evidence(store: object, guard_home: Path, record: object) -> bool:
    """Record one relayed package call as the proxy records it."""

    from ..mcp_tool_calls import allow_tool_call, block_tool_call
    from ..native_mcp_tool_call_identity import _decode  # pyright: ignore[reportPrivateUsage]
    from ..proxy.runtime_mcp_projection import McpCallProjector
    from ..tool_decision_evidence import tool_decision_scanner_evidence

    if not isinstance(record, Mapping) or set(record) - _OPTIONAL_KEYS != _RECORD_KEYS:
        return False
    harness, outcome = record["harness"], record["outcome"]
    source, policy_action = record["decision_source"], record["policy_action"]
    tool_name, params = record["tool_name"], record["params"]
    package = record["package"]
    if (
        record["kind"] != MCP_PACKAGE_CALL_EVIDENCE_KIND
        or not isinstance(harness, str)
        or harness not in _RELAY_HARNESSES
        or not isinstance(source, str)
        or not isinstance(policy_action, str)
        or not isinstance(tool_name, str)
        or not isinstance(params, dict)
        or params.get("name") != tool_name
    ):
        return False
    # Only a safe-alternative queued request carries its inbox row, and it must.
    reviewed = _REVIEW_KEY in record
    redaction_level = _redaction_level(record[_REVIEW_KEY]) if reviewed else None
    if reviewed and redaction_level is None:
        return False
    # Only an ask queued request carries the approval request it was written
    # on, which answers the call instead of the inbox row the other mode adds.
    queued = _queued_approval(record[_APPROVAL_KEY]) if _APPROVAL_KEY in record else None
    if _APPROVAL_KEY in record and (queued is None or reviewed):
        return False
    # Only an observed forward carries the rows the enforced policy would have
    # blocked it on, and it must: the record states that list even when both
    # policies permitted the call and queued nothing.
    observed = _observed_notices(record[_OBSERVED_KEY]) if _OBSERVED_KEY in record else None
    if _OBSERVED_KEY in record and (observed is None or reviewed or queued is not None):
        return False
    forwarded = outcome == "forward"
    if forwarded:
        # The proxy forwards under the action it permitted the call with, and
        # records the receipt under that same action. Observe mode forwards
        # under the action it would have executed and records the mode itself.
        permitted_source = _OBSERVE_SOURCE if observed is not None else f"policy-{policy_action}"
        if reviewed or queued is not None or policy_action not in _FORWARD_ACTIONS or source != permitted_source:
            return False
    elif (
        outcome != "block"
        or observed is not None
        or policy_action in _FORWARD_ACTIONS
        or source != _block_source(reviewed, queued)
    ):
        return False
    facts = _package_facts(package, forwarded=forwarded)
    if facts is None:
        return False
    try:
        identity = _decode(record["identity"], expect_hash=True, token=True)
        decision = _decision(record["decision"])
        ordered = _ordered_params(params, record["arguments"])
        if identity.artifact.harness != harness:
            return False
        artifact = _package_artifact(
            harness=harness,
            tool_name=tool_name,
            arguments=ordered.get("arguments"),
            workspace=Path(facts["workspace"]),
            path=facts["path"],
            guard_home=guard_home,
            config_path=identity.artifact.config_path,
            source_scope=identity.artifact.source_scope,
        )
        # The resident decided one package request; a parse that rebuilds
        # another one is not that request's receipt.
        if artifact is None or artifact.artifact_id != facts["artifact_id"]:
            return False
        scanner_evidence = (*tool_decision_scanner_evidence(decision), *facts["evidence"])
        # `_queue_approval_center_response` projects a queued call with its
        # artifact; `_record_package_{block,forward}` and the `ask` branch of
        # `_queue_package_approval_response` project it without one.
        projector = McpCallProjector(guard_home)
        projection = (
            projector.project(tool_name, ordered, artifact)
            if redaction_level is not None
            else projector.project(tool_name, ordered)
        )
        recorded: dict[str, Any] = {
            "store": store,
            "artifact": artifact,
            "artifact_hash": facts["artifact_hash"],
            "decision_source": source,
            "now": datetime.now(timezone.utc).isoformat(),
            "signals": facts["signals"],
            "arguments": projection.safe_arguments,
            "additional_scanner_evidence": scanner_evidence,
            "policy_action": policy_action,
        }
        if redaction_level is not None:
            # Only that projection carries risk categories to record.
            recorded["risk_categories"] = projection.risk_categories
        if forwarded:
            # `_record_package_forward`: the allow receipt alone, since the
            # relay never spends a saved approval and so remembers nothing.
            allow_tool_call(
                remember=False,
                policy_workspace=facts[_POLICY_WORKSPACE_KEY],
                **recorded,
            )
        else:
            # `_record_package_block`: no risk categories and no policy
            # workspace, as the proxy writes it. A queued request is recorded
            # by `_queue_approval_center_response` instead, which projects the
            # call with its artifact and so does carry risk categories.
            block_tool_call(**recorded)
        if queued is not None:
            # After the receipt, as the proxy raises it: the request is
            # written and the call is already blocked on it, so the notice
            # and the approval center are best effort.
            _raise_approval_surface(store, guard_home, harness, queued)
        if observed:
            # `_queue_observed_approval_requests` queues with the `notify=True`
            # its queue takes by default and nothing else: the call is
            # forwarded rather than blocked on these rows, so there is no
            # approval center to open for them.
            _raise_notices(store, observed)
        if redaction_level is not None:
            # After the receipt, as the proxy writes it.
            _record_unprompted_review(
                store,
                artifact,
                facts["artifact_hash"],
                projection,
                facts["signals"],
                policy_action=policy_action,
                scanner_evidence=scanner_evidence,
                redaction_level=redaction_level,
            )
    except Exception:
        # A record the proxy could not have written is dropped, never guessed.
        return False
    return True


def _observed_notices(observed: object) -> tuple[dict[str, Any], ...] | None:
    """The desktop notices the observed approval requests raised, or ``None``.

    An observation that queued no row states the empty list, so the absence of
    a notice is not the absence of the key: a forward that carries neither is
    not the record the resident writes under this mode.
    """

    if not isinstance(observed, Mapping) or set(observed) != {"notices"}:
        return None
    notices = observed["notices"]
    if not isinstance(notices, list) or not all(
        isinstance(notice, dict) and set(notice) == _NOTICE_KEYS for notice in notices
    ):
        return None
    return tuple(notices)


def _block_source(reviewed: bool, queued: object) -> str:
    """The decision source this block receipt's queue route is recorded under."""

    if queued is not None:
        return _APPROVAL_PENDING_SOURCE
    return _SAFE_ALTERNATIVE_SOURCE if reviewed else _BLOCK_SOURCE


def _package_facts(package: object, *, forwarded: bool) -> dict[str, Any] | None:
    """The package half of the record, or ``None`` when it is not the proxy's."""

    if not isinstance(package, Mapping):
        return None
    keys = set(package)
    workspace_bound = _POLICY_WORKSPACE_KEY in keys
    if keys - {_POLICY_WORKSPACE_KEY} != _PACKAGE_KEYS or workspace_bound != forwarded:
        return None
    artifact_id, artifact_hash = package["artifact_id"], package["artifact_hash"]
    workspace, evaluation = package["workspace"], package["evaluation"]
    path = package["path"]
    evidence, signals = package["evidence"], package["signals"]
    policy_workspace = package.get(_POLICY_WORKSPACE_KEY)
    if (
        not isinstance(artifact_id, str)
        or not isinstance(artifact_hash, str)
        or not isinstance(workspace, str)
        or not isinstance(path, (str, type(None)))
        or not isinstance(evaluation, dict)
        or not isinstance(evidence, list)
        or not all(isinstance(item, dict) for item in evidence)
        or not isinstance(signals, list)
        or not all(isinstance(item, str) for item in signals)
        or not isinstance(policy_workspace, (str, type(None)))
        or not all(field.strip() for field in (artifact_id, artifact_hash, workspace))
        or (path is not None and not path.strip())
    ):
        return None
    return {
        "artifact_id": artifact_id,
        "artifact_hash": artifact_hash,
        "workspace": workspace,
        "path": path,
        "evaluation": evaluation,
        "evidence": tuple(evidence),
        "signals": tuple(signals),
        _POLICY_WORKSPACE_KEY: policy_workspace,
    }


def _package_artifact(
    *,
    harness: str,
    tool_name: str,
    arguments: object,
    workspace: Path,
    path: str | None,
    guard_home: Path,
    config_path: str,
    source_scope: str,
) -> Any | None:
    """``_package_request_artifact`` for the call the record carries.

    ``path`` is the relay's own search path, bound here so the resident
    resolves the command's manager exactly as it did for the decision. A relay
    that ran without a ``PATH`` states ``None``, and the gate resolved that call
    under no bound environment at all, which the resident reads as its own
    (``normalized_command_segments`` falls back to the process environment, as
    the Python baseline fell back to ``os.environ``). Stating no environment
    here reproduces that: ``_resident_environment`` binds the ambient ``PATH``,
    which is the one the resident was spawned with. Binding an empty ``PATH``
    instead would resolve the manager against the workspace alone, an execution
    context the decision never had, and the ``artifact_id`` check below drops
    whatever the two sides disagree on.
    """

    from ..proxy.runtime_mcp import _command_argument  # pyright: ignore[reportPrivateUsage]
    from ..runtime.package_intent_common import build_package_request_artifact
    from ..runtime.package_intent_parser import extract_package_intent_request

    intent = extract_package_intent_request(
        tool_name,
        arguments,
        action_envelope_command=_command_argument(arguments),
        workspace=workspace,
        guard_home=guard_home,
        environment=None if path is None else {"PATH": path},
    )
    if intent is None:
        return None
    return build_package_request_artifact(
        harness=harness,
        intent=intent,
        config_path=config_path,
        source_scope=source_scope,
        guard_home=guard_home,
    )
