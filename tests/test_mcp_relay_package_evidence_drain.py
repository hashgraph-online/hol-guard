from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard.daemon import hook_direct_evidence_drain
from codex_plugin_scanner.guard.daemon.mcp_relay_package_evidence_drain import (
    is_mcp_relay_package_evidence,
    record_mcp_relay_package_evidence,
)

from .mcp_relay_package_evidence_support import (
    ARTIFACT_ID,
    COMMAND,
    CONFIG_PATH,
    EVIDENCE,
    PATH,
    SOURCE_SCOPE,
    TOKEN,
    WORKSPACE,
    _decision,
    _package,
    _Projector,
    _record,
    _reviewed,
    calls,
    parsed,
    reviews,
)

__all__ = ["calls", "parsed", "reviews"]


def test_only_a_package_record_is_this_drains() -> None:
    assert is_mcp_relay_package_evidence(_record())
    assert not is_mcp_relay_package_evidence({"kind": "mcp_tool_call"})
    assert not is_mcp_relay_package_evidence("mcp_package_call")


def test_a_forward_is_recorded_against_the_package_artifact(
    tmp_path: Path, calls: list[tuple[str, dict[str, Any]]], parsed: dict[str, Any]
) -> None:
    store = object()

    assert record_mcp_relay_package_evidence(store, tmp_path, _record())

    [(kind, recorded)] = calls
    assert kind == "allow"
    assert recorded["store"] is store
    # The package request, rebuilt from the same parser input the resident read.
    assert recorded["artifact"].artifact_id == ARTIFACT_ID
    assert recorded["artifact_hash"] == TOKEN
    assert recorded["remember"] is False
    assert recorded["decision_source"] == "policy-warn"
    assert recorded["policy_action"] == "warn"
    assert recorded["policy_workspace"] == WORKSPACE
    # The evaluation's reason signals, not the tool decision's.
    assert recorded["signals"] == ("left-pad has an advisory",)
    assert recorded["arguments"] == {"safe": True, "artifact": False}
    assert recorded["additional_scanner_evidence"] == tuple(EVIDENCE)
    # `_record_package_forward` passes no risk categories of its own.
    assert "risk_categories" not in recorded
    [(tool_name, params, artifact)] = _Projector.projected
    assert tool_name == "shell" and artifact is None
    # The host's own key order, which the proxy projects the call from.
    assert isinstance(params, dict) and list(params["arguments"]) == ["cwd", "command"]


def test_the_artifact_is_rebuilt_from_the_recorded_call(
    tmp_path: Path, calls: list[tuple[str, dict[str, Any]]], parsed: dict[str, Any]
) -> None:
    assert record_mcp_relay_package_evidence(object(), tmp_path, _record())

    [(tool_name, arguments, kwargs)] = parsed["extract"]
    assert tool_name == "shell"
    # The arguments in host key order, and the command the action envelope names.
    assert list(arguments) == ["cwd", "command"]
    assert kwargs["action_envelope_command"] == COMMAND
    # The workspace and search path the resident decided against, not the
    # daemon's own.
    assert kwargs["workspace"] == Path("/work")
    assert kwargs["environment"] == {"PATH": PATH}
    assert kwargs["guard_home"] == tmp_path
    # The scope and config path the call's own identity states.
    assert parsed["build"] == [("codex", parsed["intent"], CONFIG_PATH, SOURCE_SCOPE)]


def test_a_call_the_relay_decided_without_a_search_path_is_still_recorded(
    tmp_path: Path, calls: list[tuple[str, dict[str, Any]]], parsed: dict[str, Any]
) -> None:
    """The gate states an absent ``PATH`` as ``None``; the rebuild binds none either."""

    assert record_mcp_relay_package_evidence(object(), tmp_path, _record(package=_package(path=None)))

    [(_, _, kwargs)] = parsed["extract"]
    assert kwargs["environment"] is None
    [(kind, _)] = calls
    assert kind == "allow"


def test_a_search_path_the_relay_could_not_have_written_is_dropped(tmp_path: Path) -> None:
    """An empty string is neither a path nor the absence the gate states."""

    assert not record_mcp_relay_package_evidence(object(), tmp_path, _record(package=_package(path="")))


def test_a_block_is_recorded_without_a_policy_workspace(
    tmp_path: Path, calls: list[tuple[str, dict[str, Any]]], parsed: dict[str, Any]
) -> None:
    package = _package()
    del package["policy_workspace"]
    record = _record(
        outcome="block",
        decision_source="policy-block",
        policy_action="block",
        decision=_decision("block"),
        package=package,
    )

    assert record_mcp_relay_package_evidence(object(), tmp_path, record)

    [(kind, recorded)] = calls
    assert kind == "block"
    assert recorded["artifact"].artifact_id == ARTIFACT_ID
    assert recorded["policy_action"] == "block"
    # `_record_package_block` binds no workspace and no risk categories.
    assert "policy_workspace" not in recorded
    assert "risk_categories" not in recorded


def test_a_queued_request_is_blocked_in_place_and_left_in_the_inbox(
    tmp_path: Path,
    calls: list[tuple[str, dict[str, Any]]],
    parsed: dict[str, Any],
    reviews: list[dict[str, Any]],
) -> None:
    store = object()

    assert record_mcp_relay_package_evidence(store, tmp_path, _reviewed())

    [(kind, recorded)] = calls
    assert kind == "block"
    assert recorded["decision_source"] == "policy-safe-alternative"
    assert recorded["policy_action"] == "review"
    # `_queue_approval_center_response` projects the call with its artifact,
    # so the receipt carries that projection's risk categories and arguments.
    assert recorded["risk_categories"] == ["supply-chain"]
    assert recorded["arguments"] == {"safe": True, "artifact": True}
    assert "policy_workspace" not in recorded
    # The inbox row follows the receipt, written with the bound level.
    [review] = reviews
    assert review["store"] is store
    assert review["artifact"] is recorded["artifact"]
    assert review["artifact_hash"] == TOKEN
    assert review["signals"] == ("left-pad has an advisory",)
    assert review["policy_action"] == "review"
    assert review["redaction_level"] == "partial"
    assert review["scanner_evidence"] == recorded["additional_scanner_evidence"]
    assert review["projection"].risk_categories == ["supply-chain"]


@pytest.mark.parametrize(
    "fields",
    [
        # A level the proxy never writes a receipt with.
        {"review": {"redaction_level": "summary"}},
        {"review": {"redaction_level": None}},
        # The row is the level alone.
        {"review": {"redaction_level": "full", "extra": True}},
        {"review": "full"},
        # Only the safe-alternative branch leaves a row.
        {"decision_source": "policy-block", "policy_action": "block"},
    ],
)
def test_an_inbox_row_the_proxy_could_not_have_written_is_dropped(
    tmp_path: Path,
    calls: list[tuple[str, dict[str, Any]]],
    parsed: dict[str, Any],
    reviews: list[dict[str, Any]],
    fields: dict[str, object],
) -> None:
    assert not record_mcp_relay_package_evidence(object(), tmp_path, _reviewed(**fields))
    assert calls == [] and reviews == []


def test_a_receipt_recorded_without_its_inbox_row_is_dropped(
    tmp_path: Path,
    calls: list[tuple[str, dict[str, Any]]],
    parsed: dict[str, Any],
    reviews: list[dict[str, Any]],
) -> None:
    # A block the lane answers through the queue route always leaves the row.
    record = _reviewed()
    del record["review"]

    assert not record_mcp_relay_package_evidence(object(), tmp_path, record)
    # A forward never leaves one.
    assert not record_mcp_relay_package_evidence(object(), tmp_path, _record(review={"redaction_level": "full"}))
    assert calls == [] and reviews == []


def test_a_record_naming_another_package_is_dropped(
    tmp_path: Path, calls: list[tuple[str, dict[str, Any]]], parsed: dict[str, Any]
) -> None:
    # The resident decided one package request; a parse of these arguments that
    # rebuilds a different one is not that request's receipt.
    parsed["artifact_id"] = "package-request:npm:right-pad"

    assert not record_mcp_relay_package_evidence(object(), tmp_path, _record())
    assert calls == []


def test_a_call_that_is_no_package_request_is_dropped(
    tmp_path: Path, calls: list[tuple[str, dict[str, Any]]], parsed: dict[str, Any]
) -> None:
    parsed["intent"] = None

    assert not record_mcp_relay_package_evidence(object(), tmp_path, _record())
    assert calls == []


def test_arguments_the_record_does_not_match_are_dropped(
    tmp_path: Path, calls: list[tuple[str, dict[str, Any]]], parsed: dict[str, Any]
) -> None:
    # `_ordered_params` rejects host entries that are not the params' arguments.
    record = _record(arguments={"format": "mapping", "entries": [["command", "npm install right-pad"]]})

    assert not record_mcp_relay_package_evidence(object(), tmp_path, record)
    assert calls == []


@pytest.mark.parametrize(
    "fields",
    [
        # A forward under an action the proxy never forwards on.
        {"policy_action": "block", "decision_source": "policy-block"},
        # A forward whose source is not the action it was permitted under.
        {"decision_source": "policy-allow"},
        # A block that still claims a forwarding action.
        {"outcome": "block", "decision_source": "policy-block", "policy_action": "warn"},
        # A block recorded under a source the package lane never answers with.
        {"outcome": "block", "decision_source": "inline-denied", "policy_action": "block"},
        # An outcome the lane never answers with.
        {"outcome": "deferred"},
        # A harness the relay does not serve.
        {"harness": "claude-code"},
        # Params that are not the call the record names.
        {"params": {"name": "install", "arguments": {"command": COMMAND}}},
        # A record that is not the shape the resident writes.
        {"kind": "mcp_tool_call"},
        {"remember": True},
    ],
)
def test_a_record_the_proxy_could_not_have_written_is_dropped(
    tmp_path: Path, calls: list[tuple[str, dict[str, Any]]], parsed: dict[str, Any], fields: dict[str, object]
) -> None:
    assert not record_mcp_relay_package_evidence(object(), tmp_path, _record(**fields))
    assert calls == []


@pytest.mark.parametrize(
    "mutate",
    [
        # A forward must state the workspace its allow is bound to.
        lambda package: package.pop("policy_workspace"),
        # The package half is the receipt's facts, all of them.
        lambda package: package.pop("artifact_hash"),
        lambda package: package.update(extra=True),
        lambda package: package.update(signals=[{"message": "not a string"}]),
        lambda package: package.update(evidence=[["not", "a", "mapping"]]),
        lambda package: package.update(evaluation="warn"),
        lambda package: package.update(workspace="  "),
        lambda package: package.update(path="  "),
        lambda package: package.pop("path"),
    ],
)
def test_a_package_half_the_proxy_could_not_have_written_is_dropped(
    tmp_path: Path, calls: list[tuple[str, dict[str, Any]]], parsed: dict[str, Any], mutate: Any
) -> None:
    package = _package()
    mutate(package)

    assert not record_mcp_relay_package_evidence(object(), tmp_path, _record(package=package))
    assert calls == []


def test_the_direct_drain_routes_a_package_record_here(
    tmp_path: Path, calls: list[tuple[str, dict[str, Any]]], parsed: dict[str, Any]
) -> None:
    store = object()
    host = SimpleNamespace(store=store, guard_home=tmp_path)

    assert hook_direct_evidence_drain.record_direct_hook_evidence(host, _record())

    [(kind, recorded)] = calls
    assert kind == "allow"
    assert recorded["store"] is store
    assert recorded["artifact"].artifact_id == ARTIFACT_ID
