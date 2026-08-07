from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.runtime.network_local_core import logical_flow_id
from codex_plugin_scanner.guard.runtime.network_observer import project_network_observation
from codex_plugin_scanner.guard.runtime.network_policy_contract import (
    Destination,
    DestinationKind,
    EnforcementGrade,
    NetworkAction,
    NetworkEvidence,
    NetworkFlowRequest,
    NetworkProtocol,
    ProcessTreeIdentity,
    canonical_digest,
)

_DIGEST = "a" * 64


def _request() -> NetworkFlowRequest:
    return NetworkFlowRequest(
        request_id="request.alpha",
        process_tree=ProcessTreeIdentity("install.alpha", "session.alpha", 42, 100, _DIGEST),
        destination=Destination(DestinationKind.HOST, "api.example.com"),
        protocol=NetworkProtocol.TCP,
        port=443,
        observed_at_epoch_ms=1_000,
    )


def _evidence(request: NetworkFlowRequest) -> NetworkEvidence:
    return NetworkEvidence(
        flow_id=logical_flow_id(request),
        process_tree_digest=request.process_tree.digest,
        destination_digest=canonical_digest(request.destination),
        protocol=request.protocol,
        port=request.port,
        action=NetworkAction.DENY,
        policy_digest=_DIGEST,
        backend_digest=_DIGEST,
        grade=EnforcementGrade.DESTINATION_ENFORCED,
        observed_at_epoch_ms=request.observed_at_epoch_ms,
    )


def test_observer_projects_privacy_safe_flow_without_claiming_enforcement() -> None:
    request = _request()

    observation = project_network_observation(request)

    assert observation.flow_id == logical_flow_id(request)
    assert observation.destination_digest == canonical_digest(request.destination)
    assert observation.process_tree_digest == request.process_tree.digest
    assert not observation.enforcement_observed
    assert observation.enforced_action is None
    assert observation.enforcement_grade is EnforcementGrade.OBSERVE
    assert "example.com" not in repr(observation)


def test_observer_reports_only_matching_enforcement_evidence() -> None:
    request = _request()
    observation = project_network_observation(request, enforcement=_evidence(request))

    assert observation.enforcement_observed
    assert observation.enforced_action is NetworkAction.DENY
    assert observation.enforcement_grade is EnforcementGrade.DESTINATION_ENFORCED

    mismatched = _evidence(
        NetworkFlowRequest(
            request_id="request.beta",
            process_tree=request.process_tree,
            destination=request.destination,
            protocol=request.protocol,
            port=8443,
            observed_at_epoch_ms=request.observed_at_epoch_ms,
        )
    )
    with pytest.raises(ValueError, match="does not describe"):
        _ = project_network_observation(request, enforcement=mismatched)
