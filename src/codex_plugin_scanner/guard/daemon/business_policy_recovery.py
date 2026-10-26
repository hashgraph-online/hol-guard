"""Fresh human recovery of the exact stored business policy, without request replay."""

from dataclasses import replace

from ..approval_gate import ApprovalGateError, ApprovalGateInput, require_high_risk
from ..approval_gate import input_from_mapping as approval_gate_input_from_mapping
from ..business_policy_document_import import has_business_rules
from ..mcp.policy_errors import PolicyToolError
from ..mcp.policy_store import MCPolicyRequestRepository
from ..mcp.policy_tools import _check_feature_flags
from ..native_business_source_recovery import recover_committed_business_source
from ..native_policy_snapshot_constants import NativePolicySnapshotError
from ..policy_document import policy_document_digest
from ..policy_document_authority import policy_import_approval_binding
from ..policy_document_yaml import parse_policy_document_yaml


def handle_business_policy_recovery(handler, request_id, payload):
    from .mcp_policy_decisions import _write_source_error

    store = handler.server.store
    request = MCPolicyRequestRepository(store).get_request(request_id)
    if (
        request is None
        or request.status == "declined"
        or request.mode != "replace"
        or payload.get("candidateDigest") != request.policy_document_digest
    ):
        _unavailable(handler)
        return
    try:
        document = parse_policy_document_yaml(request.canonical_policy_yaml)
        if not has_business_rules(document) or policy_document_digest(document) != request.policy_document_digest:
            _unavailable(handler)
            return
        if payload.get("action") == "inspect-recovery":
            from .business_policy_recovery_inspection import inspect_business_policy_recovery

            handler._write_json(inspect_business_policy_recovery(store, request, document))
            return
        _check_feature_flags()
        grant = require_high_risk(
            store.guard_home,
            purpose="policy_import",
            **policy_import_approval_binding(document, "replace"),
            approval_gate_input=replace(
                approval_gate_input_from_mapping(payload) or ApprovalGateInput(),
                use_cooldown=False,
                require_fresh_totp=True,
            ),
        )
        from ..mcp.policy_recovery_state import stage_request_recovery

        source = recover_committed_business_source(
            store,
            document,
            approval_gate_grant=grant,
            stage_request_recovery=lambda connection, digest, now: stage_request_recovery(
                connection, request_id, digest, now
            ),
        )
    except ApprovalGateError as error:
        handler._write_approval_gate_error(error)
        return
    except (NativePolicySnapshotError, TimeoutError) as error:
        _write_source_error(handler, error)
        return
    except PolicyToolError as error:
        if error.code in {"policy_import_disabled", "mcp_policy_write_disabled"}:
            handler._write_json({"error": error.code}, status=403)
            return
        _unavailable(handler)
        return
    except ValueError:
        _unavailable(handler)
        return
    # Recovery is a new policy import, not resolution/replay of an old request.
    handler._write_json(
        {
            "installationRecovered": True,
            "requestId": request_id,
            "sourceDigest": source.source_digest,
            "message": "Policy installation recovered. No app action was sent or replayed.",
        }
    )


def _unavailable(handler):
    handler._write_json(
        {
            "installationRecovered": False,
            "error": "business_source_recovery_candidate_unavailable",
            "message": "This request has no recoverable business policy. Review the current policy before continuing.",
        },
        status=409,
    )
