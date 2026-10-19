"""Controller-owned approval mediation over an authoritative World transaction.

The permissive provider baseline remains World.call. This adapter supports mail
send, calendar invite, persisted chat-draft post, document permission changes,
and record updates. It derives scope from persisted state, never model approval
assertions. The controller alone provisions the ledger, anchor and policy ID.
"""

from __future__ import annotations

import copy
import json

from .approval import ApprovalError, ApprovalLedger, ClaimResult, validate_request, verify_grant
from .contracts import canonical_json, digest
from .world import COLLECTIONS, World


class ApprovedWorld:
    def __init__(self, world: World, ledger: ApprovalLedger, *, policy_version: str, clock=None):
        if world.path != ledger.database_path:
            raise ApprovalError("world and approval ledger must share one transaction database")
        if type(policy_version) is not str or not policy_version or len(policy_version) > 512:
            raise ApprovalError("invalid trusted policy version")
        self.world = world
        self.ledger = ledger
        self.policy_version = policy_version
        if clock is not None and not callable(clock):
            raise ApprovalError('trusted controller clock must be callable')
        self._clock = clock

    def request_for(self, operation: str, args: dict) -> dict:
        """Trusted controller builder for a grant over the current persisted state."""
        with self.world._connection() as connection:
            request, _ = self._derive(connection, operation, args)
            return request

    def call(self, operation: str, args: dict, *, operation_id: str, grant: dict, now: int) -> ClaimResult:
        """Validate freshly derived scope and commit effect/journal/claim atomically.

        A retry returns its cached receipt even though its first commit advanced
        state; it performs no second mutation. Changed operation arguments cannot
        inherit that cache entry. Unknown model actor/state/recipient overrides
        fail before entering the transaction.
        """
        args = self._arguments(operation, args)
        if type(operation_id) is not str or not operation_id or len(operation_id) > 128:
            raise ApprovalError("invalid controller operation ID")
        if type(grant) is not dict or type(grant.get("record")) is not dict:
            raise ApprovalError("missing signed controller approval")
        signed_request = grant["record"].get("request")
        # Anchor and expiry are checked before any transaction callback. A signed
        # request is only used to address a cache; new effects rederive it below.
        verified = verify_grant(grant, signed_request, trusted_public_key=self.ledger.trusted_public_key, now=now)
        if verified["max_uses"] != 1:
            raise ApprovalError("world effects require an exact single-use approval")
        intent = digest({"operation": operation, "args": args, "operation_id": operation_id})
        ledger_id = "world-" + intent

        def commit(connection):
            current, provider_args = self._derive(connection, operation, args)
            verify_grant(grant, current, trusted_public_key=self.ledger.trusted_public_key, now=now)
            result = self.world.execute_on_connection(connection, operation, provider_args, operation_id)
            journal = connection.execute("SELECT value FROM journal ORDER BY sequence DESC LIMIT 1").fetchone()
            return {
                "operation_id": operation_id,
                "intent_digest": intent,
                "result": result,
                "world_receipt": json.loads(journal[0]),
            }

        return self.ledger.execute(grant, signed_request, operation_id=ledger_id, now=now,
                                   effect=commit, clock=self._clock)

    @staticmethod
    def _arguments(operation: str, args: dict) -> dict:
        canonical_json(args)
        if type(operation) is not str or type(args) is not dict:
            raise ApprovalError("invalid world approval operation/arguments")
        family, _, method = operation.partition(".")
        if family not in COLLECTIONS:
            raise ApprovalError("unknown approval service")
        common = {"record_id", "expected_version"}
        if operation in {"mail.send", "calendar.invite"}:
            required, allowed = common, common
        elif operation == "chat.post":
            required, allowed = common | {"draft_id"}, common | {"draft_id"}
        elif operation == "docs.set_permissions":
            required, allowed = common | {"permissions"}, common | {"permissions", "visibility"}
        elif method == "update":
            required, allowed = common | {"data"}, common | {"data"}
        else:
            raise ApprovalError("unsupported consequential approval operation")
        if not required.issubset(args) or not set(args).issubset(allowed):
            raise ApprovalError("missing or unknown approved operation arguments")
        if type(args["record_id"]) is not str or not args["record_id"]:
            raise ApprovalError("record_id must be a string")
        if type(args["expected_version"]) is not int or args["expected_version"] < 1:
            raise ApprovalError("expected_version must be a positive integer")
        return copy.deepcopy(args)

    def _derive(self, connection, operation, args):
        args = self._arguments(operation, args)
        family, _, _method = operation.partition(".")
        record_id = args["draft_id"] if operation == "chat.post" else args["record_id"]
        before = self.world._record(connection, record_id, family, "write")
        if before["version"] != args["expected_version"]:
            raise ApprovalError("stale authoritative record version")
        targets = [record_id]
        states = {record_id: str(before["version"])}
        recipients = []
        provider_args = copy.deepcopy(args)
        if operation == "mail.send":
            if before["collection"] != "mail.drafts":
                raise ApprovalError("approved send requires a persisted draft")
            recipients = before["data"].get("recipients", [])
            if not recipients:
                raise ApprovalError("approved draft has no persisted recipients")
        elif operation == "calendar.invite":
            if before["collection"] != "calendar.events":
                raise ApprovalError("approved invitation requires a persisted event")
            recipients = before["data"].get("attendees", [])
            if not recipients:
                raise ApprovalError("approved invitation has no persisted attendees")
        elif operation == "chat.post":
            if before["collection"] != "chat.drafts":
                raise ApprovalError("approved post requires a persisted chat draft")
            if connection.execute("SELECT 1 FROM records WHERE id=?", (args["record_id"],)).fetchone():
                raise ApprovalError("post target already exists")
            channel = before["data"].get("channel_id")
            if type(channel) is not str or not channel:
                raise ApprovalError("approved post requires a persisted channel target")
            targets.extend([args["record_id"], channel])
            states[args["record_id"]] = "absent"
            provider_args = {
                "record_id": args["record_id"],
                "tenant_id": before["tenant_id"],
                "data": copy.deepcopy(before["data"]),
            }
        elif operation == "docs.set_permissions":
            permissions = args["permissions"]
            if type(permissions) is not list or len(permissions) > 256:
                raise ApprovalError("permissions must be a bounded list")
            for permission in permissions:
                principal = (
                    permission
                    if type(permission) is str
                    else permission.get("principal_id")
                    if type(permission) is dict
                    else None
                )
                if type(principal) is not str or not principal:
                    raise ApprovalError("permission must bind a principal")
                if principal not in targets:
                    targets.append(principal)
        payload = {
            "tenant_id": before["tenant_id"],
            "owner_id": before["owner_id"],
            "persisted_data": before["data"],
            "persisted_acl": before["acl"],
            "provider_args": provider_args,
        }
        return validate_request(
            {
                "actor": self.world.actor,
                "operation": operation,
                "target_ids": targets,
                "recipients": recipients,
                "payload_digest": digest(payload),
                "policy_version": self.policy_version,
                "state_versions": states,
            }
        ), provider_args
