"""Process-tree-bound, expiring grants for approved network flows."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import cast

from codex_plugin_scanner.guard.runtime.network_local_core import logical_flow_id
from codex_plugin_scanner.guard.runtime.network_policy_contract import (
    Destination,
    NetworkFlowRequest,
    NetworkProtocol,
    ProcessTreeIdentity,
    canonical_digest,
    require_digest,
    require_id,
)


class GrantUse(str, Enum):
    ONCE = "once"
    SESSION = "session"


@dataclass(frozen=True, slots=True)
class ScopedNetworkGrant:
    grant_id: str
    process_tree_digest: str
    session_id: str
    destination: Destination
    protocol: NetworkProtocol
    port: int
    issued_at_epoch_ms: int
    expires_at_epoch_ms: int
    use: GrantUse

    def __post_init__(self) -> None:
        require_id(self.grant_id, "grant_id")
        require_digest(self.process_tree_digest, "process_tree_digest")
        require_id(self.session_id, "session_id")
        if type(self.port) is not int or not 1 <= self.port <= 65_535:
            raise ValueError("port must be within 1..65535")
        if type(self.issued_at_epoch_ms) is not int or self.issued_at_epoch_ms <= 0:
            raise ValueError("issued_at_epoch_ms must be positive")
        if type(self.expires_at_epoch_ms) is not int or self.expires_at_epoch_ms <= self.issued_at_epoch_ms:
            raise ValueError("expires_at_epoch_ms must follow issue time")
        if not isinstance(cast(object, self.use), GrantUse):
            raise ValueError("use must be exact")

    @property
    def digest(self) -> str:
        return canonical_digest(self)


class ScopedGrantEngine:
    """In-memory grant authority; grants never cross process-tree sessions."""

    def __init__(self) -> None:
        self._grants: dict[str, ScopedNetworkGrant] = {}

    def issue(
        self,
        request: NetworkFlowRequest,
        *,
        expires_at_epoch_ms: int,
        use: GrantUse = GrantUse.ONCE,
    ) -> ScopedNetworkGrant:
        if expires_at_epoch_ms <= request.observed_at_epoch_ms:
            raise ValueError("grant must expire after its request")
        identity = {
            "flow": logical_flow_id(request),
            "request": request.request_id,
            "expires_at_epoch_ms": expires_at_epoch_ms,
            "use": use,
        }
        grant = ScopedNetworkGrant(
            grant_id=f"grant.{canonical_digest(identity)[:32]}",
            process_tree_digest=request.process_tree.digest,
            session_id=request.process_tree.session_id,
            destination=request.destination,
            protocol=request.protocol,
            issued_at_epoch_ms=request.observed_at_epoch_ms,
            port=request.port,
            expires_at_epoch_ms=expires_at_epoch_ms,
            use=use,
        )
        self._grants[grant.grant_id] = grant
        return grant

    def authorize(self, grant_id: str, request: NetworkFlowRequest, *, now_epoch_ms: int) -> bool:
        grant = self._grants.get(grant_id)
        if grant is None:
            return False
        if now_epoch_ms < grant.issued_at_epoch_ms:
            return False
        if now_epoch_ms >= grant.expires_at_epoch_ms:
            del self._grants[grant_id]
            return False
        matches = (
            grant.process_tree_digest == request.process_tree.digest
            and grant.session_id == request.process_tree.session_id
            and grant.destination == request.destination
            and grant.protocol is request.protocol
            and grant.port == request.port
        )
        if matches and grant.use is GrantUse.ONCE:
            del self._grants[grant_id]
        return matches

    def revoke_tree(self, process_tree: ProcessTreeIdentity) -> int:
        doomed = [
            grant_id for grant_id, grant in self._grants.items() if grant.process_tree_digest == process_tree.digest
        ]
        for grant_id in doomed:
            del self._grants[grant_id]
        return len(doomed)

    def expire(self, *, now_epoch_ms: int) -> int:
        doomed = [grant_id for grant_id, grant in self._grants.items() if now_epoch_ms >= grant.expires_at_epoch_ms]
        for grant_id in doomed:
            del self._grants[grant_id]
        return len(doomed)
