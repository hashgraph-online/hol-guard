from __future__ import annotations

from codex_plugin_scanner.guard.runtime.network_grant_engine import GrantUse, ScopedGrantEngine
from codex_plugin_scanner.guard.runtime.network_policy_contract import (
    Destination,
    DestinationKind,
    NetworkFlowRequest,
    NetworkProtocol,
    ProcessTreeIdentity,
)

_DIGEST = "b" * 64


def _request(*, session_id: str = "session.alpha", port: int = 443) -> NetworkFlowRequest:
    return NetworkFlowRequest(
        request_id=f"request.{session_id}.{port}",
        process_tree=ProcessTreeIdentity("install.alpha", session_id, 42, 100, _DIGEST),
        destination=Destination(DestinationKind.HOST, "api.example.com"),
        protocol=NetworkProtocol.TCP,
        port=port,
        observed_at_epoch_ms=1_000,
    )


def test_one_time_grant_is_exactly_scoped_and_consumed() -> None:
    engine = ScopedGrantEngine()
    request = _request()
    grant = engine.issue(request, expires_at_epoch_ms=2_000)

    assert not engine.authorize(grant.grant_id, request, now_epoch_ms=999)
    assert not engine.authorize(grant.grant_id, _request(port=8443), now_epoch_ms=1_100)
    assert not engine.authorize(grant.grant_id, _request(session_id="session.beta"), now_epoch_ms=1_100)
    assert engine.authorize(grant.grant_id, request, now_epoch_ms=1_000)
    assert not engine.authorize(grant.grant_id, request, now_epoch_ms=1_101)


def test_session_grant_expires_and_revokes_with_process_tree() -> None:
    engine = ScopedGrantEngine()
    request = _request()
    grant = engine.issue(request, expires_at_epoch_ms=2_000, use=GrantUse.SESSION)

    assert engine.authorize(grant.grant_id, request, now_epoch_ms=1_999)
    assert engine.expire(now_epoch_ms=2_000) == 1
    assert not engine.authorize(grant.grant_id, request, now_epoch_ms=2_000)

    replacement = engine.issue(request, expires_at_epoch_ms=3_000, use=GrantUse.SESSION)
    assert engine.revoke_tree(request.process_tree) == 1
    assert not engine.authorize(replacement.grant_id, request, now_epoch_ms=2_100)
