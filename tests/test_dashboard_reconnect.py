"""Focused security regressions for authenticated dashboard reconnect."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import cast

import pytest

from ci.guard_daemon_harness import GuardDaemonServer
from codex_plugin_scanner.guard.daemon.dashboard_reconnect import (
    DASHBOARD_RECONNECT_CHALLENGE_TTL_SECONDS,
    consume_dashboard_reconnect_challenge,
    issue_dashboard_reconnect_challenge,
    prepare_dashboard_reconnect_authorization,
)
from codex_plugin_scanner.guard.daemon.discovery import (
    daemon_discovery_key_path,
    ensure_daemon_discovery_key,
)
from codex_plugin_scanner.guard.local_dashboard_session import build_local_dashboard_session_token
from codex_plugin_scanner.guard.store import GuardStore


def _store(tmp_path: Path) -> GuardStore:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    return GuardStore(guard_home)


def _post_json(
    daemon: GuardDaemonServer,
    path: str,
    payload: dict[str, object],
    *,
    dashboard_session: str | None = None,
    origin: str | None = None,
) -> tuple[int, dict[str, object]]:
    headers = {"Content-Type": "application/json"}
    if dashboard_session is not None:
        headers["X-Guard-Dashboard-Session"] = dashboard_session
    if origin is not None:
        headers["Origin"] = origin
    request = urllib.request.Request(
        f"http://127.0.0.1:{daemon.port}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            body = json.loads(response.read().decode("utf-8"))
            assert isinstance(body, dict)
            return response.status, body
    except urllib.error.HTTPError as error:
        body = json.loads(error.read().decode("utf-8"))
        assert isinstance(body, dict)
        return error.code, body


def _prepare(daemon: GuardDaemonServer) -> dict[str, object]:
    dashboard_session = build_local_dashboard_session_token(
        auth_token=daemon._server.auth_token,
        surface="dashboard",
    )
    status, payload = _post_json(
        daemon,
        "/v1/update/reconnect/prepare",
        {},
        dashboard_session=dashboard_session,
        origin=f"http://127.0.0.1:{daemon.port}",
    )
    assert status == 200
    return payload


def _challenge(
    daemon: GuardDaemonServer,
    authorization: dict[str, object],
    *,
    client_nonce: str = "55" * 32,
    candidate_origin: str | None = None,
) -> tuple[int, dict[str, object]]:
    origin = candidate_origin or f"http://127.0.0.1:{daemon.port}"
    return _post_json(
        daemon,
        "/v1/update/reconnect/challenge",
        {
            "protocol_version": 1,
            "reconnect_id": authorization["reconnect_id"],
            "client_nonce": client_nonce,
            "candidate_origin": origin,
        },
        origin=origin,
    )


def _challenge_without_proof(payload: dict[str, object]) -> dict[str, object]:
    return {key: value for key, value in payload.items() if key != "proof"}


def dashboard_reconnect_proof(verifier: str, proof_context: str, challenge: dict[str, object]) -> str:
    # The proof the browser computes; the native runtime's cross-language
    # fixture pins the same bytes.
    payload = json.dumps(
        {"proof_context": proof_context, **challenge}, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    return hmac.new(bytes.fromhex(verifier), payload.encode("utf-8"), hashlib.sha256).hexdigest()


def test_dashboard_reconnect_survives_restart_and_consumes_each_proof_once(tmp_path: Path) -> None:
    store = _store(tmp_path)
    original = GuardDaemonServer(store, host="127.0.0.1", port=0)
    original.start()
    try:
        authorization = _prepare(original)
    finally:
        original.stop()

    restart_deadline = time.monotonic() + 30.0
    while True:
        try:
            restarted = GuardDaemonServer(store, host="127.0.0.1", port=0)
            break
        except RuntimeError as error:
            if (
                str(error) != "A previous Guard daemon remains quarantined after unconfirmed containment."
                or time.monotonic() >= restart_deadline
            ):
                raise
            time.sleep(0.05)
    restarted.start()
    try:
        status, challenge_payload = _challenge(restarted, authorization)
        assert status == 200
        challenge = _challenge_without_proof(challenge_payload)
        verifier = cast(str, authorization["verifier"])
        assert challenge_payload["proof"] == dashboard_reconnect_proof(verifier, "server", challenge)
        client_proof = dashboard_reconnect_proof(verifier, "client", challenge)

        verified_status, verified = _post_json(
            restarted,
            "/v1/update/reconnect/verify",
            {"protocol_version": 1, "challenge": challenge, "proof": client_proof},
            origin=f"http://127.0.0.1:{restarted.port}",
        )
        replay_status, replay = _post_json(
            restarted,
            "/v1/update/reconnect/verify",
            {"protocol_version": 1, "challenge": challenge, "proof": client_proof},
            origin=f"http://127.0.0.1:{restarted.port}",
        )
        variant_challenge: dict[str, object] = {
            **challenge,
            "reconnect_id": challenge["reconnect_id"].upper(),
            "ignored": "replay-cache-bypass",
        }
        variant_replay_status, variant_replay = _post_json(
            restarted,
            "/v1/update/reconnect/verify",
            {"protocol_version": 1, "challenge": variant_challenge, "proof": client_proof},
            origin=f"http://127.0.0.1:{restarted.port}",
        )
    finally:
        restarted.stop()

    assert verified_status == 200
    assert verified == {"verified": True, "reason_code": "dashboard_reconnect_proof_accepted"}
    assert replay_status == 404
    assert replay["error"] == "daemon_candidate_unavailable"
    assert replay["reason_code"] == "dashboard_reconnect_proof_replayed"
    assert variant_replay_status == 404
    assert variant_replay["reason_code"] == "dashboard_reconnect_proof_replayed"


def test_dashboard_reconnect_prepare_requires_an_authenticated_dashboard_session(tmp_path: Path) -> None:
    daemon = GuardDaemonServer(_store(tmp_path), host="127.0.0.1", port=0)
    daemon.start()
    try:
        status, payload = _post_json(
            daemon,
            "/v1/update/reconnect/prepare",
            {},
            origin=f"http://127.0.0.1:{daemon.port}",
        )
    finally:
        daemon.stop()

    assert status == 401
    assert payload["error"] == "unauthorized"


def test_dashboard_reconnect_proofs_allow_the_approved_hosted_dashboard_origin(tmp_path: Path) -> None:
    daemon = GuardDaemonServer(_store(tmp_path), host="127.0.0.1", port=0)
    daemon.start()
    try:
        authorization = _prepare(daemon)
        candidate_origin = f"http://127.0.0.1:{daemon.port}"
        status, challenge_payload = _post_json(
            daemon,
            "/v1/update/reconnect/challenge",
            {
                "protocol_version": 1,
                "reconnect_id": authorization["reconnect_id"],
                "client_nonce": "55" * 32,
                "candidate_origin": candidate_origin,
            },
            origin="https://hol.org",
        )
        assert status == 200
        challenge = _challenge_without_proof(challenge_payload)
        proof = dashboard_reconnect_proof(cast(str, authorization["verifier"]), "client", challenge)
        verified_status, verified = _post_json(
            daemon,
            "/v1/update/reconnect/verify",
            {"protocol_version": 1, "challenge": challenge, "proof": proof},
            origin="https://hol.org",
        )
    finally:
        daemon.stop()

    assert verified_status == 200
    assert verified["verified"] is True


def test_dashboard_reconnect_rejects_wrong_proof_without_exposing_verifier(tmp_path: Path) -> None:
    daemon = GuardDaemonServer(_store(tmp_path), host="127.0.0.1", port=0)
    daemon.start()
    try:
        authorization = _prepare(daemon)
        status, challenge_payload = _challenge(daemon, authorization)
        assert status == 200
        challenge = _challenge_without_proof(challenge_payload)
        rejected_status, rejected = _post_json(
            daemon,
            "/v1/update/reconnect/verify",
            {"protocol_version": 1, "challenge": challenge, "proof": "00" * 32},
            origin=f"http://127.0.0.1:{daemon.port}",
        )
    finally:
        daemon.stop()

    assert rejected_status == 404
    assert rejected == {
        "error": "daemon_candidate_unavailable",
        "reason_code": "dashboard_reconnect_proof_invalid",
    }
    serialized = json.dumps(rejected)
    assert authorization["verifier"] not in serialized
    assert daemon._server.auth_token not in serialized


@pytest.mark.parametrize(
    "candidate_origin",
    (
        "http://localhost:4781",
        "http://127.1:4781",
        "http://2130706433:4781",
        "https://127.0.0.1:4781",
        "http://user@127.0.0.1:4781",
        "http://127.0.0.1:4781/path",
        "http://127.0.0.1:4781/#fragment",
    ),
)
def test_dashboard_reconnect_rejects_ambiguous_or_non_origin_candidates(
    tmp_path: Path,
    candidate_origin: str,
) -> None:
    daemon = GuardDaemonServer(_store(tmp_path), host="127.0.0.1", port=0)
    daemon.start()
    try:
        authorization = _prepare(daemon)
        status, payload = _challenge(
            daemon,
            authorization,
            candidate_origin=candidate_origin,
        )
    finally:
        daemon.stop()

    assert status in {403, 404}
    assert payload["error"] in {"forbidden_origin", "daemon_candidate_unavailable"}


def test_dashboard_reconnect_rejects_expiry_wrong_state_and_previous_installation(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    ensure_daemon_discovery_key(guard_home)
    authorization = prepare_dashboard_reconnect_authorization(guard_home, now_ms=1_000)
    challenge_payload, reason = issue_dashboard_reconnect_challenge(
        guard_home,
        reconnect_id=authorization["reconnect_id"],
        client_nonce="66" * 32,
        candidate_origin="http://127.0.0.1:4781",
        state_id="new-state",
        now_ms=2_000,
    )
    assert reason == "dashboard_reconnect_challenge_issued"
    assert challenge_payload is not None
    malformed_challenge, malformed_reason = issue_dashboard_reconnect_challenge(
        guard_home,
        reconnect_id=authorization["reconnect_id"],
        client_nonce="not-a-nonce",
        candidate_origin="http://127.0.0.1:4781",
        state_id="new-state",
        now_ms=2_000,
    )
    challenge = _challenge_without_proof(challenge_payload)
    verifier = cast(str, authorization["verifier"])
    client_proof = dashboard_reconnect_proof(verifier, "client", challenge)

    wrong_state, wrong_state_reason = consume_dashboard_reconnect_challenge(
        guard_home,
        challenge=challenge,
        proof=client_proof,
        expected_candidate_origin="http://127.0.0.1:4781",
        expected_state_id="other-state",
        now_ms=2_001,
    )
    expired, expired_reason = consume_dashboard_reconnect_challenge(
        guard_home,
        challenge=challenge,
        proof=client_proof,
        expected_candidate_origin="http://127.0.0.1:4781",
        expected_state_id="new-state",
        now_ms=2_000 + DASHBOARD_RECONNECT_CHALLENGE_TTL_SECONDS * 1_000 + 1,
    )
    key_path = daemon_discovery_key_path(guard_home)
    key_path.write_text("77" * 32, encoding="ascii")
    if os.name != "nt":
        key_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    previous_install_challenge, previous_install_reason = issue_dashboard_reconnect_challenge(
        guard_home,
        reconnect_id=authorization["reconnect_id"],
        client_nonce="88" * 32,
        candidate_origin="http://127.0.0.1:4781",
        state_id="replacement-state",
        now_ms=2_002,
    )

    assert wrong_state is False
    assert wrong_state_reason == "dashboard_reconnect_proof_context_mismatch"
    assert expired is False
    assert expired_reason == "dashboard_reconnect_proof_expired"
    assert previous_install_challenge is None
    assert previous_install_reason == "dashboard_reconnect_authorization_unavailable"
    assert malformed_challenge is None
    assert malformed_reason == "dashboard_reconnect_malformed_challenge"


def test_dashboard_reconnect_authorization_file_is_private_and_contains_no_verifier(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    ensure_daemon_discovery_key(guard_home)
    authorization = prepare_dashboard_reconnect_authorization(guard_home)
    state_path = guard_home / "dashboard-reconnect-authorizations.json"
    contents = state_path.read_text(encoding="utf-8")

    assert cast(str, authorization["verifier"]) not in contents
    if os.name != "nt":
        assert stat.S_IMODE(state_path.stat().st_mode) == 0o600


def test_dashboard_reconnect_identity_reports_a_native_outage_as_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard import native_runner_authority as authority
    from codex_plugin_scanner.guard.daemon.dashboard_reconnect import dashboard_reconnect_challenge_identity

    def unavailable(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise authority.NativeRunnerAuthorityError("native_runner_authority_unavailable")

    monkeypatch.setattr(authority, "native_runner_authority", unavailable)
    assert dashboard_reconnect_challenge_identity(tmp_path, {}) == (None, "dashboard_reconnect_identity_unavailable")
