"""Dashboard reconnect, daemon identity, and audit events."""

from __future__ import annotations

from . import server as _server


def _query_has_guard_token(self: _server._GuardDaemonHandler, query: str) -> bool:
    return any(key == "token" for key, _value in _server.parse_qsl(query, keep_blank_values=True))


def _handle_dashboard_reconnect_prepare(self: _server._GuardDaemonHandler) -> None:
    daemon_server = self._daemon_server()
    try:
        with daemon_server.dashboard_reconnect_lock:
            authorization = _server.prepare_dashboard_reconnect_authorization(daemon_server.store.guard_home)
    except (OSError, RuntimeError):
        self._write_json(
            {
                "error": "dashboard_reconnect_unavailable",
                "reason_code": "dashboard_reconnect_identity_unavailable",
            },
            status=503,
            extra_headers={"Cache-Control": "no-store"},
        )
        return
    self._write_json(authorization, extra_headers={"Cache-Control": "no-store"})


def _handle_dashboard_reconnect_challenge(self: _server._GuardDaemonHandler, payload: dict[str, object]) -> None:
    if payload.get("protocol_version") != _server.DASHBOARD_RECONNECT_PROTOCOL_VERSION:
        self._write_dashboard_reconnect_candidate_failure("dashboard_reconnect_protocol_mismatch")
        return
    candidate_origin = self._strict_loopback_origin(payload.get("candidate_origin"))
    daemon_origin = self._dashboard_reconnect_daemon_origin()
    if candidate_origin is None or daemon_origin is None or candidate_origin != daemon_origin:
        self._write_dashboard_reconnect_candidate_failure("dashboard_reconnect_origin_mismatch")
        return
    state = self._current_authenticated_daemon_state()
    state_id = self._optional_string(state.get("state_id")) if state is not None else None
    if state_id is None:
        self._write_dashboard_reconnect_candidate_failure("dashboard_reconnect_state_unavailable")
        return
    daemon_server = self._daemon_server()
    with daemon_server.dashboard_reconnect_lock:
        challenge, reason_code = _server.issue_dashboard_reconnect_challenge(
            daemon_server.store.guard_home,
            reconnect_id=payload.get("reconnect_id"),
            client_nonce=payload.get("client_nonce"),
            candidate_origin=candidate_origin,
            state_id=state_id,
        )
    if challenge is None:
        self._write_dashboard_reconnect_candidate_failure(reason_code)
        return
    self._write_json(challenge, extra_headers={"Cache-Control": "no-store"})


def _handle_dashboard_reconnect_verify(self: _server._GuardDaemonHandler, payload: dict[str, object]) -> None:
    if payload.get("protocol_version") != _server.DASHBOARD_RECONNECT_PROTOCOL_VERSION:
        self._write_dashboard_reconnect_candidate_failure("dashboard_reconnect_protocol_mismatch")
        return
    raw_challenge = payload.get("challenge")
    if not isinstance(raw_challenge, dict) or not _server._is_string_object_dict(raw_challenge):
        self._write_dashboard_reconnect_candidate_failure("dashboard_reconnect_malformed_proof")
        return
    candidate_origin = self._strict_loopback_origin(raw_challenge.get("candidate_origin"))
    daemon_origin = self._dashboard_reconnect_daemon_origin()
    state = self._current_authenticated_daemon_state()
    state_id = self._optional_string(state.get("state_id")) if state is not None else None
    if candidate_origin is None or daemon_origin is None or candidate_origin != daemon_origin or state_id is None:
        self._write_dashboard_reconnect_candidate_failure("dashboard_reconnect_proof_context_mismatch")
        return
    daemon_server = self._daemon_server()
    challenge_identity = _server.dashboard_reconnect_challenge_identity(raw_challenge)
    if challenge_identity is None:
        self._write_dashboard_reconnect_candidate_failure("dashboard_reconnect_malformed_proof")
        return
    now_ms = int(_server.time.time() * 1000)
    with daemon_server.dashboard_reconnect_lock:
        expired_challenges = [
            identity
            for identity, expires_at_ms in daemon_server.dashboard_reconnect_consumed_challenges.items()
            if expires_at_ms < now_ms
        ]
        for identity in expired_challenges:
            daemon_server.dashboard_reconnect_consumed_challenges.pop(identity, None)
        if challenge_identity in daemon_server.dashboard_reconnect_consumed_challenges:
            self._write_dashboard_reconnect_candidate_failure("dashboard_reconnect_proof_replayed")
            return
        verified, reason_code = _server.consume_dashboard_reconnect_challenge(
            daemon_server.store.guard_home,
            challenge=raw_challenge,
            proof=payload.get("proof"),
            expected_candidate_origin=daemon_origin,
            expected_state_id=state_id,
        )
        if verified:
            expires_at_ms = raw_challenge.get("expires_at_ms")
            daemon_server.dashboard_reconnect_consumed_challenges[challenge_identity] = (
                expires_at_ms if isinstance(expires_at_ms, int) else now_ms
            )
            while len(daemon_server.dashboard_reconnect_consumed_challenges) > 256:
                oldest = next(iter(daemon_server.dashboard_reconnect_consumed_challenges))
                daemon_server.dashboard_reconnect_consumed_challenges.pop(oldest, None)
    if not verified:
        self._write_dashboard_reconnect_candidate_failure(reason_code)
        return
    self._write_json(
        {"verified": True, "reason_code": reason_code},
        extra_headers={"Cache-Control": "no-store"},
    )


def _write_dashboard_reconnect_candidate_failure(self: _server._GuardDaemonHandler, reason_code: str) -> None:
    self._write_json(
        {"error": "daemon_candidate_unavailable", "reason_code": reason_code},
        status=404,
        extra_headers={"Cache-Control": "no-store"},
    )


def _current_authenticated_daemon_state(self: _server._GuardDaemonHandler) -> dict[str, object] | None:
    daemon_server = self._daemon_server()
    state = _server.load_authenticated_daemon_state(daemon_server.store.guard_home)
    if state is None:
        return None
    expected_guard_home = str(daemon_server.store.guard_home.resolve())
    if (
        state.get("guard_home") != expected_guard_home
        or state.get("host") != daemon_server.daemon_host()
        or state.get("port") != daemon_server.daemon_port()
        or state.get("pid") != _server.os.getpid()
        or state.get("state_id") != daemon_server.runtime_session_id
    ):
        return None
    return state


def _dashboard_reconnect_daemon_origin(self: _server._GuardDaemonHandler) -> str | None:
    daemon_server = self._daemon_server()
    host = daemon_server.daemon_host()
    if host == "127.0.0.1":
        return f"http://127.0.0.1:{daemon_server.daemon_port()}"
    if host == "::1":
        return f"http://[::1]:{daemon_server.daemon_port()}"
    return None


def _strict_loopback_origin(cls: type[_server._GuardDaemonHandler], value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = cls._normalize_origin(value)
    if normalized is None:
        return None
    parsed = _server.urlparse(normalized)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "::1"}:
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    if port is None or not 1 <= port <= 65535:
        return None
    canonical_host = "[::1]" if parsed.hostname == "::1" else "127.0.0.1"
    canonical = f"http://{canonical_host}:{port}"  # NOSONAR(S5332) strict loopback host validated above
    raw_origin = value.strip()
    return canonical if normalized == canonical and raw_origin in {canonical, f"{canonical}/"} else None


def _handle_daemon_identity_challenge(self: _server._GuardDaemonHandler, payload: dict[str, object]) -> None:
    nonce = self._optional_string(payload.get("nonce"))
    hook_event = self._optional_string(payload.get("hook_event"))
    state_id = self._optional_string(payload.get("state_id"))
    protocol_version = payload.get("protocol_version")
    if (
        nonce is None
        or len(nonce) != 64
        or any(character not in "0123456789abcdef" for character in nonce.lower())
        or hook_event is None
        or len(hook_event) > 128
        or state_id is None
        or protocol_version != _server.DAEMON_DISCOVERY_PROTOCOL_VERSION
    ):
        self._write_json({"error": "invalid_daemon_identity_challenge"}, status=400)
        return
    daemon_server = self._daemon_server()
    guard_home = daemon_server.store.guard_home
    state = _server.load_authenticated_daemon_state(guard_home)
    discovery_key = _server.load_daemon_discovery_key(guard_home)
    if state is None or discovery_key is None:
        self._write_json({"error": "daemon_identity_unavailable"}, status=503)
        return
    expected_guard_home = str(guard_home.resolve())
    if (
        state.get("state_id") != state_id
        or state.get("guard_home") != expected_guard_home
        or state.get("host") != daemon_server.daemon_host()
        or state.get("port") != daemon_server.daemon_port()
        or state.get("pid") != _server.os.getpid()
    ):
        self._write_json({"error": "daemon_identity_state_mismatch"}, status=409)
        return
    issued_at_ms = int(_server.time.time() * 1000)
    expires_at_ms = issued_at_ms + _server.DAEMON_DISCOVERY_CHALLENGE_TTL_SECONDS * 1000
    response = _server.authenticated_challenge_payload(
        discovery_key=discovery_key,
        state=state,
        nonce=nonce,
        hook_event=hook_event,
        issued_at_ms=issued_at_ms,
        expires_at_ms=expires_at_ms,
    )
    with daemon_server.daemon_discovery_challenges_lock:
        expired: list[str] = []
        for candidate, item in daemon_server.daemon_discovery_challenges.items():
            candidate_expiry = item.get("expires_at_ms")
            if not isinstance(candidate_expiry, int) or candidate_expiry < issued_at_ms:
                expired.append(candidate)
        for candidate in expired:
            daemon_server.daemon_discovery_challenges.pop(candidate, None)
        if len(daemon_server.daemon_discovery_challenges) >= 256:
            oldest = next(iter(daemon_server.daemon_discovery_challenges))
            daemon_server.daemon_discovery_challenges.pop(oldest, None)
        daemon_server.daemon_discovery_challenges[nonce] = {
            "proof": response["proof"],
            "hook_event": hook_event,
            "expires_at_ms": expires_at_ms,
            "connection_id": id(self.connection),
            "state_id": state_id,
        }
    self.close_connection = False
    # The handler intentionally remains HTTP/1.0 for the rest of the daemon,
    # but this two-step proof must stay on one TCP connection.  Advertise an
    # HTTP/1.1 response for this request only; the response has an explicit
    # Content-Length, so http.client can safely reuse the socket for the
    # authenticated hook request.  ``close_connection = False`` also tells
    # BaseHTTPRequestHandler to read that next request on this handler.
    self.connection.settimeout(_server.DAEMON_DISCOVERY_CHALLENGE_TTL_SECONDS)
    previous_protocol_version = self.protocol_version
    self.protocol_version = "HTTP/1.1"
    try:
        self._write_json(response, extra_headers={"Cache-Control": "no-store"})
    finally:
        self.protocol_version = previous_protocol_version


def _consume_codex_daemon_challenge(self: _server._GuardDaemonHandler, payload: dict[str, object]) -> bool:
    nonce = self.headers.get("X-Guard-Daemon-Nonce")
    proof = self.headers.get("X-Guard-Daemon-Proof")
    if not isinstance(nonce, str) or not isinstance(proof, str):
        return False
    daemon_server = self._daemon_server()
    with daemon_server.daemon_discovery_challenges_lock:
        challenge = daemon_server.daemon_discovery_challenges.pop(nonce, None)
    if challenge is None:
        return False
    expires_at_ms = challenge.get("expires_at_ms")
    expected_proof = challenge.get("proof")
    if (
        not isinstance(expires_at_ms, int)
        or expires_at_ms < int(_server.time.time() * 1000)
        or challenge.get("connection_id") != id(self.connection)
        or not isinstance(expected_proof, str)
        or not _server.secrets.compare_digest(proof, expected_proof)
    ):
        return False
    event = payload.get("hook_event_name", payload.get("event"))
    return isinstance(event, str) and event.strip() == challenge.get("hook_event")


def _write_unauthorized(self: _server._GuardDaemonHandler, *, extra_headers: dict[str, str] | None = None) -> None:
    self._record_auth_audit_event()
    self._write_json({"error": "unauthorized"}, status=401, extra_headers=extra_headers)


def _daemon_server(self: _server._GuardDaemonHandler) -> _server._GuardDaemonHttpServer:
    return _server.cast(_server._GuardDaemonHttpServer, self.server)


def _record_auth_audit_event(self: _server._GuardDaemonHandler) -> None:
    origin = self.headers.get("Origin")
    payload: dict[str, object] = {
        "method": self.command,
        "path": _server.urlparse(self.path).path,
        "origin": self._normalize_origin(origin),
        "origin_header": origin if isinstance(origin, str) and origin.strip() else None,
        "has_authorization": isinstance(self.headers.get("Authorization"), str),
        "has_dashboard_session": isinstance(self.headers.get("X-Guard-Dashboard-Session"), str),
        "has_guard_token": isinstance(self.headers.get("X-Guard-Token"), str),
    }
    key: _server._AuthAuditKey = (
        self.command,
        _server.cast(str, payload["path"]),
        _server.cast(str | None, payload["origin"]),
        _server.cast(str | None, payload["origin_header"]),
        _server.cast(bool, payload["has_authorization"]),
        _server.cast(bool, payload["has_dashboard_session"]),
        _server.cast(bool, payload["has_guard_token"]),
    )
    daemon_server = self._daemon_server()
    now = _server.time.monotonic()
    with daemon_server.auth_audit_lock:
        previous = daemon_server.auth_audit_windows.get(key)
        reported_suppressed_count = 0
        if previous is not None and now - previous["started_at"] < _server._AUTH_AUDIT_COALESCE_SECONDS:
            if previous["pending"] or previous["persisted"]:
                previous["suppressed_count"] += 1
                return
            reported_suppressed_count = previous["suppressed_count"]
        elif previous is not None:
            reported_suppressed_count = previous["suppressed_count"]
        if reported_suppressed_count:
            payload["suppressed_count"] = reported_suppressed_count
        if (
            key not in daemon_server.auth_audit_windows
            and len(daemon_server.auth_audit_windows) >= _server._AUTH_AUDIT_KEY_LIMIT
        ):
            oldest = min(
                daemon_server.auth_audit_windows,
                key=lambda item: daemon_server.auth_audit_windows[item]["started_at"],
            )
            _ = daemon_server.auth_audit_windows.pop(oldest)
        window: _server._AuthAuditWindow = {
            "started_at": now,
            "suppressed_count": reported_suppressed_count,
            "pending": True,
            "persisted": False,
        }
        daemon_server.auth_audit_windows[key] = window
    try:
        with _server.sqlite_connect_timeout_override(_server._AUTH_AUDIT_SQLITE_TIMEOUT_SECONDS):
            daemon_server.store.add_event("daemon.auth.unauthorized", payload, _server._now())
    except Exception:
        with daemon_server.auth_audit_lock:
            current = daemon_server.auth_audit_windows.get(key)
            if current is window:
                window["pending"] = False
                window["suppressed_count"] += 1
        daemon_server.diagnostics.record_exception("auth_audit_persistence_failed")
    else:
        with daemon_server.auth_audit_lock:
            current = daemon_server.auth_audit_windows.get(key)
            if current is window:
                window["pending"] = False
                window["persisted"] = True
                window["suppressed_count"] -= reported_suppressed_count


def _record_query_token_rejection(self: _server._GuardDaemonHandler) -> None:
    self._record_bounded_denial_event(
        "daemon.auth.query_token_rejected",
        {"method": self.command, "path": _server.urlparse(self.path).path, "has_query_token": True},
    )


def _record_hook_path_rejection(self: _server._GuardDaemonHandler, *, parameter: str, reason: str) -> None:
    self._record_bounded_denial_event(
        "daemon.hook.path_rejected",
        {
            "method": self.command,
            "path": _server.urlparse(self.path).path,
            "parameter": parameter,
            "reason": reason,
        },
    )


def _record_bounded_denial_event(
    self: _server._GuardDaemonHandler, event_name: str, payload: dict[str, object]
) -> None:
    daemon_server = self._daemon_server()
    with daemon_server.denial_audit_lock:
        for attempt in range(2):
            try:
                with _server.sqlite_connect_timeout_override(_server._AUTH_AUDIT_SQLITE_TIMEOUT_SECONDS):
                    daemon_server.store.add_event(event_name, payload, _server._now())
            except TimeoutError:
                daemon_server.diagnostics.record_exception("auth_audit_persistence_timeout")
                return
            except _server.sqlite3.OperationalError as error:
                if attempt == 0 and any(
                    marker in str(error).lower() for marker in ("database is locked", "database table is locked")
                ):
                    continue
                daemon_server.diagnostics.record_exception("auth_audit_persistence_failed")
            except _server.sqlite3.DatabaseError:
                daemon_server.diagnostics.record_exception("auth_audit_persistence_failed")
            else:
                return
