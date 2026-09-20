"""Dashboard session and request authorization."""

from __future__ import annotations

from . import server as _server


def _header_token_is_valid(self: _server._GuardDaemonHandler, *, payload: dict[str, object] | None = None) -> bool:
    token = self.headers.get("X-Guard-Token")
    path = _server.urlparse(self.path).path
    path_parts = [part for part in path.split("/") if part]
    return self._tokens_match(token) or (
        self._path_supports_dashboard_session(path, path_parts)
        and self._dashboard_session_token_is_valid(payload=payload)
    )


def _dashboard_session_token_is_valid(
    self: _server._GuardDaemonHandler, *, payload: dict[str, object] | None = None
) -> bool:
    session_token = self.headers.get("X-Guard-Dashboard-Session")
    authorization = self.headers.get("Authorization")
    bearer_token = None
    if isinstance(authorization, str) and authorization.lower().startswith("bearer "):
        bearer_token = authorization[7:].strip()
    candidates = [
        candidate for candidate in (session_token, bearer_token) if isinstance(candidate, str) and candidate.strip()
    ]
    return any(self._dashboard_session_token_matches(candidate, payload=payload) for candidate in candidates)


def _dashboard_session_token_matches(
    self: _server._GuardDaemonHandler, token: str, *, payload: dict[str, object] | None = None
) -> bool:
    claims = self._dashboard_session_token_claims(token)
    if claims is None:
        return False
    return self._dashboard_session_claims_authorize_request(claims, payload=payload)


def _dashboard_session_token_claims(
    self: _server._GuardDaemonHandler,
    token: str,
    *,
    allow_expired_within_seconds: float = 0.0,
) -> dict[str, object] | None:
    if not token.startswith("gld1."):
        return None
    parts = token.split(".")
    if len(parts) != 3:
        return None
    prefix, encoded_payload, signature = parts
    if prefix != "gld1" or not encoded_payload or not signature:
        return None
    expected = _server._dashboard_session_signature(encoded_payload, self.server.auth_token)  # type: ignore[attr-defined]
    if not _server.secrets.compare_digest(signature, expected):
        return None
    claims = _server._decode_dashboard_session_payload(encoded_payload)
    if self._optional_string(claims.get("aud")) != _server.LOCAL_DASHBOARD_SESSION_AUDIENCE:
        return None
    expires_at = claims.get("expires_at")
    if not isinstance(expires_at, str):
        return None
    try:
        expires_at_timestamp = _server._parse_iso_timestamp(expires_at)
    except ValueError:
        return None
    if expires_at_timestamp + max(0.0, allow_expired_within_seconds) <= _server.time.time():
        return None
    return claims


def _refresh_dashboard_session_token(self: _server._GuardDaemonHandler, *, surface: str) -> str | None:
    claims = self._refreshable_dashboard_session_claims()
    if claims is None:
        return None
    started_at = self._optional_string(claims.get(_server.LOCAL_DASHBOARD_SESSION_STARTED_AT_CLAIM))
    if started_at is None:
        expires_at = self._optional_string(claims.get("expires_at"))
        if expires_at is None:
            return None
        try:
            started_at_timestamp = (
                _server._parse_iso_timestamp(expires_at) - _server.DEFAULT_LOCAL_DASHBOARD_SESSION_TTL_SECONDS
            )
        except ValueError:
            return None
        started_at = _server.datetime.fromtimestamp(started_at_timestamp, tz=_server.timezone.utc).isoformat()
    try:
        absolute_expires_at = _server._parse_iso_timestamp(started_at) + _server.MAX_LOCAL_DASHBOARD_SESSION_AGE_SECONDS
    except ValueError:
        return None
    remaining_seconds = absolute_expires_at - _server.time.time()
    if remaining_seconds < 1:
        return None
    refreshed_surface = surface if surface in {"approval-center", "dashboard", "cloud-dashboard"} else "dashboard"
    return _server.build_local_dashboard_session_token(
        auth_token=self.server.auth_token,  # type: ignore[attr-defined]
        surface=refreshed_surface,
        expires_in_seconds=min(_server.DEFAULT_LOCAL_DASHBOARD_SESSION_TTL_SECONDS, int(remaining_seconds)),
        session_started_at=started_at,
    )


def _refreshable_dashboard_session_claims(self: _server._GuardDaemonHandler) -> dict[str, object] | None:
    session_token = self.headers.get("X-Guard-Dashboard-Session")
    authorization = self.headers.get("Authorization")
    bearer_token = None
    if isinstance(authorization, str) and authorization.lower().startswith("bearer "):
        bearer_token = authorization[7:].strip()
    candidates = [
        candidate for candidate in (session_token, bearer_token) if isinstance(candidate, str) and candidate.strip()
    ]
    for candidate in candidates:
        claims = self._dashboard_session_token_claims(
            candidate,
            allow_expired_within_seconds=_server._LOCAL_DASHBOARD_SESSION_REFRESH_GRACE_SECONDS,
        )
        if claims is None:
            continue
        surface = self._optional_string(claims.get("surface"))
        if surface in {"approval-center", "dashboard", "cloud-dashboard"}:
            return claims
    return None


def _dashboard_session_claims_authorize_request(
    self: _server._GuardDaemonHandler,
    claims: dict[str, object],
    *,
    payload: dict[str, object] | None,
) -> bool:
    surface = self._optional_string(claims.get("surface"))
    path = _server.urlparse(self.path).path
    path_parts = [part for part in path.split("/") if part]
    if surface in {"approval-center", "dashboard", "cloud-dashboard"}:
        return self._path_supports_dashboard_session(path, path_parts)
    action_path = self._optional_string(claims.get("action_path"))
    if action_path is None:
        return False
    if self.command == "GET" and self._dashboard_session_scoped_read_path_is_allowed(claims, path):
        return self._dashboard_session_scoped_nonce_matches_request(claims=claims, payload=payload)
    if (
        len(path_parts) == 3
        and path_parts[:2] == ["v1", "apps"]
        and path_parts[2] in _server._cloud_app_dashboard_session_actions(action_path)
    ):
        if payload is None:
            return False
        harness = self._optional_string(claims.get("harness"))
        location_id = self._optional_string(claims.get("location_id"))
        workspace_id = self._optional_string(claims.get("workspace_id")) or ""
        payload_harness = self._optional_string(payload.get("harness"))
        payload_location_id = self._optional_string(payload.get("location_id")) or self._optional_string(
            payload.get("locationId")
        )
        payload_workspace_id = self._optional_string(payload.get("workspace_id")) or ""
        return (
            harness is not None
            and payload_harness == harness
            and (not location_id or payload_location_id == location_id)
            and (not workspace_id or payload_workspace_id == workspace_id)
        )
    supply_chain_action = self._supply_chain_claim_action_for_request(path, path_parts)
    if supply_chain_action is not None:
        return self._supply_chain_dashboard_claims_authorize(
            claims,
            payload=payload,
            supply_chain_action=supply_chain_action,
        )
    return False


def _dashboard_session_scoped_read_path_is_allowed(
    self: _server._GuardDaemonHandler, claims: dict[str, object], path: str
) -> bool:
    allowed_read_paths = claims.get("allowed_read_paths")
    if not isinstance(allowed_read_paths, list):
        return False
    return path in {item for item in allowed_read_paths if isinstance(item, str)}


def _dashboard_session_scoped_nonce_matches_request(
    self: _server._GuardDaemonHandler,
    *,
    claims: dict[str, object],
    payload: dict[str, object] | None,
) -> bool:
    claim_nonce = self._optional_string(claims.get("nonce"))
    if claim_nonce is None:
        return True
    request_nonce = self._optional_string(self.headers.get("X-Guard-Dashboard-Nonce"))
    if request_nonce is None and payload is not None:
        request_nonce = self._optional_string(payload.get("dashboard_session_nonce"))
    return request_nonce == claim_nonce


def _local_surface_session_request_is_allowed(
    self: _server._GuardDaemonHandler, path: str, path_parts: list[str]
) -> bool:
    if path in {
        "/v1/cloud-review",
        "/v1/capabilities",
        "/v1/sessions",
        "/v1/runtime",
        "/v1/harnesses",
        "/v1/inventory",
        "/v1/settings",
        "/v1/settings/export",
        "/v1/events",
        "/v1/events/stream",
        "/v1/command-activity",
        "/v1/command-activity/analytics",
        "/v1/command-activity/diagnostics",
        "/v1/command-activity/events",
        "/v1/command-activity/feedback",
        "/v1/command-extensions",
        "/v1/requests",
        "/v1/receipts",
        "/v1/receipts/analytics",
        "/v1/insights/share",
        "/v1/cloud/connect",
        "/v1/receipts/latest",
        "/v1/policy",
        "/v1/policy/cloud-exceptions",
        "/v1/evidence",
        "/v1/evidence/export",
        "/v1/clients/attach",
        "/v1/clients/heartbeat",
        "/v1/sessions/start",
        "/v1/operations/start",
        "/v1/operations/block",
        "/v1/policy/sync",
        "/v1/requests/clear",
        *_server._REMOTE_REVIEW_POST_ROUTES,
        "/v1/settings/import",
        "/v1/settings/reset",
        "/v1/read-state",
        "/v1/policy/clear",
        "/v1/approval-gate/cooldown/revoke",
        "/v1/approval-gate/totp/enroll",
        "/v1/approval-gate/totp/verify",
        "/v1/approval-gate/totp/disable",
        "/v1/daemon/repair",
        "/v1/protection/repair",
        "/v1/notifications/setup",
        "/v1/update/status",
        "/v1/update/channel",
        "/v1/update/reconnect/prepare",
    }:
        return True
    # Hosted dashboard access is blocked for these routes, but local
    # loopback/dashboard sessions still use them until the route deletion
    # slice lands.
    if len(path_parts) == 3 and path_parts[:2] == ["v1", "apps"] and path_parts[2] in _server._HEADLESS_APP_ACTIONS:
        return True
    if len(path_parts) >= 2 and path_parts[:2] == ["v1", "supply-chain"]:
        return True
    if self.command == "GET":
        if len(path_parts) == 4 and path_parts[:3] == ["v1", "mcp-policy", "requests"]:
            return True
        if len(path_parts) == 3 and path_parts[:2] in (
            ["v1", "requests"],
            ["v1", "receipts"],
            ["v1", "operations"],
        ):
            return True
        if len(path_parts) == 4 and path_parts[:2] == ["v1", "sessions"] and path_parts[3] == "resume":
            return True
    if self.command == "POST":
        if len(path_parts) == 5 and path_parts[:3] == ["v1", "mcp-policy", "requests"] and path_parts[4] == "decision":
            return True
        if path in {"/v1/update", "/v1/update/channel", "/v1/update/reconnect/prepare"}:
            return True
        if (
            len(path_parts) == 4
            and path_parts[:2] == ["v1", "requests"]
            and path_parts[3]
            in {
                "approve",
                "block",
                "resume",
            }
        ):
            return True
        if (
            len(path_parts) == 4
            and path_parts[:2] == ["v1", "operations"]
            and path_parts[3]
            in {
                "items",
                "status",
            }
        ):
            return True
    return False


def _path_supports_dashboard_session(self: _server._GuardDaemonHandler, path: str, path_parts: list[str]) -> bool:
    return self._is_hosted_dashboard_api_path(path, path_parts) or self._local_surface_session_request_is_allowed(
        path,
        path_parts,
    )


def _claim_string(self: _server._GuardDaemonHandler, claims: dict[str, object], *keys: str) -> str | None:
    for key in keys:
        value = self._optional_string(claims.get(key))
        if value is not None:
            return value
    return None


def _enforce_package_firewall_rate_limit(
    self: _server._GuardDaemonHandler,
    operation: str,
    payload: dict[str, object],
) -> bool:
    workspace_id = (
        self._optional_string(payload.get("workspace_id"))
        or self._optional_string(payload.get("workspaceId"))
        or self.server.store.get_cloud_workspace_id()  # type: ignore[attr-defined]
        or "local"
    )
    rate_key = f"{workspace_id}:{operation}"
    allowed, retry_after = self.server.package_firewall_action_rate_limiter.allow(rate_key)  # type: ignore[attr-defined]
    if allowed:
        return True
    self._write_json(
        {
            "error": "rate_limited",
            "message": "Package firewall actions are temporarily rate limited.",
            "operation": operation,
            "retry_after_seconds": retry_after,
        },
        status=429,
    )
    return False


def _consume_dashboard_session_nonce(self: _server._GuardDaemonHandler, nonce: str) -> bool:
    now = _server.time.monotonic()
    ttl_seconds = 600.0
    with self.server.package_firewall_session_nonces_lock:  # type: ignore[attr-defined]
        stale_before = now - ttl_seconds
        stale_keys = [
            key for key, seen_at in self.server.package_firewall_session_nonces.items() if seen_at <= stale_before
        ]
        for key in stale_keys:
            del self.server.package_firewall_session_nonces[key]
        if nonce in self.server.package_firewall_session_nonces:
            return False
        self.server.package_firewall_session_nonces[nonce] = now
        return True


def _supply_chain_dashboard_claims_authorize(
    self: _server._GuardDaemonHandler,
    claims: dict[str, object],
    *,
    payload: dict[str, object] | None,
    supply_chain_action: str,
) -> bool:
    action_path = self._optional_string(claims.get("action_path"))
    allowed_claim = claims.get("allowed_action_paths")
    allowed_actions = (
        {item for item in allowed_claim if isinstance(item, str)} if isinstance(allowed_claim, list) else set()
    )
    if supply_chain_action != action_path and supply_chain_action not in allowed_actions:
        return False
    claim_nonce = self._claim_string(claims, "nonce")
    if claim_nonce is not None and not self._consume_dashboard_session_nonce(claim_nonce):
        return False
    if payload is None:
        return supply_chain_action in {"package_shims_status", "supply_chain_bundle"}
    workspace_id = self._claim_string(claims, "workspace_id", "workspaceId") or ""
    payload_workspace_id = (
        self._optional_string(payload.get("workspace_id")) or self._optional_string(payload.get("workspaceId")) or ""
    )
    if workspace_id and payload_workspace_id != workspace_id:
        return False
    location_id = self._claim_string(claims, "location_id", "locationId")
    payload_location_id = (
        self._optional_string(payload.get("location_id")) or self._optional_string(payload.get("locationId")) or ""
    )
    if location_id and payload_location_id != location_id:
        return False
    daemon_origin = self._claim_string(claims, "daemon_origin", "daemonOrigin")
    if daemon_origin is not None:
        request_origin = self._normalize_origin(self.headers.get("Origin"))
        payload_origin = (
            self._optional_string(payload.get("daemon_origin"))
            or self._optional_string(payload.get("daemonOrigin"))
            or request_origin
        )
        if payload_origin != daemon_origin:
            return False
    managers_claim = claims.get("managers")
    if not isinstance(managers_claim, list):
        return True
    allowed_managers = {item for item in managers_claim if isinstance(item, str)}
    managers_value = payload.get("managers")
    if managers_value is None:
        return True
    if not isinstance(managers_value, list) or not all(isinstance(manager, str) for manager in managers_value):
        return False
    return set(managers_value).issubset(allowed_managers)


def _supply_chain_claim_action_for_request(path: str, path_parts: list[str]) -> str | None:
    if path == "/v1/supply-chain/package-shims":
        return "package_shims_status"
    if path == "/v1/supply-chain/entitlement":
        return "supply_chain_entitlement"
    if path == "/v1/supply-chain/bundle":
        return "supply_chain_bundle"
    if path == "/v1/supply-chain/repair":
        return "package_shims_repair_all"
    if len(path_parts) == 4 and path_parts[:3] == ["v1", "supply-chain", "package-shims"]:
        action = "remove" if path_parts[3] == "uninstall" else path_parts[3]
        if action in {"activate", "install", "repair", "test", "remove", "open-shell"}:
            return f"package_shims_{action}"
    if len(path_parts) == 3 and path_parts[:2] == ["v1", "supply-chain"] and path_parts[2] in {"audit", "sync"}:
        return f"package_shims_{path_parts[2]}"
    return None


def _tokens_match(self: _server._GuardDaemonHandler, token: object) -> bool:
    if not isinstance(token, str):
        return False
    try:
        provided = token.encode("ascii")
        expected = self.server.auth_token.encode("ascii")  # type: ignore[attr-defined]
    except UnicodeEncodeError:
        return False
    return _server.secrets.compare_digest(provided, expected)
