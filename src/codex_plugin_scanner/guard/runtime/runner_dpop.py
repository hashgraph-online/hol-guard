"""Dpop.

Shared state and replaceable dependencies belong to the runner facade.
"""

from __future__ import annotations

from . import runner


def _base64url_encode(data: bytes) -> str:
    return runner.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _encode_jwt_segment(payload: runner.Mapping[str, object]) -> str:
    return runner._base64url_encode(
        runner.json.dumps(dict(payload), separators=(",", ":"), sort_keys=True).encode("utf-8")
    )


def _dpop_access_token_confirmation_claim(access_token: str) -> str:
    # RFC 9449 requires the DPoP `ath` claim to be the SHA-256 hash of the access token.
    # codeql[py/weak-sensitive-data-hashing]
    digest = runner.hashes.Hash(runner.hashes.SHA256())
    digest.update(access_token.encode("ascii"))
    return runner._base64url_encode(digest.finalize())


def _sign_guard_dpop_proof(
    *,
    request_url: str,
    method: str,
    dpop_key_material: runner.GuardDpopKeyMaterial,
    access_token: str | None = None,
    nonce: str | None = None,
    now: runner.datetime | None = None,
) -> str:
    issued_at = int((now or runner.datetime.now(runner.timezone.utc)).timestamp())
    header = {
        "alg": dpop_key_material.algorithm,
        "jwk": dpop_key_material.public_jwk,
        "typ": "dpop+jwt",
    }
    claims: dict[str, object] = {
        "htu": request_url,
        "htm": method.upper(),
        "iat": issued_at,
        "jti": str(runner.uuid4()),
    }
    if isinstance(access_token, str) and access_token:
        claims["ath"] = runner._dpop_access_token_confirmation_claim(access_token)
    if isinstance(nonce, str):
        normalized_nonce = nonce.strip()
        if normalized_nonce:
            claims["nonce"] = normalized_nonce
    signing_input = f"{runner._encode_jwt_segment(header)}.{runner._encode_jwt_segment(claims)}".encode("ascii")
    try:
        private_key = runner.serialization.load_pem_private_key(
            dpop_key_material.private_key_pem.encode("ascii"),
            password=None,
        )
    except (TypeError, ValueError) as exc:
        raise runner.GuardSyncAuthorizationExpiredError(
            "Guard Cloud authorization key is invalid. Reconnect Guard Cloud."
        ) from exc
    if not isinstance(private_key, runner.ec.EllipticCurvePrivateKey) or not isinstance(
        private_key.curve, runner.ec.SECP256R1
    ):
        raise RuntimeError("Guard DPoP key must be a P-256 (SECP256R1) EC private key.")
    der_signature = private_key.sign(signing_input, runner.ec.ECDSA(runner.hashes.SHA256()))
    r_value, s_value = runner.decode_dss_signature(der_signature)
    jose_signature = runner._base64url_encode(
        r_value.to_bytes(32, byteorder="big") + s_value.to_bytes(32, byteorder="big")
    )
    return f"{signing_input.decode('ascii')}.{jose_signature}"


def _guard_http_header_value(response: object, header_name: str) -> str | None:
    headers = getattr(response, "headers", None)
    if headers is None:
        return None
    value = headers.get(header_name)
    if value is None:
        header_items = getattr(headers, "items", None)
        if callable(header_items):
            target_header = header_name.lower()
            raw_header_items = header_items()
            if not isinstance(raw_header_items, runner.Iterable):
                raw_header_items = ()
            for header_item in raw_header_items:
                if not isinstance(header_item, tuple) or len(header_item) != 2:
                    continue
                current_name, current_value = header_item
                if isinstance(current_name, str) and current_name.lower() == target_header:
                    value = current_value
                    break
    if not isinstance(value, str):
        return None
    normalized_value = value.strip()
    return normalized_value or None


def _http_error_payload(error: runner.urllib.error.HTTPError) -> object:
    try:
        raw_body = error.read()
    except OSError:
        raw_body = b""
    error.fp = runner.io.BytesIO(raw_body)
    if not raw_body:
        return None
    try:
        return runner.json.loads(raw_body.decode("utf-8"))
    except (UnicodeDecodeError, runner.json.JSONDecodeError):
        return None


def _dpop_nonce_from_http_error(error: runner.urllib.error.HTTPError, payload: object) -> str | None:
    if error.code not in {400, 401}:
        return None
    nonce = runner._guard_http_header_value(error, "DPoP-Nonce")
    if nonce is None:
        return None
    if isinstance(payload, dict):
        oauth_error = str(payload.get("error") or "").strip()
        if oauth_error and oauth_error not in {"use_dpop_nonce", "invalid_dpop_proof"}:
            return None
    return nonce


def _remember_guard_dpop_request_context(dpop_header: str, context: dict[str, object]) -> None:
    if len(runner._GUARD_DPOP_REQUEST_CONTEXTS) >= runner._GUARD_DPOP_REQUEST_CONTEXT_LIMIT:
        oldest_header = next(iter(runner._GUARD_DPOP_REQUEST_CONTEXTS), None)
        if isinstance(oldest_header, str):
            runner._GUARD_DPOP_REQUEST_CONTEXTS.pop(oldest_header, None)
    runner._GUARD_DPOP_REQUEST_CONTEXTS[dpop_header] = context


def _guard_sync_request(
    auth_context: dict[str, object],
    *,
    request_url: str,
    method: str,
    data: bytes | None = None,
    extra_headers: dict[str, str] | None = None,
    dpop_nonce: str | None = None,
) -> runner.urllib.request.Request:
    headers = runner._guard_sync_headers(
        auth_context,
        request_url=request_url,
        method=method,
        extra_headers=extra_headers,
        dpop_nonce=dpop_nonce,
    )
    request = runner.urllib.request.Request(
        request_url,
        data=data,
        method=method,
        headers=headers,
    )
    object.__setattr__(
        request,
        "_guard_dpop_retry_context",
        {
            "auth_context": auth_context,
            "request_url": request_url,
            "method": method,
            "extra_headers": None if extra_headers is None else dict(extra_headers),
            "dpop_nonce": dpop_nonce,
        },
    )
    return request


def _guard_sync_headers(
    auth_context: dict[str, object],
    *,
    request_url: str,
    method: str,
    extra_headers: dict[str, str] | None = None,
    dpop_nonce: str | None = None,
) -> dict[str, str]:
    access_token = str(auth_context["access_token"])
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": runner._GUARD_SYNC_USER_AGENT,
    }
    dpop_key_material = auth_context.get("dpop_key_material")
    if isinstance(dpop_key_material, runner.GuardDpopKeyMaterial):
        dpop_header = runner._sign_guard_dpop_proof(
            request_url=request_url,
            method=method,
            dpop_key_material=dpop_key_material,
            access_token=access_token,
            nonce=dpop_nonce,
        )
        headers["DPoP"] = dpop_header
        runner._remember_guard_dpop_request_context(
            dpop_header,
            {
                "auth_context": auth_context,
                "request_url": request_url,
                "method": method,
                "extra_headers": None if extra_headers is None else dict(extra_headers),
                "dpop_nonce": dpop_nonce,
            },
        )
    if isinstance(extra_headers, dict):
        headers.update(extra_headers)
    return headers


def _guard_sync_request_with_nonce(
    request: runner.urllib.request.Request,
    dpop_nonce: str,
) -> runner.urllib.request.Request | None:
    request_context = runner._resolve_guard_dpop_retry_context(request)
    if request_context is None:
        return None
    auth_context = request_context.get("auth_context")
    request_url = request_context.get("request_url")
    method = request_context.get("method")
    extra_headers = request_context.get("extra_headers")
    current_dpop_nonce = request_context.get("dpop_nonce")
    if not isinstance(auth_context, dict) or not isinstance(request_url, str) or not isinstance(method, str):
        return None
    if extra_headers is not None and not isinstance(extra_headers, dict):
        return None
    if current_dpop_nonce == dpop_nonce:
        return None
    return runner._guard_sync_request(
        auth_context,
        request_url=request_url,
        method=method,
        data=runner._request_data_bytes(request.data),
        extra_headers=None if extra_headers is None else {str(key): str(value) for key, value in extra_headers.items()},
        dpop_nonce=dpop_nonce,
    )


def _resolve_guard_dpop_retry_context(
    request: runner.urllib.request.Request,
) -> dict[str, object] | None:
    request_context = getattr(request, "_guard_dpop_retry_context", None)
    if isinstance(request_context, dict):
        return request_context
    current_dpop = request.get_header("DPoP")
    if not isinstance(current_dpop, str):
        for header_name, header_value in request.header_items():
            if header_name.lower() == "dpop":
                current_dpop = header_value
                break
    if not isinstance(current_dpop, str):
        return None
    request_context = runner._GUARD_DPOP_REQUEST_CONTEXTS.get(current_dpop)
    if not isinstance(request_context, dict):
        return None
    return request_context


def _refresh_guard_sync_request(
    request: runner.urllib.request.Request,
) -> runner.urllib.request.Request | None:
    """Build a new request with a fresh DPoP proof for timeout retries.

    Reusing the same DPoP proof after a timeout triggers server-side replay
    detection because the original request may have already been consumed.
    Preserves any server-provided DPoP nonce from the current request so
    nonce-challenged endpoints do not lose their nonce state across retries.
    """
    request_context = runner._resolve_guard_dpop_retry_context(request)
    if request_context is None:
        return None
    auth_context = request_context.get("auth_context")
    request_url = request_context.get("request_url")
    method = request_context.get("method")
    extra_headers = request_context.get("extra_headers")
    current_dpop_nonce = request_context.get("dpop_nonce")
    if not isinstance(auth_context, dict) or not isinstance(request_url, str) or not isinstance(method, str):
        return None
    if extra_headers is not None and not isinstance(extra_headers, dict):
        return None
    return runner._guard_sync_request(
        auth_context,
        request_url=request_url,
        method=method,
        data=runner._request_data_bytes(request.data),
        extra_headers=None if extra_headers is None else {str(key): str(value) for key, value in extra_headers.items()},
        dpop_nonce=current_dpop_nonce if isinstance(current_dpop_nonce, str) else None,
    )
