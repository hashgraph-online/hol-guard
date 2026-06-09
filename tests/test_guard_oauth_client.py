import pytest

from codex_plugin_scanner.guard.cli.oauth_client import (
    LOCAL_GUARD_OAUTH_CLIENT_ID,
    PRODUCTION_GUARD_OAUTH_CLIENT_ID,
    STAGING_GUARD_OAUTH_CLIENT_ID,
    GuardDpopKeyMaterial,
    build_pkce_s256_challenge,
    detect_guard_oauth_environment,
    generate_dpop_key_pair,
    generate_pkce_verifier,
    resolve_guard_oauth_client_config,
    validate_guard_sync_endpoint,
)


def test_resolve_guard_oauth_client_config_for_production() -> None:
    config = resolve_guard_oauth_client_config("https://hol.org")

    assert config.issuer == "https://hol.org"
    assert config.authorize_endpoint == "https://hol.org/api/guard/oauth/authorize"
    assert config.token_endpoint == "https://hol.org/api/guard/oauth/token"
    assert config.device_authorization_endpoint == "https://hol.org/api/guard/oauth/device/authorize"
    assert config.jwks_endpoint == "https://hol.org/api/guard/oauth/jwks"
    assert config.client_id == PRODUCTION_GUARD_OAUTH_CLIENT_ID


def test_resolve_guard_oauth_client_config_for_staging() -> None:
    config = resolve_guard_oauth_client_config("https://staging.hol.org")

    assert config.client_id == STAGING_GUARD_OAUTH_CLIENT_ID
    assert config.token_endpoint == "https://staging.hol.org/api/guard/oauth/token"
    assert detect_guard_oauth_environment(config.issuer) == "staging"


def test_resolve_guard_oauth_client_config_for_local_loopback() -> None:
    config = resolve_guard_oauth_client_config("http://127.0.0.1:3000")

    assert config.client_id == LOCAL_GUARD_OAUTH_CLIENT_ID
    assert config.authorize_endpoint == "http://127.0.0.1:3000/api/guard/oauth/authorize"
    assert detect_guard_oauth_environment(config.issuer) == "local"


def test_resolve_guard_oauth_client_config_for_docker_lab_host() -> None:
    config = resolve_guard_oauth_client_config("http://host.docker.internal:3017")

    assert config.client_id == LOCAL_GUARD_OAUTH_CLIENT_ID
    assert config.authorize_endpoint == "http://host.docker.internal:3017/api/guard/oauth/authorize"
    assert detect_guard_oauth_environment(config.issuer) == "local"


def test_validate_guard_sync_endpoint_allows_docker_lab_http() -> None:
    issuer = "http://host.docker.internal:3017"
    sync_url = "http://host.docker.internal:3017/api/guard/receipts/sync"

    assert validate_guard_sync_endpoint(sync_url, issuer=issuer) == sync_url


def test_resolve_guard_oauth_client_config_rejects_unallowlisted_host() -> None:
    with pytest.raises(ValueError, match="allowlisted"):
        resolve_guard_oauth_client_config("https://evil.example")


def test_generate_pkce_verifier_uses_rfc7636_charset() -> None:
    verifier = generate_pkce_verifier(64)

    assert len(verifier) == 64
    assert all(character.isalnum() or character in "-._~" for character in verifier)


def test_generate_pkce_verifier_rejects_out_of_range_length() -> None:
    try:
        generate_pkce_verifier(42)
    except ValueError as error:
        assert "between 43 and 128" in str(error)
    else:
        raise AssertionError("PKCE verifier length below RFC minimum must fail")


def test_build_pkce_s256_challenge_matches_known_vector() -> None:
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

    challenge = build_pkce_s256_challenge(verifier)

    assert challenge == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def test_build_pkce_s256_challenge_rejects_invalid_characters() -> None:
    try:
        build_pkce_s256_challenge("invalid verifier with spaces")
    except ValueError as error:
        assert "unsupported characters" in str(error)
    else:
        raise AssertionError("PKCE challenge builder must reject invalid verifier characters")


def test_generate_dpop_key_pair_returns_es256_material() -> None:
    material = generate_dpop_key_pair()

    assert isinstance(material, GuardDpopKeyMaterial)
    assert material.algorithm == "ES256"
    assert material.private_key_pem.startswith("-----BEGIN PRIVATE KEY-----")
    assert material.public_jwk["kty"] == "EC"
    assert material.public_jwk["crv"] == "P-256"
    assert isinstance(material.public_jwk["x"], str) and material.public_jwk["x"]
    assert isinstance(material.public_jwk["y"], str) and material.public_jwk["y"]
    assert isinstance(material.public_jwk_thumbprint, str) and material.public_jwk_thumbprint
