"""OAuth profile metadata must survive local credential reconstruction."""

import pytest

from codex_plugin_scanner.guard.store_oauth import StoreOAuthConnectMixin


@pytest.mark.parametrize("profile", [{"email": "user@example.com", "display_name": "User"}, None, "invalid"])
def test_oauth_profile_survives_credential_reconstruction(profile):
    metadata = StoreOAuthConnectMixin._oauth_local_credentials_metadata(
        {"issuer": "https://hol.org", "client_id": "test-client", "cloud_user_profile": profile}
    )
    assert metadata is not None
    result = StoreOAuthConnectMixin._build_oauth_local_credentials_result(
        metadata=metadata,
        secret_payload={
            "refresh_token": "fake-test-token",
            "dpop_private_key_pem": "fake-test-key",
            "dpop_public_jwk": {},
            "dpop_public_jwk_thumbprint": "fake-test-thumbprint",
        },
    )
    assert result is not None
    if isinstance(profile, dict):
        assert result["cloud_user_profile"] == profile
    else:
        assert "cloud_user_profile" not in result
