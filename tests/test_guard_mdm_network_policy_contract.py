from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from codex_plugin_scanner.guard.mdm.contracts import MDM_POLICY_SCHEMA_VERSION
from codex_plugin_scanner.guard.mdm.policy import ManagedPolicyError, parse_managed_policy


def _payload(network: dict[str, object]) -> dict[str, object]:
    return {"schemaVersion": MDM_POLICY_SCHEMA_VERSION, "network": network}


def _validator() -> Draft202012Validator:
    schema_path = Path(__file__).parents[1] / "docs" / "guard" / "schemas" / "mdm-policy-v1.schema.json"
    return Draft202012Validator(json.loads(schema_path.read_text(encoding="utf-8")))


@pytest.mark.parametrize(
    "proxy_url",
    (
        "https://proxy.example",
        "https://proxy.example:8443",
        "HTTPS://proxy.example:443/",
        "https://[2001:db8::1]:8443",
    ),
)
def test_explicit_proxy_schema_and_runtime_accept_only_credential_free_https(proxy_url: str) -> None:
    payload = _payload({"proxyMode": "explicit", "proxyUrl": proxy_url})

    _validator().validate(payload)
    policy = parse_managed_policy(payload)

    assert policy.network.proxy_mode == "explicit"
    assert policy.network.proxy_url == proxy_url


@pytest.mark.parametrize(
    "proxy_url",
    (
        "",
        "http://proxy.example:8080",
        "https://user:secret@proxy.example:8443",
        "https://proxy.example:8443/path",
        "https://proxy.example:8443?token=secret",
        "https://proxy.example:8443#fragment",
        "https://proxy.example:0",
        "https://proxy.example:65536",
        "https://proxy.example:",
        " https://proxy.example:8443",
        "https://proxy.example:8443 trailing",
    ),
)
def test_explicit_proxy_schema_and_runtime_reject_ambiguous_or_secret_urls(proxy_url: str) -> None:
    payload = _payload({"proxyMode": "explicit", "proxyUrl": proxy_url})

    with pytest.raises(ValidationError):
        _validator().validate(payload)
    with pytest.raises(ManagedPolicyError, match=r"network(?:\.proxyUrl| proxy credentials)"):
        parse_managed_policy(payload)


@pytest.mark.parametrize("mode", ("system", "none"))
def test_proxy_url_is_forbidden_when_proxy_mode_is_not_explicit(mode: str) -> None:
    payload = _payload({"proxyMode": mode, "proxyUrl": "https://proxy.example:8443"})

    with pytest.raises(ValidationError):
        _validator().validate(payload)
    with pytest.raises(ManagedPolicyError, match="only valid for explicit proxy mode"):
        parse_managed_policy(payload)


def test_explicit_proxy_requires_url_in_schema_and_runtime() -> None:
    payload = _payload({"proxyMode": "explicit"})

    with pytest.raises(ValidationError):
        _validator().validate(payload)
    with pytest.raises(ManagedPolicyError, match="required for explicit proxy mode"):
        parse_managed_policy(payload)


@pytest.mark.parametrize("proxy_mode", ([], {}))
def test_proxy_mode_must_be_a_valid_string(proxy_mode: object) -> None:
    payload = _payload({"proxyMode": proxy_mode})

    with pytest.raises(ValidationError):
        _validator().validate(payload)
    with pytest.raises(ManagedPolicyError, match=r"network\.proxyMode is invalid"):
        parse_managed_policy(payload)


def test_unknown_network_keys_fail_runtime_validation() -> None:
    payload = _payload({"proxyMode": "none", "credential": "must-not-be-accepted"})

    with pytest.raises(ValidationError):
        _validator().validate(payload)
    with pytest.raises(ManagedPolicyError, match="unknown network keys"):
        parse_managed_policy(payload)


def test_managed_ca_bundle_path_must_be_absolute() -> None:
    payload = _payload({"proxyMode": "none", "caBundlePath": "relative/private-ca.pem"})

    with pytest.raises(ValidationError):
        _validator().validate(payload)
    with pytest.raises(ManagedPolicyError, match=r"network\.caBundlePath must be absolute"):
        parse_managed_policy(payload)
