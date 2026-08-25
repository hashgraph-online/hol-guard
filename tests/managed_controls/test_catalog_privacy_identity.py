from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.managed_controls.identity import (
    CatalogIdentityState,
    ExtensionIdentity,
    compare_extension_identity,
)
from codex_plugin_scanner.guard.managed_controls.privacy import (
    CatalogPrivacyError,
    privacy_safe_catalog_payload,
)


def test_catalog_projection_excludes_commands_paths_and_secrets() -> None:
    payload = {
        "schema_version": 1,
        "catalog_digest": "a" * 64,
        "extensions": [
            {
                "extension_id": "command.git",
                "name": "Git",
                "version": "1",
                "permissions": [],
            }
        ],
    }
    assert privacy_safe_catalog_payload(payload) == payload
    with pytest.raises(CatalogPrivacyError):
        privacy_safe_catalog_payload({**payload, "extensions": [{"raw_command": "rm -rf /"}]})
    with pytest.raises(CatalogPrivacyError):
        privacy_safe_catalog_payload(
            {
                **payload,
                "extensions": [
                    {
                        "extension_id": "command.git",
                        "name": "Git",
                        "version": "1",
                        "permissions": [None],
                    }
                ],
            }
        )
    with pytest.raises(CatalogPrivacyError):
        privacy_safe_catalog_payload(
            {
                **payload,
                "extensions": [
                    {
                        "extension_id": "command.git",
                        "name": "/home/example/private-tool",
                        "version": "1",
                        "permissions": [],
                    }
                ],
            }
        )


def test_custom_identity_is_truthfully_local_only_without_cloud_match() -> None:
    local = ExtensionIdentity("custom.acme", "1", custom=True)
    assert compare_extension_identity(local, None) is CatalogIdentityState.CUSTOM_LOCAL_ONLY


@pytest.mark.parametrize(
    ("cloud", "expected"),
    (
        (ExtensionIdentity("custom.attacker", "1", custom=True), CatalogIdentityState.MISSING),
        (ExtensionIdentity("custom.acme", "2", custom=True), CatalogIdentityState.VERSION_DIFFERENT),
    ),
)
def test_custom_identity_spoofing_requires_exact_id_and_version(
    cloud: ExtensionIdentity,
    expected: CatalogIdentityState,
) -> None:
    local = ExtensionIdentity("custom.acme", "1", custom=True)
    assert compare_extension_identity(local, cloud) is expected


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("name", "/Users/alice/private/custom-tool"),
        ("name", "token=super-secret"),
        ("source_path", "/private/custom-tool"),
        ("raw_command", "custom-tool --credential secret"),
    ),
)
def test_custom_catalog_privacy_rejects_names_paths_commands_and_secrets(
    field: str,
    value: str,
) -> None:
    extension = {
        "extension_id": "command.custom-tool",
        "name": "Custom tool",
        "version": "1",
        "custom": True,
        "permissions": [],
        field: value,
    }
    with pytest.raises(CatalogPrivacyError):
        privacy_safe_catalog_payload(
            {
                "schema_version": 1,
                "catalog_digest": "a" * 64,
                "extensions": [extension],
            }
        )
