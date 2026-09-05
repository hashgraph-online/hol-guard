from __future__ import annotations

import json
import urllib.request
from pathlib import Path
from types import TracebackType
from typing import cast, final

import pytest

from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
from codex_plugin_scanner.guard.policy_bundle_trusted_keys import (
    PolicyBundleVerificationKey,
    policy_bundle_verification_key_from_public_key,
)
from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.store import GuardStore
from tests.policy_bundle_signing_helpers import (
    policy_bundle_test_verification_key,
    sign_policy_bundle,
)
from tests.support.network import stub_authenticated_urlopen

_WORKSPACE_ID = "workspace-1"


@final
class _Response:
    def __init__(self, payload: dict[str, object]) -> None:
        self._payload: dict[str, object] = payload

    def __enter__(self) -> _Response:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc, traceback

    def read(self) -> bytes:
        return json.dumps(self._payload).encode("utf-8")


def _connected_store(tmp_path: Path) -> GuardStore:
    store = GuardStore(tmp_path / "guard-home")
    dpop = generate_dpop_key_pair()
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="test-refresh-token",
        dpop_private_key_pem=dpop.private_key_pem,
        dpop_public_jwk=dpop.public_jwk,
        dpop_public_jwk_thumbprint=dpop.public_jwk_thumbprint,
        grant_id="grant-1",
        machine_id="machine-1",
        workspace_id=_WORKSPACE_ID,
        now="2026-08-26T11:59:00+00:00",
    )
    return store


def _policy_bundle() -> dict[str, object]:
    return sign_policy_bundle(
        {
            "contractVersion": "guard-policy-bundle.v1",
            "bundleVersion": "policy-2026-08-26.1",
            "issuedAt": "2026-08-26T12:00:00+00:00",
            "expiresAt": None,
            "verifier": {},
            "rolloutState": "enforcing",
            "policyDefaults": {
                "mode": "enforce",
                "defaultAction": "warn",
                "unknownPublisherAction": "review",
                "changedHashAction": "require-reapproval",
                "newNetworkDomainAction": "warn",
                "subprocessAction": "block",
                "telemetryEnabled": False,
                "syncEnabled": True,
            },
            "rules": [],
            "acknowledgements": [],
        },
        workspace_id=_WORKSPACE_ID,
    )


def test_first_sync_anchors_review_key_after_policy_activation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _connected_store(tmp_path)
    policy_key = policy_bundle_test_verification_key(workspace_id=_WORKSPACE_ID)
    review_key = policy_bundle_verification_key_from_public_key(
        key_id="guard-review-first-sync",
        public_key_pem=policy_key.public_key_pem,
        purpose="remote_approval",
        workspace_id=_WORKSPACE_ID,
    )
    bundle = _policy_bundle()
    response = _Response(
        {
            "syncedAt": "2026-08-26T12:00:00+00:00",
            "receiptsStored": 0,
            "policyBundle": bundle,
            "reviewVerificationKeys": [review_key.to_dict()],
        }
    )

    def validate_policy_bundle(
        policy_bundle: dict[str, object],
        **_kwargs: object,
    ) -> tuple[dict[str, object], None, tuple[PolicyBundleVerificationKey, ...]]:
        return policy_bundle, None, (policy_key,)

    def open_sync(_request: urllib.request.Request, timeout: float) -> _Response:
        del _request, timeout
        return response

    def no_auxiliary_sync(
        _store: GuardStore,
        auth_context: dict[str, object] | None = None,
    ) -> int:
        del _store, auth_context
        return 0

    monkeypatch.setattr(runner, "validate_synced_policy_bundle", validate_policy_bundle)
    stub_authenticated_urlopen(monkeypatch, open_sync)
    monkeypatch.setattr(runner, "sync_pain_signals", no_auxiliary_sync)
    monkeypatch.setattr(runner, "sync_guard_events", no_auxiliary_sync)

    _ = runner.sync_receipts(
        store,
        auth_context={
            "access_token": "test-access-token",
            "dpop_key_material": None,
            "sync_url": "https://hol.org/api/guard/receipts/sync",
        },
    )

    policy_keyring = store.get_sync_payload("policy_bundle_keyring")
    review_keyring = store.get_sync_payload("guard_review_verification_keyring")
    assert isinstance(policy_keyring, dict)
    keys = policy_keyring.get("keys")
    assert isinstance(keys, list)
    typed_keys = cast(list[object], keys)
    assert typed_keys and isinstance(typed_keys[0], dict)
    first_key = cast(dict[str, object], typed_keys[0])
    assert first_key["fingerprintSha256"] == review_key.fingerprint_sha256
    assert review_keyring == [review_key.to_dict()]
