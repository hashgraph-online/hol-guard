from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import json
import urllib.error
import urllib.request
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.daemon import extension_control_api as extension_control_api_module
from codex_plugin_scanner.guard.daemon.client import GuardDaemonRequestError, GuardSurfaceDaemonClient
from codex_plugin_scanner.guard.daemon.extension_control_api import (
    ExtensionControlApiError,
    ExtensionControlApiService,
)
from codex_plugin_scanner.guard.daemon.manager import load_guard_daemon_auth_token
from codex_plugin_scanner.guard.local_dashboard_session import LOCAL_DASHBOARD_SESSION_AUDIENCE
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    CommandSafetyExtensionRegistry,
)
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityView,
)
from codex_plugin_scanner.guard.runtime.extension_control_proof import ExtensionControlProof
from codex_plugin_scanner.guard.runtime.extension_control_runtime import ExtensionControlRuntime
from codex_plugin_scanner.guard.store import GuardStore


def _mutation_payload(*, revision: int = 4) -> dict[str, object]:
    return {
        "previous_revision": revision,
        "catalog_digest": BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        "layers": [],
        "actor_id": "local-admin",
        "idempotency_key": "mutation-1",
        "nonce": "nonce-1",
    }


def _service(store: GuardStore, *, revision: int = 4) -> ExtensionControlApiService:
    view = ExtensionControlAuthorityView(
        AuthorityHealth.PROTECTED,
        revision,
        BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        (),
    )
    return ExtensionControlApiService(
        store=store,
        registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        runtime=ExtensionControlRuntime(view),
    )


def _dashboard_token(auth_token: str) -> str:
    payload_json = json.dumps(
        {
            "aud": LOCAL_DASHBOARD_SESSION_AUDIENCE,
            "version": "guard-local-daemon-session.v1",
            "expires_at": datetime(2099, 1, 1, tzinfo=timezone.utc).isoformat(),
            "surface": "approval-center",
        },
        separators=(",", ":"),
    )
    payload = base64.urlsafe_b64encode(payload_json.encode()).decode().rstrip("=")
    signature = hmac.new(auth_token.encode(), payload.encode(), hashlib.sha256).digest()
    encoded_signature = base64.urlsafe_b64encode(signature).decode().rstrip("=")
    return f"gld1.{payload}.{encoded_signature}"


def test_catalog_and_effective_responses_are_bounded_public_dtos(tmp_path: Path) -> None:
    service = _service(GuardStore(tmp_path / "guard-home"))

    catalog = service.catalog()
    effective = service.effective()

    assert catalog["catalog_digest"] == BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    assert isinstance(catalog["extensions"], list)
    assert catalog["limits"] == {
        "max_body_bytes": 1_000_000,
        "max_controls": 4096,
        "max_observations": 2048,
    }
    assert effective == {
        "schema_version": "guard.daemon.extension-controls.v1",
        "health": "protected",
        "revision": 4,
        "catalog_digest": BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        "global_lockdown": False,
        "controls": [],
        "layers": [],
        "failures": [],
    }


def test_degraded_acknowledgement_consumes_daemon_bound_approval_before_refresh(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    degraded = ExtensionControlAuthorityView(
        AuthorityHealth.DEGRADED_UNACKNOWLEDGED,
        0,
        BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        (),
    )
    service = ExtensionControlApiService(
        store=store,
        registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        runtime=ExtensionControlRuntime(degraded),
    )
    calls: list[str] = []
    monkeypatch.setattr(
        extension_control_api_module,
        "require_extension_control",
        lambda *_args, **_kwargs: calls.append("require") or object(),
    )
    monkeypatch.setattr(
        extension_control_api_module,
        "consume_extension_control_grant",
        lambda *_args, **_kwargs: calls.append("consume"),
    )

    effective = service.acknowledge_degraded(
        {
            "approval_password": "secret",
            "session_nonce": "nonce",
        }
    )

    assert effective["health"] == AuthorityHealth.DEGRADED_ACKNOWLEDGED.value
    assert effective["failures"] == []
    assert calls == ["require", "consume"]


def test_degraded_acknowledgement_rejects_missing_daemon_approval(tmp_path: Path) -> None:
    degraded = ExtensionControlAuthorityView(
        AuthorityHealth.DEGRADED_UNACKNOWLEDGED,
        0,
        BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        (),
    )
    service = ExtensionControlApiService(
        store=GuardStore(tmp_path / "guard-home"),
        registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        runtime=ExtensionControlRuntime(degraded),
    )

    with pytest.raises(ExtensionControlApiError) as denied:
        service.acknowledge_degraded({"session_nonce": "nonce"})

    assert denied.value.status == 423
    assert service.effective()["health"] == AuthorityHealth.DEGRADED_UNACKNOWLEDGED.value


def test_legacy_extension_aliases_migrate_to_canonical_catalog_ids(tmp_path: Path) -> None:
    legacy_id = "command.legacy-control-id"
    first = BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions[0]
    registry = CommandSafetyExtensionRegistry(
        (replace(first, aliases=(legacy_id,)), *BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions[1:])
    )
    view = ExtensionControlAuthorityView(AuthorityHealth.PROTECTED, 4, registry.catalog_digest, ())
    service = ExtensionControlApiService(
        store=GuardStore(tmp_path / "guard-home"),
        registry=registry,
        runtime=ExtensionControlRuntime(view),
    )
    payload = {
        **_mutation_payload(),
        "catalog_digest": registry.catalog_digest,
        "layers": [
            {
                "schema_version": "1.0.0",
                "kind": "local-admin",
                "catalog_digest": registry.catalog_digest,
                "global_lockdown": False,
                "controls": [
                    {
                        "target_kind": "extension",
                        "target_id": legacy_id,
                        "state": "disabled",
                    }
                ],
            }
        ],
    }

    mutation = service._mutation_from_payload(payload)

    assert mutation.layers[0].controls[0].target.target_id == first.extension_id


def test_alias_migration_rejects_duplicate_canonical_targets(tmp_path: Path) -> None:
    legacy_id = "command.legacy-control-id"
    first = BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions[0]
    registry = CommandSafetyExtensionRegistry(
        (replace(first, aliases=(legacy_id,)), *BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions[1:])
    )
    view = ExtensionControlAuthorityView(AuthorityHealth.PROTECTED, 4, registry.catalog_digest, ())
    service = ExtensionControlApiService(
        store=GuardStore(tmp_path / "guard-home"),
        registry=registry,
        runtime=ExtensionControlRuntime(view),
    )
    payload = {
        **_mutation_payload(),
        "catalog_digest": registry.catalog_digest,
        "layers": [
            {
                "schema_version": "1.0.0",
                "kind": "local-admin",
                "catalog_digest": registry.catalog_digest,
                "global_lockdown": False,
                "controls": [
                    {
                        "target_kind": "extension",
                        "target_id": legacy_id,
                        "state": "disabled",
                    },
                    {
                        "target_kind": "extension",
                        "target_id": first.extension_id,
                        "state": "enabled",
                    },
                ],
            }
        ],
    }

    with pytest.raises(ExtensionControlApiError) as duplicate:
        service._mutation_from_payload(payload)

    assert (duplicate.value.status, duplicate.value.code) == (400, "duplicate_control_target")


def test_preview_rejects_stale_revision_and_unknown_catalog(tmp_path: Path) -> None:
    service = _service(GuardStore(tmp_path / "guard-home"))

    with pytest.raises(ExtensionControlApiError) as stale:
        service.preview(_mutation_payload(revision=3))
    assert (stale.value.status, stale.value.code) == (409, "revision_conflict")
    assert stale.value.to_payload() == {
        "error": "revision_conflict",
        "recovery": {"action": "refresh_effective_controls"},
    }

    payload = _mutation_payload()
    payload["catalog_digest"] = "f" * 64
    with pytest.raises(ExtensionControlApiError) as catalog:
        service.preview(payload)
    assert (catalog.value.status, catalog.value.code) == (409, "catalog_conflict")

    malformed = _mutation_payload()
    malformed["layers"] = [{"kind": "invalid"}]
    with pytest.raises(ExtensionControlApiError) as invalid:
        service.preview(malformed)
    assert (invalid.value.status, invalid.value.code) == (400, "invalid_mutation")


@dataclass
class _FakeProof:
    proof_id: str = "proof-1"


class _ApplyingStore:
    def __init__(self, guard_home: Path) -> None:
        self.guard_home = guard_home
        self.events: list[tuple[str, dict[str, object], str]] = []
        self.commits = 0

    def commit_extension_control_layers(self, *_args: object, **_kwargs: object) -> ExtensionControlAuthorityView:
        self.commits += 1
        return ExtensionControlAuthorityView(
            AuthorityHealth.PROTECTED,
            5,
            BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
            (),
        )

    def add_event(self, event_name: str, payload: dict[str, object], now: str) -> None:
        self.events.append((event_name, payload, now))


def test_apply_requires_matching_server_held_proof_and_refreshes_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _ApplyingStore(tmp_path / "guard-home")
    service = _service(cast(GuardStore, store))
    monkeypatch.setattr(
        extension_control_api_module,
        "issue_extension_control_proof",
        lambda *_args, **_kwargs: cast(ExtensionControlProof, _FakeProof()),
    )
    payload = _mutation_payload()
    payload.update(
        {
            "session_nonce": "session-1",
            "approval_password": "not-persisted",
        }
    )

    preview = service.preview(payload)
    apply_payload = {**payload, "proof_id": preview["proof_id"]}
    result = service.apply(apply_payload)

    assert result["revision"] == 5
    assert store.commits == 1
    assert store.events[0][0] == "extension_control_authority_changed"
    assert "local-admin" not in json.dumps(store.events[0][1])
    assert service.apply(apply_payload) == result
    assert store.commits == 1
    assert len(store.events) == 1
    with pytest.raises(ExtensionControlApiError) as mismatch:
        service.apply({**apply_payload, "nonce": "different"})
    assert mismatch.value.code == "proof_mismatch"


def test_http_routes_authenticate_before_reading_sensitive_post_body(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    connection = http.client.HTTPConnection("127.0.0.1", daemon.port, timeout=2)
    try:
        request = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}/v1/extension-controls/catalog",
            method="GET",
        )
        with pytest.raises(urllib.error.HTTPError) as unauthorized:
            urllib.request.urlopen(request, timeout=2)
        assert unauthorized.value.code == 401

        auth_token = load_guard_daemon_auth_token(store.guard_home)
        assert auth_token is not None
        authenticated = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}/v1/extension-controls/catalog",
            method="GET",
            headers={"X-Guard-Dashboard-Session": _dashboard_token(auth_token)},
        )
        with urllib.request.urlopen(authenticated, timeout=2) as response:
            assert response.status == 200
            assert json.loads(response.read())["catalog_digest"] == (BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest)

        connection.putrequest("POST", "/v1/extension-controls/apply")
        connection.putheader("Content-Type", "application/json")
        connection.putheader("Content-Length", "1000000")
        connection.endheaders()
        response = connection.getresponse()
        assert response.status == 401
        response.read()
        connection.close()
        connection = http.client.HTTPConnection("127.0.0.1", daemon.port, timeout=2)
        connection.putrequest("POST", "/v1/extension-controls/apply")
        connection.putheader("X-Guard-Token", auth_token)
        connection.putheader("Content-Type", "application/json")
        connection.putheader("Content-Length", "1000001")
        connection.endheaders()
        response = connection.getresponse()
        client = GuardSurfaceDaemonClient(f"http://127.0.0.1:{daemon.port}", auth_token)
        refreshed = client.refresh_extension_controls()
        assert refreshed["health"] == "unenrolled"
        with pytest.raises(GuardDaemonRequestError) as not_degraded:
            client.acknowledge_degraded_extension_controls({})
        assert not_degraded.value.status == 409
        assert not_degraded.value.code == "authority_not_degraded"
        with pytest.raises(GuardDaemonRequestError) as unavailable:
            client.preview_extension_controls(_mutation_payload(revision=0))
        assert unavailable.value.status == 423
        assert unavailable.value.code == "authority_unavailable"
        assert unavailable.value.recovery_action == "enroll_or_repair_authority"

        assert response.status == 413
    finally:
        connection.close()
        daemon.stop()
