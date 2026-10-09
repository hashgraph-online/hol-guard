from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import cast
from unittest.mock import Mock

import pytest

from codex_plugin_scanner.guard.daemon import extension_control_api as extension_control_api_module
from codex_plugin_scanner.guard.daemon import managed_controls_api as managed_controls_api_module
from codex_plugin_scanner.guard.daemon.extension_control_api import (
    ExtensionControlApiError,
    ExtensionControlApiService,
)
from codex_plugin_scanner.guard.local_dashboard_session import LOCAL_DASHBOARD_SESSION_AUDIENCE
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    CommandSafetyExtensionRegistry,
)
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityError,
    ExtensionControlAuthorityView,
)
from codex_plugin_scanner.guard.runtime.extension_control_limits import (
    MAX_DAEMON_CATALOG_RESPONSE_BYTES,
    advertised_extension_control_limits,
)
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
    limits = advertised_extension_control_limits()
    assert catalog["limits"] == {
        **limits,
        "max_body_bytes": MAX_DAEMON_CATALOG_RESPONSE_BYTES,
        "max_controls": limits["max_controls_total"],
    }
    projection = cast(dict[str, object], effective.pop("projection"))
    assert projection["schema_version"] == "guard.daemon.extension-control-projection.v1"
    assert projection["revision"] == effective["revision"]
    assert projection["catalog_digest"] == effective["catalog_digest"]
    assert projection["health"] == effective["health"]
    assert isinstance(projection["extensions"], list)
    assert isinstance(projection["permissions"], list)
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


def test_inspect_command_uses_existing_guard_home_and_runtime_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    service = _service(store)
    snapshot = service._runtime.current()
    inspected = {"status": "native_unavailable", "command": "git status"}
    inspector = Mock(return_value=inspected)
    monkeypatch.setattr(extension_control_api_module.command_inspection, "inspect_command", inspector)

    result = service.inspect_command(
        {
            "command": "  git status  ",
            "cwd": str(tmp_path),
            "home_dir": str(tmp_path),
        }
    )

    assert result is inspected
    inspector.assert_called_once_with(
        "git status",
        cwd=tmp_path,
        home_dir=tmp_path,
        guard_home=store.guard_home,
        extension_control_snapshot=snapshot,
    )


@pytest.mark.parametrize(
    ("payload", "code"),
    [
        ({"command": "", "cwd": "/tmp", "home_dir": "/tmp"}, "invalid_inspection_command"),
        ({"command": "x" * 4097, "cwd": "/tmp", "home_dir": "/tmp"}, "invalid_inspection_command"),
        ({"command": "echo ok", "cwd": "relative", "home_dir": "/tmp"}, "invalid_cwd"),
        ({"command": "echo ok", "cwd": "/tmp", "home_dir": "relative"}, "invalid_home_dir"),
    ],
)
def test_inspect_command_rejects_unbounded_or_non_absolute_input(
    tmp_path: Path,
    payload: dict[str, object],
    code: str,
) -> None:
    service = _service(GuardStore(tmp_path / "guard-home"))

    with pytest.raises(ExtensionControlApiError) as error:
        service.inspect_command(payload)

    assert error.value.status == 400
    assert error.value.code == code


def test_effective_response_projects_frozen_windows_terminal_commands(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "custom-guard-home")
    commands = {
        "shell": "powershell",
        "enroll": "& 'C:\\custom install\\hol-guard.exe' command --guard-home 'C:\\custom guard' controls enroll",
        "recover_authority": (
            "& 'C:\\custom install\\hol-guard.exe' command --guard-home 'C:\\custom guard' controls recover-authority"
        ),
    }
    builder = Mock(return_value=commands)
    monkeypatch.setattr(
        managed_controls_api_module,
        "frozen_windows_extension_control_commands",
        builder,
    )

    effective = _service(store).effective()

    assert effective["terminal_commands"] == commands
    builder.assert_called_once_with(store.guard_home)


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


def test_authority_recovery_consumes_daemon_bound_approval_before_repair(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    tampered = ExtensionControlAuthorityView(
        AuthorityHealth.TAMPERED,
        4,
        BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        (),
    )
    protected = replace(tampered, health=AuthorityHealth.PROTECTED, revision=5)
    service = ExtensionControlApiService(
        store=store,
        registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        runtime=ExtensionControlRuntime(tampered),
    )
    calls: list[str] = []
    monkeypatch.setattr(store, "read_extension_control_authority_for_registry", lambda _registry: tampered)
    monkeypatch.setattr(
        store,
        "recover_extension_control_authority",
        lambda **_kwargs: calls.append("recover") or protected,
    )
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

    effective = service.recover_authority({"approval_password": "secret", "session_nonce": "nonce"})

    assert effective["health"] == AuthorityHealth.PROTECTED.value
    assert effective["revision"] == 5
    assert calls == ["require", "consume", "recover"]


def test_authority_recovery_rejects_healthy_authority(tmp_path: Path) -> None:
    service = _service(GuardStore(tmp_path / "guard-home"))

    with pytest.raises(ExtensionControlApiError) as denied:
        service.recover_authority({"session_nonce": "nonce"})

    assert denied.value.status == 409
    assert denied.value.code == "authority_not_recoverable"


def test_authority_recovery_never_reports_success_while_still_tampered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    tampered = ExtensionControlAuthorityView(
        AuthorityHealth.TAMPERED,
        4,
        BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        (),
    )
    service = ExtensionControlApiService(
        store=store,
        registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        runtime=ExtensionControlRuntime(tampered),
    )
    monkeypatch.setattr(store, "read_extension_control_authority_for_registry", lambda _registry: tampered)
    monkeypatch.setattr(store, "recover_extension_control_authority", lambda **_kwargs: tampered)
    monkeypatch.setattr(extension_control_api_module, "require_extension_control", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(extension_control_api_module, "consume_extension_control_grant", lambda *_args, **_kwargs: None)

    with pytest.raises(ExtensionControlApiError) as denied:
        service.recover_authority({"approval_password": "secret", "session_nonce": "nonce"})

    assert denied.value.status == 503
    assert denied.value.code == "authority_recovery_incomplete"


def test_authority_recovery_returns_bounded_error_when_store_repair_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    tampered = ExtensionControlAuthorityView(
        AuthorityHealth.TAMPERED,
        4,
        BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        (),
    )
    service = ExtensionControlApiService(
        store=store,
        registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        runtime=ExtensionControlRuntime(tampered),
    )
    monkeypatch.setattr(store, "read_extension_control_authority_for_registry", lambda _registry: tampered)
    monkeypatch.setattr(
        store,
        "recover_extension_control_authority",
        lambda **_kwargs: (_ for _ in ()).throw(ExtensionControlAuthorityError("failed")),
    )
    monkeypatch.setattr(extension_control_api_module, "require_extension_control", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(extension_control_api_module, "consume_extension_control_grant", lambda *_args, **_kwargs: None)

    with pytest.raises(ExtensionControlApiError) as denied:
        service.recover_authority({"approval_password": "secret", "session_nonce": "nonce"})

    assert denied.value.status == 503
    assert denied.value.code == "authority_recovery_failed"


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
