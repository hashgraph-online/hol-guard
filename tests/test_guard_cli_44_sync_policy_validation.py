"""Guard CLI sync policy validation behavior."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.cli import commands as guard_commands_module
from codex_plugin_scanner.guard.runtime import runner as guard_runner_module
from codex_plugin_scanner.guard.store import GuardStore
from tests.cloud_exception_bundle_fixtures import build_cloud_exception_policy_bundle
from tests.guard_cli_cloud_support import _seed_guard_cloud
from tests.guard_cli_fixture_support import _build_guard_fixture
from tests.guard_cli_test_fixtures import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)
from tests.guard_cli_test_fixtures import (
    _use_legacy_update_context as _use_legacy_update_context,
)
from tests.policy_bundle_signing_helpers import sign_policy_bundle


class TestGuardCli:
    def test_synced_policy_payload_prefers_bundle_defaults(self, tmp_path):
        home_dir = tmp_path / "home"
        store = GuardStore(home_dir)
        _seed_guard_cloud(store)
        store.set_sync_payload(
            "policy",
            {
                "mode": "observe",
                "defaultAction": "allow",
                "unknownPublisherAction": "allow",
                "changedHashAction": "allow",
                "newNetworkDomainAction": "allow",
                "subprocessAction": "allow",
                "telemetryEnabled": True,
                "syncEnabled": False,
                "updatedAt": "2026-04-09T00:00:00Z",
            },
            "2026-04-09T00:00:00Z",
        )
        store.set_sync_payload(
            "policy_bundle",
            {
                "contractVersion": "guard-policy-bundle.v1",
                "bundleVersion": "policy-2026-04-09.1",
                "bundleHash": "sha256:cf9abe12666da1cbd99e0aeb7b94d15f34c5051bb69bff1e5208477f305e6362",
                "issuedAt": "2026-04-09T00:10:00Z",
                "expiresAt": None,
                "verifier": {
                    "algorithm": "rsa-pss-sha256",
                    "keyId": "guard-policy-bundle-v1",
                    "signature": None,
                },
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
            "2026-04-09T00:10:00Z",
        )
        cached_bundle = store.get_sync_payload("policy_bundle")
        assert isinstance(cached_bundle, dict)
        cached_bundle = sign_policy_bundle(cached_bundle)
        store.set_sync_payload("policy_bundle", cached_bundle, "2026-04-09T00:10:00Z")

        assert guard_commands_module._synced_policy_payload(store) == {
            "mode": "enforce",
            "defaultAction": "warn",
            "unknownPublisherAction": "review",
            "changedHashAction": "require-reapproval",
            "newNetworkDomainAction": "warn",
            "subprocessAction": "block",
            "telemetryEnabled": False,
            "syncEnabled": True,
            "updatedAt": "2026-04-09T00:10:00Z",
            "bundleHash": cached_bundle["bundleHash"],
            "bundleVersion": "policy-2026-04-09.1",
        }

    def test_synced_policy_payload_fails_closed_for_unauthenticated_cached_bundle(self, tmp_path):
        store = GuardStore(tmp_path / "home")
        _seed_guard_cloud(store)
        fallback_policy = {"mode": "observe", "defaultAction": "warn"}
        store.set_sync_payload("policy", fallback_policy, "2026-04-09T00:00:00Z")
        digest_bundle = build_cloud_exception_policy_bundle(workspace_id="workspace-1")
        digest_bundle["verifier"] = {
            "algorithm": "sha256",
            "keyId": "legacy-digest-only",
            "signature": None,
        }
        digest_bundle["bundleHash"] = guard_runner_module._computed_policy_bundle_hash(digest_bundle)
        store.set_sync_payload("policy_bundle", digest_bundle, "2026-04-09T00:10:00Z")

        assert guard_commands_module._synced_policy_payload(store) is None

    def test_guard_invalid_harness_returns_parser_error(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)

        with pytest.raises(SystemExit) as excinfo:
            main(
                [
                    "guard",
                    "detect",
                    "codxe",
                    "--home",
                    str(home_dir),
                    "--workspace",
                    str(workspace_dir),
                ]
            )

        assert excinfo.value.code == 2
        assert "Unsupported harness: codxe" in capsys.readouterr().err

    def test_guard_sync_without_login_returns_cli_error(self, tmp_path, capsys):
        home_dir = tmp_path / "home"

        rc = main(
            [
                "guard",
                "sync",
                "--home",
                str(home_dir),
            ]
        )

        assert rc == 1
        stderr = capsys.readouterr().err
        assert "Guard Cloud is not connected yet." in stderr
        assert "Run `hol-guard connect`" in stderr
