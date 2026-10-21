"""Optional command contracts run against authenticated installed packs.

The core registry remains core-only. Authored metadata grants no activation;
the resident receives a separately prepared pack set and signed policy first.
"""

from __future__ import annotations

import os
import time
from dataclasses import replace
from types import SimpleNamespace

import pytest

COMMAND_MODULES = {
    "test_retired_command_extension_continuity",
    "test_syngraphe_safe_evidence",
    "test_guard_extension_trust",
    *(
        f"test_guard_command_{name}_extensions"
        for name in (
            "agentbridge",
            "blitcp",
            "digline",
            "noodle",
            "ollama",
            "probe",
            "remote",
            "repo2nb",
            "tui_runner",
            "skill_sunset",
            "vttforge",
        )
    ),
}
METADATA_MODULES = {
    "test_guard_extension_directory_operations",
    "test_guard_extension_control_catalog_detail",
    "test_guard_workspace_cli_control_authority",
}


@pytest.fixture(scope="session")
def authored_command_catalog():
    from codex_plugin_scanner.guard.runtime.generated_command_catalog import GeneratedCommandCatalog
    from scripts.export_extension_directory import native_extensions
    from tests.native_command_test_support import _resolve_native_binary

    # Name the compiler explicitly: an installed wheel refuses an override from
    # the environment, and the shard leaves none exported.
    compiler = _resolve_native_binary("HOL_GUARD_NATIVE_TEST_SOURCE_COMPILER", "guard-command-source")
    with pytest.MonkeyPatch.context() as patch:
        if compiler is not None and not os.environ.get("HOL_GUARD_BUILD_SOURCE_COMPILER"):
            patch.setenv("HOL_GUARD_BUILD_SOURCE_COMPILER", str(compiler))
        return GeneratedCommandCatalog(native_extensions())


@pytest.fixture(autouse=True)
def optional_command_catalog(request, monkeypatch, tmp_path):
    module = request.module.__name__.rsplit(".", 1)[-1]
    optional_integration = (
        module == "test_native_command_evaluation_integration"
        and request.node.name == "test_real_native_payload_rejects_stale_snapshot"
    )
    if module not in COMMAND_MODULES | METADATA_MODULES and not optional_integration:
        return
    catalog = request.getfixturevalue("authored_command_catalog")
    if hasattr(request.module, "BUILT_IN_COMMAND_EXTENSION_REGISTRY"):
        monkeypatch.setattr(request.module, "BUILT_IN_COMMAND_EXTENSION_REGISTRY", catalog)
    if module == "test_guard_workspace_cli_control_authority":
        from tests import guard_extension_control_authority_fixtures

        monkeypatch.setattr(guard_extension_control_authority_fixtures, "BUILT_IN_COMMAND_EXTENSION_REGISTRY", catalog)
    if module not in COMMAND_MODULES and not optional_integration:
        return

    from codex_plugin_scanner.guard import native_command_model, native_hook_edge, native_policy_snapshot
    from codex_plugin_scanner.guard.catalog_delivery import preparation
    from codex_plugin_scanner.guard.runtime import command_evaluation
    from codex_plugin_scanner.guard.runtime.extension_control_authority import (
        AuthorityHealth,
        ExtensionControlAuthorityView,
    )
    from codex_plugin_scanner.guard.runtime.extension_control_contract import (
        CONTROL_SCHEMA_VERSION,
        ControlLayerKind,
        ControlState,
        ControlTarget,
        ControlTargetKind,
        ExtensionControl,
        ExtensionControlLayer,
    )
    from codex_plugin_scanner.guard.runtime.extension_control_runtime import ExtensionControlRuntimeSnapshot
    from tests import command_extension_contracts, mcp_policy_catalog_fixture
    from tests import native_command_test_support as support
    from tests.mcp_policy_native_fixture import _BINDINGS

    delivery = []
    original_prepare = preparation.prepare

    def private_prepare(verified, enabled, directory, **kwargs):
        # Preparation creates its parents for normal data IO. The synthetic
        # daemon also writes signed state here, which requires owner-only IO.
        assert directory.is_relative_to(tmp_path)
        assert directory.parent.name == "native-runtime"
        directory.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory.parent.chmod(0o700)
        return original_prepare(verified, enabled, directory, **kwargs)

    monkeypatch.setattr(preparation, "prepare", private_prepare)
    published_snapshots = {}
    original_snapshot = native_policy_snapshot.native_policy_snapshot_v3

    def capture_snapshot(**kwargs):
        snapshot = original_snapshot(**kwargs)
        published_snapshots[kwargs["guard_home"]] = snapshot
        return snapshot

    monkeypatch.setattr(native_policy_snapshot, "native_policy_snapshot_v3", capture_snapshot)
    monkeypatch.setattr(command_evaluation, "BUILT_IN_COMMAND_EXTENSION_REGISTRY", catalog)
    monkeypatch.setattr(command_extension_contracts, "BUILT_IN_COMMAND_EXTENSION_REGISTRY", catalog)
    monkeypatch.setattr(support, "BUILT_IN_COMMAND_EXTENSION_REGISTRY", catalog)
    current = [None]
    homes = {}
    monkeypatch.setattr(support, "native_test_guard_home", lambda **kwargs: current[0])
    original_home = command_evaluation._resolve_home
    monkeypatch.setattr(
        command_evaluation,
        "_resolve_home",
        lambda home: current[0] if home is None and current[0] is not None else original_home(home),
    )

    def close_homes():
        from codex_plugin_scanner.guard.native_resident_client import close_native_residents
        from tests.mcp_policy_native_fixture import _ADMITTED

        for home, _snapshot in homes.values():
            close_native_residents(home)
            _BINDINGS.pop(home, None)
            _ADMITTED.pop(home, None)

    request.addfinalizer(close_homes)

    def review(
        commands,
        *,
        cwd=None,
        home_dir=None,
        controls=(),
        managed_controls=(),
        global_lockdown=False,
        managed_global_lockdown=False,
        health=AuthorityHealth.PROTECTED,
    ):
        assert health is AuthorityHealth.PROTECTED
        if not delivery:
            delivery.append(request.getfixturevalue("mcp_policy_delivery"))
            monkeypatch.setattr(mcp_policy_catalog_fixture, "_DELIVERY", delivery)
        key = (controls, global_lockdown, managed_controls, managed_global_lockdown)
        if key not in homes:

            def layer(kind, values, lockdown):
                return ExtensionControlLayer(
                    schema_version=CONTROL_SCHEMA_VERSION,
                    kind=kind,
                    catalog_digest=catalog.catalog_digest,
                    global_lockdown=lockdown,
                    controls=tuple(
                        ExtensionControl(
                            target=ControlTarget(ControlTargetKind(kind), identity),
                            state=ControlState(state),
                        )
                        for kind, identity, state in values
                    ),
                )

            layers = (layer(ControlLayerKind.LOCAL_ADMIN, controls, global_lockdown),)
            if managed_controls or managed_global_lockdown:
                layers += (layer(ControlLayerKind.SIGNED_CLOUD, managed_controls, managed_global_lockdown),)
            store = SimpleNamespace(guard_home=tmp_path / f"policy-{len(homes)}")
            mcp_policy_catalog_fixture.admit_mcp_layers(store, layers)
            binding = _BINDINGS[store.guard_home]
            snapshot = ExtensionControlRuntimeSnapshot.from_authority_view(
                ExtensionControlAuthorityView(
                    health=health,
                    revision=binding["revision"],
                    catalog_digest=binding["catalog_digest"],
                    layers=tuple(replace(value, catalog_digest=binding["catalog_digest"]) for value in layers),
                    managed_revision=binding["managed_revision"],
                )
            )
            assert snapshot.effective_digest == binding["effective_digest"]
            homes[key] = (store.guard_home, snapshot)
        guard_home, snapshot = homes[key]
        current[0] = guard_home
        rows = []
        for command in commands:
            shell_home = home_dir or guard_home
            edge = native_hook_edge.review_raw_hook_native(
                payload={
                    "tool_name": "Bash",
                    "tool_input": {"command": command},
                    "guard_execution_environment": support._native_test_execution_environment(shell_home),
                },
                harness="claude-code",
                event="PreToolUse",
                guard_home=guard_home,
                cwd=cwd,
                home_dir=shell_home,
                source_ref_external_allowed=False,
                observe_mode=False,
                # Without a deadline the edge allows 0.75 s, which a cold resident
                # on a loaded Windows runner can miss.
                deadline=time.monotonic() + 5,
                policy_snapshot=published_snapshots[guard_home],
            )
            assert edge is not None, "authenticated optional command resident unavailable"
            payload = dict(edge["result"])
            # The hook default leaves 250 ms; loaded Windows runners need the full second.
            model = native_command_model.review_command_model_native(
                command, guard_home=guard_home, timeout_seconds=1.0
            )
            assert model is not None, "native command model unavailable"
            payload["command_model"] = model
            admitted = _BINDINGS[guard_home]
            evidence_binding = payload["command_extensions"]["binding"]
            for field in ("program_digest", "catalog_digest", "trust_digest"):
                assert evidence_binding[field] == admitted[field], field
            assert evidence_binding["control_effective_digest"] == admitted["effective_digest"]
            rows.append(support.RealNativeReviewFixture(command, payload, snapshot))
        return tuple(rows)

    monkeypatch.setattr(support, "real_native_review_fixtures", review)
