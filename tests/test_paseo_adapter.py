"""Paseo installation, ownership, configuration and coverage contracts."""

from __future__ import annotations

import json
import os
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import get_adapter
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.paseo import PaseoHarnessAdapter
from codex_plugin_scanner.guard.adapters.paseo_config import (
    PASEO_NATIVE_HARNESSES,
    paseo_config_path,
    paseo_providers,
    read_config_object,
)
from codex_plugin_scanner.guard.adapters.paseo_install import read_receipt, receipt_path
from codex_plugin_scanner.guard.cli.install_commands import apply_managed_install, build_harness_setup_plan
from codex_plugin_scanner.guard.inventory_contract import (
    inventory_snapshot_from_detection,
    serialize_inventory_snapshot,
)
from codex_plugin_scanner.guard.managed_install_proof import bind_managed_install_proof, verify_managed_install_proof
from codex_plugin_scanner.guard.store import GuardStore


@pytest.fixture
def context(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> HarnessContext:
    """Isolate native homes and substitute executable discovery without skipping installers."""
    home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    home.mkdir()
    workspace.mkdir()
    for key in list(os.environ):
        if key.startswith(("PASEO_", "PI_", "OMP_", "OPENCODE_", "CODEX_HOME", "CLAUDE_CONFIG", "XDG_")):
            monkeypatch.delenv(key)
    for harness in (*PASEO_NATIVE_HARNESSES.values(), "paseo"):
        # The actual installers run; only discovery of paid/authenticated CLIs is faked.
        monkeypatch.setattr(get_adapter(harness), "resolved_executable", lambda _context: sys.executable)
    return HarnessContext(
        home, workspace, tmp_path / "guard", home_override_explicit=True, workspace_override_explicit=True
    )


def write_json(path: Path, payload: object) -> None:
    """Write a deterministic JSON fixture inside the isolated test home."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def configure(context: HarnessContext, providers: dict[str, object]) -> Path:
    """Disable unrelated native providers while preserving unrelated Paseo settings."""
    entries: dict[str, object] = {name: {"enabled": False} for name in PASEO_NATIVE_HARNESSES}
    entries.update(providers)
    path = paseo_config_path(context)
    write_json(path, {"agents": {"providers": entries}, "plugins": {"enabled": False}, "custom": {"keep": True}})
    return path


def statuses(payload: dict[str, object]) -> dict[str, str]:
    """Index the public provider report by profile identity."""
    return {item["provider"]: item["status"] for item in payload["providers"]}


@pytest.mark.adapter_contract
@pytest.mark.parametrize("provider", tuple(PASEO_NATIVE_HARNESSES))
def test_paseo_installs_real_native_hooks_and_registers_native_proofs(context: HarnessContext, provider: str) -> None:
    """Exercise each real native installer and verify both native and composite records."""
    path = configure(context, {provider: {"enabled": True}})
    original = path.read_bytes()
    adapter = PaseoHarnessAdapter()
    manifest = adapter.install(context)
    native = PASEO_NATIVE_HARNESSES[provider]
    assert manifest["active"] is True
    assert statuses(manifest)[provider] == "native-hooks-installed"
    assert manifest["runtime_verification"] == "not-performed"
    assert manifest["coverage_status"] == "limited"
    assert path.read_bytes() == original
    assert verify_managed_install_proof(bind_managed_install_proof(manifest, context), context) is True
    native_install = GuardStore(context.guard_home).get_managed_install(native)
    assert native_install and native_install["active"]
    assert native_install["workspace"] is None
    assert verify_managed_install_proof(native_install["manifest"], context) is True
    assert not list(context.workspace_dir.rglob("*"))


def test_claude_preserves_user_hooks_and_installs_pretool_for_all_workspaces(context: HarnessContext) -> None:
    """Preserve user permissions and hooks while adding workspace-independent protection."""
    configure(context, {"claude": {"enabled": True}})
    settings = context.home_dir / ".claude/settings.json"
    user_hook = {"matcher": "Bash", "hooks": [{"type": "command", "command": "echo user-hook"}]}
    write_json(settings, {"hooks": {"PreToolUse": [user_hook]}, "permissions": {"allow": ["Read"]}})
    PaseoHarnessAdapter().install(context)
    result = json.loads(settings.read_text())
    assert result["permissions"] == {"allow": ["Read"]}
    assert user_hook in result["hooks"]["PreToolUse"]
    managed = [entry for entry in result["hooks"]["PreToolUse"] if entry != user_hook]
    assert managed
    assert str(context.workspace_dir) not in json.dumps(managed)


def test_shared_profiles_install_once_and_repeat_install_is_idempotent(
    context: HarnessContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Share one native installation across profiles without duplicating hooks during repair."""
    configure(context, {"pi": {"enabled": True}, "pi-work": {"extends": "pi", "label": "Work"}})
    native = get_adapter("pi")
    original_install = native.install
    calls: list[HarnessContext] = []

    def record_install(native_context: HarnessContext) -> dict[str, object]:
        """Record each real native install and the context it received."""
        calls.append(native_context)
        return original_install(native_context)

    monkeypatch.setattr(native, "install", record_install)
    adapter = PaseoHarnessAdapter()
    first = adapter.install(context)
    extension = context.home_dir / ".pi/agent/extensions/hol-guard.ts"
    original = extension.read_bytes()
    second = adapter.install(context)
    assert len(calls) == 2
    assert all(call.workspace_dir is None and not call.workspace_override_explicit for call in calls)
    assert extension.read_bytes() == original
    assert statuses(first)["pi-work"] == statuses(second)["pi-work"] == "native-hooks-installed"
    assert len(read_receipt(context)["native_proofs"]) == 1


@pytest.mark.security_critical
@pytest.mark.parametrize("changed_file", ("settings.json", "extensions/hol-guard.ts"))
def test_native_hook_drift_is_not_reported_as_protected(context: HarnessContext, changed_file: str) -> None:
    """Removing a required native artifact invalidates both diagnostics and the composite proof."""
    configure(context, {"pi": {"enabled": True}})
    adapter = PaseoHarnessAdapter()
    manifest = bind_managed_install_proof(adapter.install(context), context)
    (context.home_dir / ".pi/agent" / changed_file).unlink()
    assert verify_managed_install_proof(manifest, context) is False
    diagnosis = adapter.diagnostics(context)
    assert diagnosis["setup_status"] == "broken"
    assert statuses(diagnosis)["pi"] == "changed"


def test_uninstall_keeps_shared_hooks_settings_credentials_and_native_records(context: HarnessContext) -> None:
    """Paseo disconnection must not remove protection still used by other clients."""
    path = configure(context, {"pi": {"enabled": True, "env": {"API_KEY": "test-private-value"}}})
    adapter = PaseoHarnessAdapter()
    adapter.install(context)
    settings = context.home_dir / ".pi/agent/settings.json"
    extension = context.home_dir / ".pi/agent/extensions/hol-guard.ts"
    before = (path.read_bytes(), settings.read_bytes(), extension.read_bytes())
    assert adapter.uninstall(context)["active"] is False
    assert (path.read_bytes(), settings.read_bytes(), extension.read_bytes()) == before
    assert not receipt_path(context).exists()
    assert not (context.guard_home / "bin/guard-paseo").exists()
    assert GuardStore(context.guard_home).get_managed_install("pi")["active"] is True
    assert adapter.uninstall(context)["active"] is False


@pytest.mark.parametrize(
    "bad",
    [
        [],
        {"agents": []},
        {"agents": {"providers": []}},
        {"agents": {"providers": {"pi": {"enabled": "yes"}}}},
        {"agents": {"providers": {"../escape": {}}}},
        {"agents": {"providers": {"pi": {"env": {"HOME": 1}}}}},
    ],
)
def test_malformed_paseo_configuration_is_not_overwritten(context: HarnessContext, bad: object) -> None:
    """Invalid provider types fail before any native settings or Guard state are written."""
    path = paseo_config_path(context)
    write_json(path, bad)
    original = path.read_bytes()
    with pytest.raises(ValueError):
        PaseoHarnessAdapter().install(context)
    assert path.read_bytes() == original
    assert not context.guard_home.exists()


@pytest.mark.parametrize(
    "raw", [b'{"agents":', b"null", b'{"agents":{},"agents":{}}', b"\xff", b" " * (2 * 1024 * 1024 + 1)]
)
def test_unsafe_json_is_bounded_and_never_echoed(context: HarnessContext, raw: bytes) -> None:
    """Reject ambiguous, malformed, and oversized configuration without rewriting it."""
    path = configure(context, {})
    path.write_bytes(raw)
    with pytest.raises(ValueError, match="Cannot safely read configuration"):
        read_config_object(path)
    assert path.read_bytes() == raw


@pytest.mark.security_critical
@pytest.mark.parametrize("relative", [".pi", ".pi/agent/settings.json", ".pi/agent/extensions/hol-guard.ts"])
def test_native_symlink_targets_are_rejected_before_install(
    context: HarnessContext, tmp_path: Path, relative: str
) -> None:
    """Prevent native configuration writes from following links outside the declared home."""
    configure(context, {"pi": {"enabled": True}})
    target = tmp_path / "outside"
    link = context.home_dir / relative
    link.parent.mkdir(parents=True, exist_ok=True)
    if relative == ".pi":
        target.mkdir()
    else:
        target.write_text("{}", encoding="utf-8")
    try:
        link.symlink_to(target, target_is_directory=target.is_dir())
    except OSError:
        pytest.skip("This platform does not allow symlinks.")
    with pytest.raises(ValueError, match="symlink"):
        PaseoHarnessAdapter().install(context)
    assert target.is_dir() or target.read_text() == "{}"
    assert not context.guard_home.exists()


def test_preflight_checks_every_selected_provider_before_any_write(context: HarnessContext) -> None:
    """A later provider's invalid settings must prevent earlier native writes."""
    configure(context, {"claude": {"enabled": True}, "pi": {"enabled": True}})
    path = context.home_dir / ".pi/agent/settings.json"
    path.parent.mkdir(parents=True)
    path.write_text("not-json", encoding="utf-8")
    with pytest.raises(ValueError):
        PaseoHarnessAdapter().install(context)
    assert not (context.home_dir / ".claude/settings.json").exists()
    assert not context.guard_home.exists()


@pytest.mark.parametrize(
    "override",
    [
        {"command": ["pi", "--no-extensions"]},
        {"env": {"PI_CODING_AGENT_DIR": "/another-home"}},
        {"env": {"PATH": "/custom-bin"}},
        {"env": {"HOL_GUARD_DISABLED": "1"}},
        {"env": {"LD_PRELOAD": "/untrusted.so"}},
        {"env": {"PYTHONPATH": "/untrusted-python"}},
        {"env": {"BASH_ENV": "/untrusted.sh"}},
        {"env": {"NODE_OPTIONS": "--require=/untrusted.js"}},
    ],
)
def test_custom_provider_execution_is_explicitly_uncovered(
    context: HarnessContext, override: dict[str, object]
) -> None:
    """Keep custom execution excluded while preserving verified supported-provider status."""
    configure(context, {"pi": {"enabled": True}, "custom-pi": {"extends": "pi", "label": "Custom", **override}})
    manifest = PaseoHarnessAdapter().install(context)
    assert statuses(manifest)["pi"] == "native-hooks-installed"
    assert statuses(manifest)["custom-pi"] == "unsupported"
    assert PaseoHarnessAdapter().diagnostics(context)["setup_status"] == "active"


def test_default_providers_disabled_omp_and_acp_profile_contract(context: HarnessContext) -> None:
    """Match built-in defaults without assigning native coverage to an ACP profile."""
    defaults = {provider.provider_id: provider for provider in paseo_providers(context)}
    assert len(defaults) == 6
    assert defaults["omp"].enabled is False
    assert all(provider.enabled for name, provider in defaults.items() if name != "omp")
    configure(context, {"my-omp": {"extends": "omp", "label": "My OMP"}, "other": {"extends": "acp"}})
    providers = {provider.provider_id: provider for provider in paseo_providers(context)}
    assert providers["my-omp"].enabled is True
    assert providers["other"].native_harness is None
    assert providers["other"].unsupported_reason


def test_credentials_do_not_enter_manifest_diagnostics_or_inventory(context: HarnessContext) -> None:
    """Leave credentials in Paseo configuration but exclude them from exported Guard state."""
    secret = "sk-do-not-persist-this-paseo-provider-secret"
    path = configure(context, {"pi": {"enabled": True, "env": {"API_KEY": secret}}})
    adapter = PaseoHarnessAdapter()
    outputs = [adapter.install(context), adapter.diagnostics(context), read_receipt(context)]
    detection = adapter.detect(context)
    outputs.append(detection.to_dict())
    inventory = inventory_snapshot_from_detection(
        detection, generated_at="2026-09-11T00:00:00Z", home_dir=context.home_dir
    )
    outputs.append(serialize_inventory_snapshot(inventory))
    assert secret not in json.dumps(outputs)
    assert secret in path.read_text()


def test_home_selection_and_per_instance_receipts(context: HarnessContext, monkeypatch: pytest.MonkeyPatch) -> None:
    """Respect explicit homes and keep distinct daemon receipts separate."""
    custom = context.home_dir / "another-paseo"
    monkeypatch.setenv("PASEO_HOME", str(custom))
    assert paseo_config_path(context) == context.home_dir / ".paseo/config.json"
    inherited = replace(context, home_override_explicit=False)
    assert paseo_config_path(inherited) == custom / "config.json"
    assert receipt_path(context) != receipt_path(inherited)
    monkeypatch.setenv("PASEO_HOME", "~/custom-paseo")
    assert paseo_config_path(inherited) == context.home_dir / "custom-paseo/config.json"
    monkeypatch.setenv("PASEO_HOME", "relative-home")
    with pytest.raises(ValueError, match="absolute PASEO_HOME"):
        paseo_config_path(inherited)


def test_missing_runtime_cannot_create_an_active_install(
    context: HarnessContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Do not publish an installation receipt without an available supported native runtime."""
    configure(context, {"pi": {"enabled": True}})
    monkeypatch.setattr(get_adapter("pi"), "resolved_executable", lambda _context: None)
    with pytest.raises(ValueError, match="No supported, enabled"):
        PaseoHarnessAdapter().install(context)
    assert not receipt_path(context).exists()


def test_install_failure_preserves_last_receipt_and_shared_hooks(
    context: HarnessContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unchanged installation remains tracked when a repair fails before writing."""
    configure(context, {"pi": {"enabled": True}})
    adapter = PaseoHarnessAdapter()
    adapter.install(context)
    extension = context.home_dir / ".pi/agent/extensions/hol-guard.ts"
    original = extension.read_bytes()
    original_receipt = receipt_path(context).read_bytes()

    def fail(_context: HarnessContext) -> dict[str, object]:
        """Simulate a native installer failure after an earlier successful installation."""
        raise ValueError("test installation failure")

    monkeypatch.setattr(get_adapter("pi"), "install", fail)
    with pytest.raises(ValueError, match="test installation failure"):
        adapter.install(context)
    assert receipt_path(context).read_bytes() == original_receipt
    assert extension.read_bytes() == original
    assert adapter.diagnostics(context)["setup_status"] == "active"


def test_public_install_flow_and_dry_run_use_paseo_contract(context: HarnessContext) -> None:
    """Verify the public install summary, safe dry run, and workspace-free launcher."""
    configure(context, {"pi": {"enabled": True}})
    plan = build_harness_setup_plan("install", "paseo", context, dry_run=True)
    assert plan
    assert not context.guard_home.exists()
    store = GuardStore(context.guard_home)
    payload = apply_managed_install("install", "paseo", False, context, store, None, "2026-09-11T00:00:00Z")
    managed = payload["managed_install"]
    assert managed["primary_integration"] == "native-provider-hooks"
    assert managed["coverage_status"] == "limited"
    assert managed["native_hooks"] is False
    launcher = (context.guard_home / "bin/guard-paseo").read_text()
    assert str(context.workspace_dir) not in launcher
    assert "--workspace" not in launcher
    assert verify_managed_install_proof(managed["manifest"], context) is True


def test_omp_accepts_unrelated_linux_session_environment(
    context: HarnessContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Normal Linux desktop variables must not prevent installation of OMP hooks."""
    environment = {"XDG_RUNTIME_DIR": "/run/user/1000", "XDG_SESSION_TYPE": "wayland"}
    configure(context, {"omp": {"enabled": True, "env": environment}})
    for key, value in environment.items():
        monkeypatch.setenv(key, value)
    manifest = PaseoHarnessAdapter().install(context)
    assert statuses(manifest)["omp"] == "native-hooks-installed"


def test_missing_enabled_native_runtime_reports_partial_coverage(
    context: HarnessContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unavailable enabled runtime cannot be hidden by another verified native install."""
    configure(context, {"pi": {"enabled": True}, "codex": {"enabled": True}})
    monkeypatch.setattr(get_adapter("codex"), "resolved_executable", lambda _context: None)
    adapter = PaseoHarnessAdapter()
    adapter.install(context)
    result = adapter.diagnostics(context)
    assert result["setup_status"] == "partial"
    assert statuses(result)["pi"] == "native-hooks-installed"
    assert statuses(result)["codex"] == "runtime-unavailable"


def test_opencode_unselected_config_files_do_not_invalidate_protection(context: HarnessContext) -> None:
    """Unrelated OpenCode-home files must not participate in Guard artifact proofs."""
    configure(context, {"opencode": {"enabled": True}})
    root = context.home_dir / ".config/opencode"
    write_json(root / "opencode.json", {})
    write_json(root / "opencode.jsonc", {})
    (root / "config.json").write_text("not an OpenCode configuration", encoding="utf-8")
    adapter = PaseoHarnessAdapter()
    manifest = bind_managed_install_proof(adapter.install(context), context)
    (root / "config.json").write_text("an unrelated edit", encoding="utf-8")
    write_json(root / "opencode.jsonc", {"unused": "changed"})
    assert verify_managed_install_proof(manifest, context) is True
    assert adapter.diagnostics(context)["setup_status"] == "active"


@pytest.mark.parametrize("provider,key", [("codex", "managed_hook_manifest_path"), ("opencode", "managed_plugin_path")])
def test_native_managed_artifacts_participate_in_paseo_proofs(context: HarnessContext, provider: str, key: str) -> None:
    """Deleting an authenticated manifest or managed plugin invalidates composite protection."""
    configure(context, {provider: {"enabled": True}})
    adapter = PaseoHarnessAdapter()
    manifest = bind_managed_install_proof(adapter.install(context), context)
    native = GuardStore(context.guard_home).get_managed_install(PASEO_NATIVE_HARNESSES[provider])
    artifact = Path(native["manifest"][key])
    artifact.unlink()
    assert verify_managed_install_proof(manifest, context) is False
    assert adapter.diagnostics(context)["setup_status"] == "broken"


def test_child_drift_before_receipt_publication_rejects_install(
    context: HarnessContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reject success when an earlier child changes before the composite receipt is written."""
    configure(context, {"claude": {"enabled": True}, "pi": {"enabled": True}})
    native = get_adapter("pi")
    original = native.install

    def change_earlier_install(native_context: HarnessContext) -> dict[str, object]:
        """Simulate another writer changing the first provider during the second install."""
        manifest = original(native_context)
        write_json(context.home_dir / ".claude/settings.json", {"changed": True})
        return manifest

    monkeypatch.setattr(native, "install", change_earlier_install)
    with pytest.raises(ValueError, match="Native protection changed"):
        PaseoHarnessAdapter().install(context)
    assert not receipt_path(context).exists()
    assert (context.home_dir / ".pi/agent/extensions/hol-guard.ts").is_file()


def test_paseo_capability_does_not_claim_uniform_fail_closed_hooks() -> None:
    """Keep the public failure-behavior claim consistent with the supported native providers."""
    from codex_plugin_scanner.guard.protection_capabilities import protection_capability_payloads

    capabilities = {item["harness"]: item for item in protection_capability_payloads()}
    assert capabilities["paseo"]["fail_open_on_hook_failure"] is True
    assert capabilities["paseo"]["limited"] is True
    assert "some providers continue" in capabilities["paseo"]["honesty_sentence"]


@pytest.mark.parametrize("include_native", [False, True])
def test_cloud_sync_preserves_native_inventories_without_sending_local_paseo_content(
    context: HarnessContext, monkeypatch: pytest.MonkeyPatch, include_native: bool
) -> None:
    """Keep unsupported composite events and content out of otherwise valid native cloud batches."""
    from types import SimpleNamespace

    from codex_plugin_scanner.guard import aibom_cli
    from codex_plugin_scanner.guard.aibom_content_upload import empty_content_upload_summary
    from codex_plugin_scanner.guard.inventory_contract import GuardAgentInventorySnapshot
    from codex_plugin_scanner.guard.runtime import runner

    generated = "2026-09-11T00:00:00Z"
    local = GuardAgentInventorySnapshot("paseo:local", "paseo:agent", "paseo", generated)
    native = GuardAgentInventorySnapshot("pi:native", "pi:agent", "pi", generated)
    snapshots = (local, native) if include_native else (local,)
    store = GuardStore(context.guard_home)
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: "workspace-1")
    sent: list[dict[str, object]] = []
    uploads: list[tuple[object, ...]] = []

    def collect(*_args, primary_content_sources, **_kwargs):
        """Provide local and native fixtures while exposing a local-only content candidate."""
        primary_content_sources.append(SimpleNamespace(snapshot_id=local.snapshot_id))
        if include_native:
            primary_content_sources.append(SimpleNamespace(snapshot_id=native.snapshot_id))
        return snapshots

    def request(_auth, *, data, **_kwargs):
        """Capture the outgoing cloud event body without making a network request."""
        sent.append(json.loads(data))
        return object()

    def upload(_store, _runner, auth, *, sources, **_kwargs):
        """Record content candidates passed to the uploader without transferring files."""
        uploads.append(sources)
        return empty_content_upload_summary(), auth

    monkeypatch.setattr(aibom_cli, "collect_aibom_snapshots", collect)
    monkeypatch.setattr(aibom_cli, "upload_primary_content_sources", upload)
    monkeypatch.setattr(runner, "_guard_events_sync_url", lambda url: url)
    monkeypatch.setattr(runner, "_guard_sync_request", request)
    monkeypatch.setattr(runner, "_urlopen_json_with_timeout_retry", lambda **_kwargs: {"accepted": 1, "rejected": 0})
    summary = aibom_cli.sync_aibom_snapshots(
        store,
        context,
        generated_at=generated,
        auth_context={"sync_url": "https://hol.test/api/v1/guard/events", "token": "test-token"},
    )
    assert summary["synced"] is True
    assert summary["snapshots"] == int(include_native)
    assert len(sent) == int(include_native)
    assert all(event["payload"]["snapshot"]["agentType"] == "pi" for batch in sent for event in batch["events"])
    assert [source.snapshot_id for sources in uploads for source in sources] == (
        [native.snapshot_id] if include_native else []
    )
    assert serialize_inventory_snapshot(local)["agentType"] == "paseo"
    with pytest.raises(ValueError, match="local-only"):
        aibom_cli._inventory_snapshot_event(
            snapshot=local, workspace_id="workspace-1", device_id=None, generated_at=generated
        )
