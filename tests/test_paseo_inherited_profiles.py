"""Inherited provider execution and shared-hook disconnect contracts."""

from __future__ import annotations

import json

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.paseo import PaseoHarnessAdapter
from codex_plugin_scanner.guard.adapters.paseo_config import paseo_providers
from codex_plugin_scanner.guard.adapters.paseo_install import receipt_path
from codex_plugin_scanner.guard.cli.install_commands import build_harness_setup_plan
from tests.test_paseo_adapter import configure, statuses
from tests.test_paseo_adapter import context as context


@pytest.mark.security_critical
@pytest.mark.parametrize(
    "inherited",
    [
        {"command": ["pi", "--no-extensions"]},
        {"env": {"PI_CODING_AGENT_DIR": "/elsewhere"}},
        {"env": {"HOL_GUARD_DISABLED": "1"}},
        {"env": {"NODE_OPTIONS": "--require=/untrusted.js"}},
    ],
)
def test_inherited_provider_overrides_cannot_claim_native_protection(
    context: HarnessContext, inherited: dict[str, object]
) -> None:
    """A child's harmless environment does not erase unsafe base launch settings."""
    configure(
        context,
        {
            "pi": {"enabled": False, **inherited},
            "pi-work": {"extends": "pi", "label": "Work", "env": {"API_KEY": "test-secret"}},
        },
    )
    providers = {item.provider_id: item for item in paseo_providers(context)}
    assert providers["pi-work"].enabled is True
    assert providers["pi-work"].unsupported_reason
    with pytest.raises(ValueError, match="No supported, enabled"):
        PaseoHarnessAdapter().install(context)
    assert not receipt_path(context).exists()


def test_inherited_credentials_preserve_profile_support_without_entering_receipts(context: HarnessContext) -> None:
    """Ordinary inherited endpoint and credential settings do not disable native hooks."""
    configure(
        context,
        {
            "pi": {"enabled": False, "env": {"API_KEY": "private-base-credential"}},
            "pi-work": {"extends": "pi", "label": "Work", "env": {"API_BASE_URL": "https://models.test"}},
        },
    )
    manifest = PaseoHarnessAdapter().install(context)
    assert statuses(manifest)["pi-work"] == "native-hooks-installed"
    assert "private-base-credential" not in json.dumps(manifest)


def test_disconnect_plan_warns_that_native_protection_remains(context: HarnessContext) -> None:
    """Show shared-hook ownership before the operator confirms disconnection."""
    plan = build_harness_setup_plan("uninstall", "paseo", context, dry_run=True)
    step = plan["steps"][0]
    assert "receipt and launcher" in step["body"]
    assert "native provider protection remains installed" in step["body"]
    assert step["requires_confirmation"] is True


@pytest.mark.parametrize("artifact", ["settings.json", "extensions/hol-guard.ts"])
def test_reinstall_repairs_deleted_native_artifacts(context: HarnessContext, artifact: str) -> None:
    """Reinstall rebuilds drifted native settings/extensions and publishes fresh proofs."""
    configure(context, {"pi": {"enabled": True}})
    adapter = PaseoHarnessAdapter()
    adapter.install(context)
    target = context.home_dir / ".pi/agent" / artifact
    target.unlink()
    assert adapter.diagnostics(context)["setup_status"] == "broken"
    repaired = adapter.install(context)
    assert target.is_file()
    assert statuses(repaired)["pi"] == "native-hooks-installed"
    assert adapter.diagnostics(context)["setup_status"] == "active"
