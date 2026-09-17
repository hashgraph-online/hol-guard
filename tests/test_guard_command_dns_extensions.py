"""Dedicated per-cloud DNS command extension tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.command_inspection import inspect_command
from tests.command_extension_contracts import assert_reviewed_command_cases, assert_safe_command_cases

DNS_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    ("aws route53 delete-hosted-zone --id Z123", "AWS DNS destructive command", "command.dns.aws.zone-deletion"),
    (
        "aws route53 delete-query-logging-config --id abc",
        "AWS DNS destructive command",
        "command.dns.aws.zone-deletion",
    ),
    (
        "aws route53 delete-reusable-delegation-set --id N123",
        "AWS DNS destructive command",
        "command.dns.aws.zone-deletion",
    ),
    (
        "aws --future-global-option account route53 delete-hosted-zone --id Z123",
        "AWS DNS destructive command",
        "command.dns.aws.zone-deletion",
    ),
    (
        "aws route53 change-resource-record-sets --hosted-zone-id Z123 --change-batch file://change.json",
        "AWS DNS destructive command",
        "command.dns.aws.record-change",
    ),
    (
        "aws route53 delete-health-check --health-check-id abc",
        "AWS DNS destructive command",
        "command.dns.aws.health-check-deletion",
    ),
    (
        "aws route53 disable-hosted-zone-dnssec --hosted-zone-id Z123",
        "AWS DNS destructive command",
        "command.dns.aws.dnssec-disable",
    ),
    (
        "aws route53resolver delete-resolver-endpoint --resolver-endpoint-id rslvr-in-123",
        "AWS DNS destructive command",
        "command.dns.aws.resolver-deletion",
    ),
    ("gcloud beta dns managed-zones delete public", "Google DNS destructive command", "command.dns.gcp.zone-deletion"),
    (
        "gcloud --filter active dns managed-zones delete public",
        "Google DNS destructive command",
        "command.dns.gcp.zone-deletion",
    ),
    (
        "gcloud dns record-sets delete www --zone public --type A",
        "Google DNS destructive command",
        "command.dns.gcp.record-deletion",
    ),
    (
        "gcloud dns policies delete office",
        "Google DNS destructive command",
        "command.dns.gcp.policy-deletion",
    ),
    (
        "az network dns zone delete -g app -n example.test",
        "Azure DNS destructive command",
        "command.dns.azure.public-zone-deletion",
    ),
    (
        "az --future-global-option tenant network dns zone delete -g app -n example.test",
        "Azure DNS destructive command",
        "command.dns.azure.public-zone-deletion",
    ),
    (
        "az network dns record-set a delete -g app -z example.test -n www",
        "Azure DNS destructive command",
        "command.dns.azure.public-record-deletion",
    ),
    (
        "az network private-dns zone delete -g app -n example.test",
        "Azure DNS destructive command",
        "command.dns.azure.private-zone-deletion",
    ),
    (
        "az dns-resolver delete -g app -n office",
        "Azure DNS destructive command",
        "command.dns.azure.resolver-deletion",
    ),
    (
        "aws route53resolver delete-firewall-rule --firewall-rule-group-id rslvr-frg-123 "
        "--firewall-domain-list-id rslvr-fdl-123",
        "AWS DNS destructive command",
        "command.dns.aws.resolver-deletion",
    ),
    (
        "az dns-resolver inbound-endpoint delete -g app --dns-resolver-name office -n inbound",
        "Azure DNS destructive command",
        "command.dns.azure.resolver-deletion",
    ),
    (
        "az dns-resolver vnet-link delete -g app --ruleset-name office -n link",
        "Azure DNS destructive command",
        "command.dns.azure.resolver-deletion",
    ),
)

DNS_SAFE_COMMANDS: tuple[str, ...] = (
    "aws route53 delete-hosted-zone --help",
    "aws route53 delete-hosted-zone --generate-cli-skeleton input",
    "aws route53 delete-query-logging-config --generate-cli-skeleton output",
    "aws --future-global-option account route53 delete-hosted-zone --id Z123 --help",
    "aws route53 list-hosted-zones",
    "aws --future-global-option account route53 list-hosted-zones",
    "aws route53resolver list-resolver-endpoints",
    "gcloud dns managed-zones delete --help",
    "gcloud dns managed-zones describe public",
    "gcloud --filter active dns managed-zones describe public",
    "gcloud dns record-sets list --zone public",
    "az network dns zone delete --help",
    "az --future-global-option tenant network dns zone delete -g app -n example.test --help",
    "az network dns zone show -g app -n example.test",
    "az network dns record-set a list -g app -z example.test",
    "az network private-dns zone list -g app",
    "grep 'delete-hosted-zone|managed-zones delete' docs",
    "printf '%s\\n' 'aws route53 delete-hosted-zone --id Z123'",
)


def test_dns_rules_feed_runtime_hooks(tmp_path: Path) -> None:
    assert_reviewed_command_cases(DNS_REVIEW_CASES, tmp_path)


def test_dns_observer_and_help_commands_remain_safe(tmp_path: Path) -> None:
    assert_safe_command_cases(DNS_SAFE_COMMANDS, tmp_path)


@pytest.mark.parametrize(
    ("command", "rule_id"),
    [
        ("aws route53 delete-hosted-zone --id Z123 > --help", "command.dns.aws.zone-deletion"),
        ("aws route53 delete-hosted-zone --id Z123 >--help", "command.dns.aws.zone-deletion"),
        (
            "aws route53 delete-hosted-zone --id Z123 << --help\npayload\n--help",
            "command.dns.aws.zone-deletion",
        ),
    ],
)
def test_help_redirection_target_does_not_hide_dns_command(command: str, rule_id: str, tmp_path: Path) -> None:
    payload = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)
    rules = payload["rules"]
    assert isinstance(rules, list)

    assert payload["status"] == "review"
    assert rule_id in {str(rule["rule_id"]) for rule in rules if isinstance(rule, dict) and "rule_id" in rule}


def test_lumped_dns_extension_is_not_registered() -> None:
    assert BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.dns") is None


def test_legacy_dns_controls_expand_onto_provider_extensions() -> None:
    from codex_plugin_scanner.guard.runtime.command_dns_extensions import expand_legacy_dns_layers
    from codex_plugin_scanner.guard.runtime.extension_control_contract import (
        CONTROL_SCHEMA_VERSION,
        ControlLayerKind,
        ControlState,
        ControlTarget,
        ControlTargetKind,
        ExtensionControl,
        ExtensionControlLayer,
    )

    layer = ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=ControlLayerKind.LOCAL_ADMIN,
        catalog_digest="a" * 64,
        global_lockdown=False,
        controls=(
            ExtensionControl(
                ControlTarget(ControlTargetKind.EXTENSION, "command.dns"),
                ControlState.DISABLED,
            ),
        ),
    )
    expanded = expand_legacy_dns_layers((layer,))
    assert len(expanded) == 1
    targets = {control.target.target_id for control in expanded[0].controls}
    assert targets == {"command.dns.aws", "command.dns.gcp", "command.dns.azure"}
    assert all(control.state is ControlState.DISABLED for control in expanded[0].controls)


def test_legacy_dns_expansion_merges_provider_collision_and_keeps_original_duplicates() -> None:
    from codex_plugin_scanner.guard.runtime.command_dns_extensions import expand_legacy_dns_layers
    from codex_plugin_scanner.guard.runtime.extension_control_contract import (
        CONTROL_SCHEMA_VERSION,
        ControlLayerKind,
        ControlState,
        ControlTarget,
        ControlTargetKind,
        ExtensionControl,
        ExtensionControlLayer,
    )

    def _layer(*controls: ExtensionControl) -> ExtensionControlLayer:
        return ExtensionControlLayer(
            schema_version=CONTROL_SCHEMA_VERSION,
            kind=ControlLayerKind.LOCAL_ADMIN,
            catalog_digest="a" * 64,
            global_lockdown=False,
            controls=controls,
        )

    def _control(target_id: str, state: ControlState) -> ExtensionControl:
        return ExtensionControl(ControlTarget(ControlTargetKind.EXTENSION, target_id), state)

    for controls in (
        (
            _control("command.dns", ControlState.ENABLED),
            _control("command.dns.aws", ControlState.DISABLED),
        ),
        (
            _control("command.dns.aws", ControlState.DISABLED),
            _control("command.dns", ControlState.ENABLED),
        ),
    ):
        merged = expand_legacy_dns_layers((_layer(*controls),))
        merged_states = {control.target.target_id: control.state for control in merged[0].controls}
        assert merged_states == {
            "command.dns.aws": ControlState.DISABLED,
            "command.dns.gcp": ControlState.ENABLED,
            "command.dns.azure": ControlState.ENABLED,
        }

    duplicated = expand_legacy_dns_layers(
        (
            _layer(
                _control("command.dns.aws", ControlState.DISABLED),
                _control("command.dns.aws", ControlState.DISABLED),
            ),
        )
    )
    assert [control.target.target_id for control in duplicated[0].controls] == [
        "command.dns.aws",
        "command.dns.aws",
    ]


def test_dns_extensions_are_provider_specific() -> None:
    for extension_id, executable in (
        ("command.dns.aws", "aws"),
        ("command.dns.gcp", "gcloud"),
        ("command.dns.azure", "az"),
    ):
        extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get(extension_id)
        assert extension is not None
        assert executable in extension.executables
        assert len(extension.rules) >= 4
        assert extension.reference_urls
        assert all(url.startswith("https://") for url in extension.reference_urls)


def test_azure_private_dns_is_not_owned_by_generic_cloud_pack(tmp_path: Path) -> None:
    payload = inspect_command(
        "az network private-dns zone delete -g app -n example.test",
        cwd=tmp_path,
        home_dir=tmp_path,
    )
    rules = payload["rules"]
    assert isinstance(rules, list)
    rule_ids = {str(rule["rule_id"]) for rule in rules if isinstance(rule, dict) and "rule_id" in rule}
    assert "command.dns.azure.private-zone-deletion" in rule_ids
    assert not any(rule_id.startswith("command.cloud.azure.") for rule_id in rule_ids)
