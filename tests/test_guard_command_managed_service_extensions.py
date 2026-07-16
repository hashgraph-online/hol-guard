"""Structured managed-service command extension tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.command_inspection import inspect_command
from codex_plugin_scanner.guard.runtime.secret_file_requests import extract_sensitive_tool_action_request


@pytest.mark.parametrize(
    ("command", "action_class", "rule_id"),
    [
        ("aws route53 delete-hosted-zone --id Z123", "DNS destructive command", "command.dns.delete"),
        (
            "aws --future-global-option account route53 delete-hosted-zone --id Z123",
            "DNS destructive command",
            "command.dns.delete",
        ),
        ("gcloud beta dns managed-zones delete public", "DNS destructive command", "command.dns.delete"),
        (
            "gcloud --filter active dns managed-zones delete public",
            "DNS destructive command",
            "command.dns.delete",
        ),
        ("az network dns zone delete -g app -n example.test", "DNS destructive command", "command.dns.delete"),
        (
            "az --future-global-option tenant network dns zone delete -g app -n example.test",
            "DNS destructive command",
            "command.dns.delete",
        ),
        (
            "aws cloudfront delete-distribution --id E123 --if-match etag",
            "CDN destructive command",
            "command.cdn.delete",
        ),
        ("az cdn endpoint delete -g app -n edge --profile-name main", "CDN destructive command", "command.cdn.delete"),
        (
            "aws apigateway delete-rest-api --rest-api-id api123",
            "API gateway destructive command",
            "command.api-gateway.delete",
        ),
        (
            "gcloud api-gateway gateways delete public-api --location us-central1",
            "API gateway destructive command",
            "command.api-gateway.delete",
        ),
        ("az apim delete -g app -n public-api --yes", "API gateway destructive command", "command.api-gateway.delete"),
        (
            "aws elbv2 delete-load-balancer --load-balancer-arn arn:value",
            "Load balancer destructive command",
            "command.load-balancer.delete",
        ),
        (
            "gcloud preview compute forwarding-rules delete public-ip --global",
            "Load balancer destructive command",
            "command.load-balancer.delete",
        ),
        (
            "az network lb delete -g app -n public-lb",
            "Load balancer destructive command",
            "command.load-balancer.delete",
        ),
        (
            "aws cloudwatch delete-alarms --alarm-names latency",
            "Monitoring destructive command",
            "command.monitoring.delete",
        ),
        (
            "gcloud beta monitoring policies delete policy123",
            "Monitoring destructive command",
            "command.monitoring.delete",
        ),
        (
            "az monitor metrics alert delete -g app -n latency",
            "Monitoring destructive command",
            "command.monitoring.delete",
        ),
        (
            "aws sesv2 delete-email-identity --email-identity sender@example.test",
            "Email destructive command",
            "command.email.delete",
        ),
        (
            "ldcli flags delete --project-key app --feature-flag-key retired",
            "Feature flag destructive command",
            "command.feature-flags.delete",
        ),
        (
            "ldcli --output json flags delete --project-key app --feature-flag-key retired",
            "Feature flag destructive command",
            "command.feature-flags.delete",
        ),
        (
            "stripe products delete prod_123 --live",
            "Payment destructive command",
            "command.payment.delete",
        ),
        (
            "stripe --stripe-account acct_123 coupons delete promo_123",
            "Payment destructive command",
            "command.payment.delete",
        ),
        ("stripe.exe customers delete cus_123", "Payment destructive command", "command.payment.delete"),
        (
            "stripe webhook_endpoints delete we_123",
            "Payment destructive command",
            "command.payment.delete",
        ),
    ],
)
def test_managed_service_rules_feed_runtime_hooks(
    command: str,
    action_class: str,
    rule_id: str,
    tmp_path: Path,
) -> None:
    payload = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)

    assert payload["status"] == "review"
    assert payload["classification"]["action_class"] == action_class
    assert payload["controlling_rule_id"] == rule_id
    runtime_match = extract_sensitive_tool_action_request(
        "Shell",
        {"command": command},
        cwd=tmp_path,
        home_dir=tmp_path,
    )
    assert runtime_match is not None
    assert runtime_match.action_class == action_class


@pytest.mark.parametrize(
    "command",
    [
        "aws route53 delete-hosted-zone --help",
        "gcloud dns managed-zones delete --help",
        "az cdn profile delete --help",
        "aws --future-global-option account route53 delete-hosted-zone --id Z123 --help",
        "gcloud --future-global-option account dns managed-zones delete public --help",
        "az --future-global-option tenant network dns zone delete -g app -n example.test --help",
        "aws route53 list-hosted-zones",
        "aws --future-global-option account route53 list-hosted-zones",
        "gcloud dns managed-zones describe public",
        "gcloud --filter active dns managed-zones describe public",
        "az network lb show -g app -n public-lb",
        "az --future-global-option tenant network lb show -g app -n public-lb",
        "aws cloudwatch describe-alarms",
        "ldcli flags delete --help",
        "ldcli flags get --project-key app --feature-flag-key retired",
        "ldcli flags update --project-key app --feature-flag-key retired --data archive.json",
        "stripe products delete --help",
        "stripe products retrieve prod_123",
        "stripe products update prod_123 --active=false",
        "stripe payment_intents cancel pi_123",
        "grep 'delete-hosted-zone|flags delete|products delete' docs",
        "printf '%s\\n' 'aws cloudwatch delete-alarms --alarm-names latency'",
    ],
)
def test_managed_service_observer_and_help_commands_remain_safe(command: str, tmp_path: Path) -> None:
    payload = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)

    assert payload["status"] == "no_match"
    assert (
        extract_sensitive_tool_action_request(
            "Shell",
            {"command": command},
            cwd=tmp_path,
            home_dir=tmp_path,
        )
        is None
    )


def test_safe_managed_variant_does_not_hide_destructive_segment(tmp_path: Path) -> None:
    payload = inspect_command(
        "aws route53 delete-hosted-zone --help && stripe coupons delete promo_123",
        cwd=tmp_path,
        home_dir=tmp_path,
    )

    assert [rule["rule_id"] for rule in payload["rules"]] == ["command.payment.delete"]
    assert payload["controlling_rule_id"] == "command.payment.delete"


@pytest.mark.parametrize(
    ("command", "rule_id"),
    [
        ("aws route53 delete-hosted-zone --id Z123 > --help", "command.dns.delete"),
        ("aws route53 delete-hosted-zone --id Z123 >--help", "command.dns.delete"),
        ("stripe products delete prod_123 2> --help", "command.payment.delete"),
        ("stripe products delete prod_123 2>--help", "command.payment.delete"),
        ("aws route53 delete-hosted-zone --id Z123 << --help\npayload\n--help", "command.dns.delete"),
    ],
)
def test_help_redirection_target_does_not_hide_destructive_command(
    command: str,
    rule_id: str,
    tmp_path: Path,
) -> None:
    payload = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)

    assert payload["status"] == "review"
    assert rule_id in {rule["rule_id"] for rule in payload["rules"]}
    assert extract_sensitive_tool_action_request(
        "Shell",
        {"command": command},
        cwd=tmp_path,
        home_dir=tmp_path,
    ) is not None


def test_managed_service_extensions_publish_official_references() -> None:
    for extension_id in (
        "command.dns",
        "command.cdn",
        "command.api-gateway",
        "command.load-balancer",
        "command.monitoring",
        "command.email",
        "command.feature-flags",
        "command.payment",
    ):
        extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get(extension_id)

        assert extension is not None
        assert extension.reference_urls
        assert all(url.startswith("https://") for url in extension.reference_urls)
