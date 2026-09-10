"""Dedicated DNS command protection for AWS, Google Cloud, and Azure CLIs."""

from __future__ import annotations

from dataclasses import replace

from . import command_managed_service_extensions as _cloud_cli
from .command_extension_matchers import (
    executable_matcher,
    executable_path_set_matcher,
    safe_flag_variant,
    safe_option_variant,
)
from .command_extension_specs import CommandExtensionSpec
from .command_rules import AnyMatcher, CommandRuleSeverity, CommandSafetyRule, CommandSafeVariant
from .extension_control_contract import (
    ControlState,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
)

_AWS_OPT = _cloud_cli.AWS_CLI_GLOBAL_OPTIONS
_AWS_FLAGS = _cloud_cli.AWS_CLI_GLOBAL_FLAGS
_GCLOUD_OPT = _cloud_cli.GCLOUD_CLI_GLOBAL_OPTIONS
_GCLOUD_FLAGS = _cloud_cli.GCLOUD_CLI_GLOBAL_FLAGS
_AZ_OPT = _cloud_cli.AZURE_CLI_GLOBAL_OPTIONS
_AZ_FLAGS = _cloud_cli.AZURE_CLI_GLOBAL_FLAGS
_PUBLIC_RECORD_TYPES = ("a", "aaaa", "caa", "cname", "ds", "mx", "ns", "ptr", "srv", "tlsa", "txt")
_PRIVATE_RECORD_TYPES = ("a", "aaaa", "cname", "mx", "ptr", "srv", "txt")
_DELETE = "Export records and confirm recovery or delegation controls before deletion."
_CHANGE = "Inspect the current record set and preview the intended change first."
_AWS_SKELETON_VALUES = frozenset({"input", "output", "yaml-input"})

_AWS = "command.dns.aws"
_GCP = "command.dns.gcp"
_AZURE = "command.dns.azure"
_AWS_ACT = "AWS DNS destructive command"
_GCP_ACT = "Google DNS destructive command"
_AZ_ACT = "Azure DNS destructive command"


def _aws(*subs: str) -> AnyMatcher:
    return AnyMatcher(
        matchers=(
            executable_matcher(
                "aws",
                *subs,
                global_options_with_values=_AWS_OPT,
                global_flags=_AWS_FLAGS,
                fail_secure_unknown_options=True,
            ),
        )
    )


def _aws_paths(*paths: tuple[str, ...]) -> AnyMatcher:
    return AnyMatcher(
        matchers=(
            executable_path_set_matcher(
                "aws",
                paths,
                global_options_with_values=_AWS_OPT,
                global_flags=_AWS_FLAGS,
                fail_secure_unknown_options=True,
            ),
        )
    )


def _gcloud(*subs: str) -> AnyMatcher:
    return AnyMatcher(
        matchers=tuple(
            executable_matcher(
                "gcloud",
                *((track,) if track else ()),
                *subs,
                global_options_with_values=_GCLOUD_OPT,
                global_flags=_GCLOUD_FLAGS,
                fail_secure_unknown_options=True,
            )
            for track in ("", "alpha", "beta")
        )
    )


def _az(*subs: str) -> AnyMatcher:
    return AnyMatcher(
        matchers=(
            executable_matcher(
                "az",
                *subs,
                global_options_with_values=_AZ_OPT,
                global_flags=_AZ_FLAGS,
                fail_secure_unknown_options=True,
            ),
        )
    )


def _az_paths(*paths: tuple[str, ...]) -> AnyMatcher:
    return AnyMatcher(
        matchers=(
            executable_path_set_matcher(
                "az",
                paths,
                global_options_with_values=_AZ_OPT,
                global_flags=_AZ_FLAGS,
                fail_secure_unknown_options=True,
            ),
        )
    )


def _join(*groups: AnyMatcher) -> AnyMatcher:
    return AnyMatcher(matchers=tuple(child for group in groups for child in group.matchers))


def _rule(
    rule_id: str,
    title: str,
    matcher: AnyMatcher,
    action: str,
    family: str,
    *,
    severity: CommandRuleSeverity = "critical",
    safer: str = _DELETE,
    example: str | None = None,
) -> CommandSafetyRule:
    variants: list[CommandSafeVariant] = [
        safe_flag_variant(matcher, variant_id="help", title=f"{title} help", flag="--help"),
    ]
    if family == "aws-route53":
        variants.append(
            safe_option_variant(
                matcher,
                variant_id="generate-cli-skeleton",
                title="AWS request skeleton",
                option="--generate-cli-skeleton",
                allowed_values=_AWS_SKELETON_VALUES,
            )
        )
    return CommandSafetyRule(
        rule_id=rule_id,
        title=title,
        description=f"Identifies {title.lower()} operations.",
        severity=severity,
        risk_classes=("destructive_shell", "network_egress"),
        action_classes=(action,),
        safer_alternatives=(safer,),
        matcher=matcher,
        family=family,
        example_command=example,
        safe_variants=tuple(variants),
    )


_AWS_ZONE = _aws_paths(
    ("route53", "delete-hosted-zone"),
    ("route53", "delete-query-logging-config"),
    ("route53", "delete-reusable-delegation-set"),
)
_AWS_RECORDS = _aws("route53", "change-resource-record-sets")
_AWS_HEALTH = _aws("route53", "delete-health-check")
_AWS_TRAFFIC = _aws_paths(
    ("route53", "delete-traffic-policy"),
    ("route53", "delete-traffic-policy-instance"),
)
_AWS_DNSSEC = _aws_paths(
    ("route53", "disable-hosted-zone-dnssec"),
    ("route53", "delete-key-signing-key"),
    ("route53", "deactivate-key-signing-key"),
)
_AWS_RESOLVER = _aws_paths(
    ("route53resolver", "delete-resolver-endpoint"),
    ("route53resolver", "delete-resolver-rule"),
    ("route53resolver", "delete-resolver-query-log-config"),
    ("route53resolver", "delete-firewall-rule-group"),
    ("route53resolver", "delete-firewall-rule"),
    ("route53resolver", "delete-firewall-domain-list"),
    ("route53resolver", "delete-outpost-resolver"),
)
_GCP_ZONE = _gcloud("dns", "managed-zones", "delete")
_GCP_RECORD_DELETE = _gcloud("dns", "record-sets", "delete")
_GCP_RECORD_UPDATE = _gcloud("dns", "record-sets", "update")
_GCP_RECORD_IMPORT = _gcloud("dns", "record-sets", "import")
_GCP_POLICY = _gcloud("dns", "policies", "delete")
_GCP_RESPONSE = _join(
    _gcloud("dns", "response-policies", "delete"),
    _gcloud("dns", "response-policies", "rules", "delete"),
)
_AZ_PUBLIC_ZONE = _az("network", "dns", "zone", "delete")
_AZ_PUBLIC_RECORDS = _az_paths(
    *(("network", "dns", "record-set", record_type, "delete") for record_type in _PUBLIC_RECORD_TYPES)
)
_AZ_PRIVATE_ZONE = _az("network", "private-dns", "zone", "delete")
_AZ_PRIVATE_RECORDS = _az_paths(
    *(("network", "private-dns", "record-set", record_type, "delete") for record_type in _PRIVATE_RECORD_TYPES)
)
_AZ_PRIVATE_LINK = _az("network", "private-dns", "link", "vnet", "delete")
_AZ_RESOLVER = _az_paths(
    ("dns-resolver", "delete"),
    ("dns-resolver", "inbound-endpoint", "delete"),
    ("dns-resolver", "outbound-endpoint", "delete"),
    ("dns-resolver", "forwarding-ruleset", "delete"),
    ("dns-resolver", "forwarding-rule", "delete"),
    ("dns-resolver", "vnet-link", "delete"),
    ("dns-resolver", "domain-list", "delete"),
)

DNS_COMMAND_RULES = (
    _rule(
        f"{_AWS}.zone-deletion",
        "Amazon Route 53 hosted-zone deletion",
        _AWS_ZONE,
        _AWS_ACT,
        "aws-route53",
        example="aws route53 delete-hosted-zone --id Z123",
    ),
    _rule(
        f"{_AWS}.record-change",
        "Amazon Route 53 record change",
        _AWS_RECORDS,
        _AWS_ACT,
        "aws-route53",
        safer=_CHANGE,
        example="aws route53 change-resource-record-sets --hosted-zone-id Z123 --change-batch file://change.json",
    ),
    _rule(
        f"{_AWS}.health-check-deletion",
        "Amazon Route 53 health-check deletion",
        _AWS_HEALTH,
        _AWS_ACT,
        "aws-route53",
        example="aws route53 delete-health-check --health-check-id abc",
    ),
    _rule(
        f"{_AWS}.traffic-policy-deletion",
        "Amazon Route 53 traffic-policy deletion",
        _AWS_TRAFFIC,
        _AWS_ACT,
        "aws-route53",
        example="aws route53 delete-traffic-policy --id policy123 --version 1",
    ),
    _rule(
        f"{_AWS}.dnssec-disable",
        "Amazon Route 53 DNSSEC disable",
        _AWS_DNSSEC,
        _AWS_ACT,
        "aws-route53",
        example="aws route53 disable-hosted-zone-dnssec --hosted-zone-id Z123",
    ),
    _rule(
        f"{_AWS}.resolver-deletion",
        "Amazon Route 53 Resolver deletion",
        _AWS_RESOLVER,
        _AWS_ACT,
        "aws-route53",
        example="aws route53resolver delete-resolver-endpoint --resolver-endpoint-id rslvr-in-123",
    ),
    _rule(
        f"{_GCP}.zone-deletion",
        "Google Cloud DNS managed-zone deletion",
        _GCP_ZONE,
        _GCP_ACT,
        "google-cloud-dns",
        example="gcloud dns managed-zones delete public",
    ),
    _rule(
        f"{_GCP}.record-deletion",
        "Google Cloud DNS record-set deletion",
        _GCP_RECORD_DELETE,
        _GCP_ACT,
        "google-cloud-dns",
        example="gcloud dns record-sets delete www --zone public --type A",
    ),
    _rule(
        f"{_GCP}.record-update",
        "Google Cloud DNS record-set update",
        _GCP_RECORD_UPDATE,
        _GCP_ACT,
        "google-cloud-dns",
        safer=_CHANGE,
        example="gcloud dns record-sets update www --zone public --type A --rrdatas 192.0.2.1",
    ),
    _rule(
        f"{_GCP}.record-import",
        "Google Cloud DNS record-set import",
        _GCP_RECORD_IMPORT,
        _GCP_ACT,
        "google-cloud-dns",
        safer=_CHANGE,
        example="gcloud dns record-sets import zone.zone --zone public",
    ),
    _rule(
        f"{_GCP}.policy-deletion",
        "Google Cloud DNS policy deletion",
        _GCP_POLICY,
        _GCP_ACT,
        "google-cloud-dns",
        example="gcloud dns policies delete office",
    ),
    _rule(
        f"{_GCP}.response-policy-deletion",
        "Google Cloud DNS response-policy deletion",
        _GCP_RESPONSE,
        _GCP_ACT,
        "google-cloud-dns",
        example="gcloud dns response-policies delete office",
    ),
    _rule(
        f"{_AZURE}.public-zone-deletion",
        "Azure DNS zone deletion",
        _AZ_PUBLIC_ZONE,
        _AZ_ACT,
        "azure-dns",
        example="az network dns zone delete -g app -n example.test",
    ),
    _rule(
        f"{_AZURE}.public-record-deletion",
        "Azure DNS record-set deletion",
        _AZ_PUBLIC_RECORDS,
        _AZ_ACT,
        "azure-dns",
        example="az network dns record-set a delete -g app -z example.test -n www",
    ),
    _rule(
        f"{_AZURE}.private-zone-deletion",
        "Azure private DNS zone deletion",
        _AZ_PRIVATE_ZONE,
        _AZ_ACT,
        "azure-dns",
        example="az network private-dns zone delete -g app -n example.test",
    ),
    _rule(
        f"{_AZURE}.private-record-deletion",
        "Azure private DNS record-set deletion",
        _AZ_PRIVATE_RECORDS,
        _AZ_ACT,
        "azure-dns",
        example="az network private-dns record-set a delete -g app -z example.test -n www",
    ),
    _rule(
        f"{_AZURE}.private-link-deletion",
        "Azure private DNS virtual-network link deletion",
        _AZ_PRIVATE_LINK,
        _AZ_ACT,
        "azure-dns",
        example="az network private-dns link vnet delete -g app -n spoke -z example.test",
    ),
    _rule(
        f"{_AZURE}.resolver-deletion",
        "Azure DNS resolver deletion",
        _AZ_RESOLVER,
        _AZ_ACT,
        "azure-dns",
        example="az dns-resolver delete -g app -n office",
    ),
)

DNS_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id=_AWS,
        name="Amazon Route 53 command protection",
        description=(
            "Reviews AWS Route 53 hosted-zone, record, health-check, traffic-policy, DNSSEC, and Resolver deletions."
        ),
        action_classes=(_AWS_ACT,),
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternatives=("Export zone records and inspect resolver associations before deletion.",),
        reference_urls=(
            "https://docs.aws.amazon.com/cli/latest/reference/route53/index.html",
            "https://docs.aws.amazon.com/cli/latest/reference/route53/delete-hosted-zone.html",
            "https://docs.aws.amazon.com/cli/latest/reference/route53/change-resource-record-sets.html",
            "https://docs.aws.amazon.com/cli/latest/reference/route53resolver/index.html",
        ),
        executables=("aws",),
    ),
    CommandExtensionSpec(
        extension_id=_GCP,
        name="Google Cloud DNS command protection",
        description=(
            "Reviews gcloud Cloud DNS managed-zone, record-set, policy, and response-policy deletions and updates."
        ),
        action_classes=(_GCP_ACT,),
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternatives=("Export record-sets and inspect forwarding policies before deletion.",),
        reference_urls=(
            "https://cloud.google.com/sdk/gcloud/reference/dns",
            "https://cloud.google.com/sdk/gcloud/reference/dns/managed-zones/delete",
            "https://cloud.google.com/sdk/gcloud/reference/dns/record-sets/delete",
            "https://cloud.google.com/sdk/gcloud/reference/dns/policies/delete",
        ),
        executables=("gcloud",),
    ),
    CommandExtensionSpec(
        extension_id=_AZURE,
        name="Azure DNS command protection",
        description=(
            "Reviews Azure public DNS, private DNS, virtual-network link, and DNS resolver deletion through Azure CLI."
        ),
        action_classes=(_AZ_ACT,),
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternatives=("Export zone records and inspect private DNS links before deletion.",),
        reference_urls=(
            "https://learn.microsoft.com/cli/azure/network/dns/zone",
            "https://learn.microsoft.com/cli/azure/network/dns/record-set",
            "https://learn.microsoft.com/cli/azure/network/private-dns/zone",
            "https://learn.microsoft.com/cli/azure/dns-resolver",
        ),
        executables=("az",),
    ),
)

LEGACY_DNS_EXTENSION_ID = "command.dns"
LEGACY_DNS_PERMISSION_ID = "command.dns.permission.delete"
DNS_PROVIDER_EXTENSION_IDS = (_AWS, _GCP, _AZURE)
DNS_ZONE_PERMISSION_IDS = (
    f"{_AWS}.permission.zone-deletion",
    f"{_GCP}.permission.zone-deletion",
    f"{_AZURE}.permission.public-zone-deletion",
)


def expand_legacy_dns_target(target: ControlTarget) -> tuple[ControlTarget, ...]:
    """Expand the retired aggregate DNS identifiers onto provider-specific targets."""

    if target.kind is ControlTargetKind.EXTENSION and target.target_id == LEGACY_DNS_EXTENSION_ID:
        return tuple(
            ControlTarget(ControlTargetKind.EXTENSION, extension_id) for extension_id in DNS_PROVIDER_EXTENSION_IDS
        )
    if target.kind is ControlTargetKind.PERMISSION and target.target_id == LEGACY_DNS_PERMISSION_ID:
        return tuple(
            ControlTarget(ControlTargetKind.PERMISSION, permission_id) for permission_id in DNS_ZONE_PERMISSION_IDS
        )
    return (target,)


def expand_legacy_dns_layers(layers: tuple[ExtensionControlLayer, ...]) -> tuple[ExtensionControlLayer, ...]:
    """Rewrite persisted aggregate DNS controls onto the provider-specific replacements.

    Expansion-induced collisions (legacy aggregate plus an already-present provider
    target) merge with disable dominance. Duplicate original targets stay duplicated
    so composition can still fail closed.
    """

    rewritten: list[ExtensionControlLayer] = []
    for layer in layers:
        merged: dict[ControlTarget, ControlState] = {}
        order: list[ControlTarget] = []
        extras: list[ExtensionControl] = []
        seen_originals: set[ControlTarget] = set()
        for control in layer.controls:
            expanded_targets = expand_legacy_dns_target(control.target)
            if control.target in seen_originals:
                extras.extend(ExtensionControl(target, control.state) for target in expanded_targets)
                continue
            seen_originals.add(control.target)
            for target in expanded_targets:
                previous = merged.get(target)
                if previous is None:
                    order.append(target)
                    merged[target] = control.state
                elif previous is ControlState.DISABLED or control.state is ControlState.DISABLED:
                    merged[target] = ControlState.DISABLED
        expanded = [ExtensionControl(target, merged[target]) for target in order]
        expanded.extend(extras)
        rewritten.append(replace(layer, controls=tuple(expanded)))
    return tuple(rewritten)
