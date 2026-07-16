"""Structured rules and metadata for managed-service administration commands."""

from __future__ import annotations

from .command_extension_matchers import executable_matcher, safe_flag_variant
from .command_extension_specs import CommandExtensionSpec
from .command_rules import AnyMatcher, CommandSafetyRule

_AWS_OPTIONS = frozenset(
    {
        "--ca-bundle",
        "--cli-binary-format",
        "--cli-connect-timeout",
        "--cli-read-timeout",
        "--color",
        "--endpoint-url",
        "--output",
        "--profile",
        "--query",
        "--region",
    }
)
_AWS_FLAGS = frozenset(
    {
        "--cli-auto-prompt",
        "--debug",
        "--no-cli-auto-prompt",
        "--no-cli-pager",
        "--no-color",
        "--no-paginate",
        "--no-sign-request",
        "--no-verify-ssl",
    }
)
_GCLOUD_OPTIONS = frozenset(
    {
        "--access-token-file",
        "--account",
        "--billing-project",
        "--configuration",
        "--flags-file",
        "--format",
        "--impersonate-service-account",
        "--project",
        "--trace-token",
        "--verbosity",
    }
)
_GCLOUD_FLAGS = frozenset(
    {
        "--log-http",
        "--no-log-http",
        "--quiet",
        "-q",
        "--user-output-enabled",
        "--no-user-output-enabled",
    }
)
_AZURE_OPTIONS = frozenset({"--output", "-o", "--query", "--subscription"})
_AZURE_FLAGS = frozenset({"--debug", "--only-show-errors", "--verbose"})
_LDCLI_OPTIONS = frozenset(
    {
        "--access-token",
        "--base-uri",
        "--feature-flag-key",
        "--output",
        "--project-key",
        "-o",
    }
)
_LDCLI_FLAGS = frozenset({"--analytics-opt-out", "--json"})
_STRIPE_OPTIONS = frozenset(
    {
        "--api-key",
        "--color",
        "--config",
        "--device-name",
        "--log-level",
        "--project-name",
        "--stripe-account",
        "--stripe-version",
    }
)
_STRIPE_FLAGS = frozenset({"--live", "--latest", "--skip-verify"})


def _aws(*subcommands: str):
    return executable_matcher(
        "aws",
        *subcommands,
        global_options_with_values=_AWS_OPTIONS,
        global_flags=_AWS_FLAGS,
    )


def _gcloud(*subcommands: str, tracks: tuple[str, ...] = ("", "alpha", "beta")):
    return tuple(
        executable_matcher(
            "gcloud",
            *((track,) if track else ()),
            *subcommands,
            global_options_with_values=_GCLOUD_OPTIONS,
            global_flags=_GCLOUD_FLAGS,
        )
        for track in tracks
    )


def _azure(*subcommands: str):
    return executable_matcher(
        "az",
        *subcommands,
        global_options_with_values=_AZURE_OPTIONS,
        global_flags=_AZURE_FLAGS,
    )


_DNS_DELETE = AnyMatcher(
    matchers=(
        _aws("route53", "delete-hosted-zone"),
        *_gcloud("dns", "managed-zones", "delete"),
        _azure("network", "dns", "zone", "delete"),
    )
)
_CDN_DELETE = AnyMatcher(
    matchers=(
        _aws("cloudfront", "delete-distribution"),
        _azure("cdn", "profile", "delete"),
        _azure("cdn", "endpoint", "delete"),
    )
)
_API_GATEWAY_DELETE = AnyMatcher(
    matchers=(
        _aws("apigateway", "delete-rest-api"),
        _aws("apigatewayv2", "delete-api"),
        *_gcloud("api-gateway", "gateways", "delete"),
        *_gcloud("api-gateway", "apis", "delete"),
        _azure("apim", "delete"),
    )
)
_LOAD_BALANCER_DELETE = AnyMatcher(
    matchers=(
        _aws("elbv2", "delete-load-balancer"),
        *_gcloud("compute", "forwarding-rules", "delete", tracks=("", "alpha", "beta", "preview")),
        _azure("network", "lb", "delete"),
    )
)
_MONITORING_DELETE = AnyMatcher(
    matchers=(
        _aws("cloudwatch", "delete-alarms"),
        _azure("monitor", "metrics", "alert", "delete"),
        _azure("monitor", "activity-log", "alert", "delete"),
    )
)
_EMAIL_DELETE = AnyMatcher(
    matchers=(
        _aws("ses", "delete-identity"),
        _aws("sesv2", "delete-email-identity"),
        _aws("sesv2", "delete-contact-list"),
    )
)
_FEATURE_FLAG_DELETE = AnyMatcher(
    matchers=(
        executable_matcher(
            "ldcli",
            "flags",
            "delete",
            global_options_with_values=_LDCLI_OPTIONS,
            global_flags=_LDCLI_FLAGS,
        ),
    )
)
_PAYMENT_DELETE = AnyMatcher(
    matchers=tuple(
        executable_matcher(
            "stripe",
            resource,
            "delete",
            global_options_with_values=_STRIPE_OPTIONS,
            global_flags=_STRIPE_FLAGS,
        )
        for resource in ("coupons", "customers", "products")
    )
)


def _rule(
    *,
    extension_id: str,
    title: str,
    matcher: AnyMatcher,
    action_class: str,
    safer_alternative: str,
) -> CommandSafetyRule:
    return CommandSafetyRule(
        rule_id=f"{extension_id}.delete",
        title=title,
        description=f"Identifies documented {title.lower()} operations through supported command-line tools.",
        severity="critical",
        risk_classes=("destructive_shell", "network_egress"),
        action_classes=(action_class,),
        safer_alternatives=(safer_alternative,),
        matcher=matcher,
        safe_variants=(safe_flag_variant(matcher, variant_id="help", title="Command help", flag="--help"),),
    )


MANAGED_SERVICE_COMMAND_RULES = (
    _rule(
        extension_id="command.dns",
        title="DNS zone deletion",
        matcher=_DNS_DELETE,
        action_class="DNS destructive command",
        safer_alternative="Export zone records and verify delegation before deleting the zone.",
    ),
    _rule(
        extension_id="command.cdn",
        title="CDN resource deletion",
        matcher=_CDN_DELETE,
        action_class="CDN destructive command",
        safer_alternative="Inspect active domains, origins, and traffic before deleting the resource.",
    ),
    _rule(
        extension_id="command.api-gateway",
        title="API gateway deletion",
        matcher=_API_GATEWAY_DELETE,
        action_class="API gateway destructive command",
        safer_alternative="Export the API definition and inspect active routes before deletion.",
    ),
    _rule(
        extension_id="command.load-balancer",
        title="Load balancer deletion",
        matcher=_LOAD_BALANCER_DELETE,
        action_class="Load balancer destructive command",
        safer_alternative="Inspect listeners, targets, DNS, and active traffic before deletion.",
    ),
    _rule(
        extension_id="command.monitoring",
        title="Monitoring resource deletion",
        matcher=_MONITORING_DELETE,
        action_class="Monitoring destructive command",
        safer_alternative="Export alert configuration and verify notification coverage before deletion.",
    ),
    _rule(
        extension_id="command.email",
        title="Email service resource deletion",
        matcher=_EMAIL_DELETE,
        action_class="Email destructive command",
        safer_alternative="Verify sending dependencies and export configuration before deletion.",
    ),
    _rule(
        extension_id="command.feature-flags",
        title="Feature flag deletion",
        matcher=_FEATURE_FLAG_DELETE,
        action_class="Feature flag destructive command",
        safer_alternative="Archive the flag and remove code references before permanent deletion.",
    ),
    _rule(
        extension_id="command.payment",
        title="Payment service resource deletion",
        matcher=_PAYMENT_DELETE,
        action_class="Payment destructive command",
        safer_alternative="Inspect dependent resources and prefer archival where the service supports it.",
    ),
)


def _spec(
    *,
    extension_id: str,
    name: str,
    description: str,
    action_class: str,
    safer_alternative: str,
    reference_urls: tuple[str, ...],
) -> CommandExtensionSpec:
    return CommandExtensionSpec(
        extension_id=extension_id,
        name=name,
        description=description,
        action_classes=(action_class,),
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternatives=(safer_alternative,),
        reference_urls=reference_urls,
    )


MANAGED_SERVICE_COMMAND_EXTENSION_SPECS = (
    _spec(
        extension_id="command.dns",
        name="DNS command protection",
        description="Reviews hosted-zone deletion through supported cloud CLIs.",
        action_class="DNS destructive command",
        safer_alternative="Export zone records and verify delegation before deletion.",
        reference_urls=(
            "https://docs.aws.amazon.com/cli/latest/reference/route53/delete-hosted-zone.html",
            "https://cloud.google.com/sdk/gcloud/reference/dns/managed-zones/delete",
            "https://learn.microsoft.com/cli/azure/network/dns/zone#az-network-dns-zone-delete",
        ),
    ),
    _spec(
        extension_id="command.cdn",
        name="CDN command protection",
        description="Reviews distribution, profile, and endpoint deletion through supported cloud CLIs.",
        action_class="CDN destructive command",
        safer_alternative="Inspect active domains, origins, and traffic before deletion.",
        reference_urls=(
            "https://docs.aws.amazon.com/cli/latest/reference/cloudfront/delete-distribution.html",
            "https://learn.microsoft.com/cli/azure/cdn/profile#az-cdn-profile-delete",
            "https://learn.microsoft.com/cli/azure/cdn/endpoint#az-cdn-endpoint-delete",
        ),
    ),
    _spec(
        extension_id="command.api-gateway",
        name="API gateway command protection",
        description="Reviews API and gateway deletion through supported cloud CLIs.",
        action_class="API gateway destructive command",
        safer_alternative="Export the API definition and inspect active routes before deletion.",
        reference_urls=(
            "https://docs.aws.amazon.com/cli/latest/reference/apigateway/delete-rest-api.html",
            "https://docs.aws.amazon.com/cli/latest/reference/apigatewayv2/delete-api.html",
            "https://cloud.google.com/sdk/gcloud/reference/api-gateway/gateways/delete",
            "https://learn.microsoft.com/cli/azure/apim#az-apim-delete",
        ),
    ),
    _spec(
        extension_id="command.load-balancer",
        name="Load balancer command protection",
        description="Reviews load-balancer and forwarding-rule deletion through supported cloud CLIs.",
        action_class="Load balancer destructive command",
        safer_alternative="Inspect listeners, targets, DNS, and active traffic before deletion.",
        reference_urls=(
            "https://docs.aws.amazon.com/cli/latest/reference/elbv2/delete-load-balancer.html",
            "https://cloud.google.com/sdk/gcloud/reference/compute/forwarding-rules/delete",
            "https://learn.microsoft.com/cli/azure/network/lb#az-network-lb-delete",
        ),
    ),
    _spec(
        extension_id="command.monitoring",
        name="Monitoring command protection",
        description="Reviews alarm and alert deletion through supported cloud CLIs.",
        action_class="Monitoring destructive command",
        safer_alternative="Export alert configuration and verify notification coverage before deletion.",
        reference_urls=(
            "https://docs.aws.amazon.com/cli/latest/reference/cloudwatch/delete-alarms.html",
            "https://learn.microsoft.com/cli/azure/monitor/metrics/alert#az-monitor-metrics-alert-delete",
            "https://learn.microsoft.com/cli/azure/monitor/activity-log/alert#az-monitor-activity-log-alert-delete",
        ),
    ),
    _spec(
        extension_id="command.email",
        name="Email service command protection",
        description="Reviews email identity and contact-list deletion through AWS CLI.",
        action_class="Email destructive command",
        safer_alternative="Verify sending dependencies and export configuration before deletion.",
        reference_urls=(
            "https://docs.aws.amazon.com/cli/latest/reference/ses/delete-identity.html",
            "https://docs.aws.amazon.com/cli/latest/reference/sesv2/delete-email-identity.html",
            "https://docs.aws.amazon.com/cli/latest/reference/sesv2/delete-contact-list.html",
        ),
    ),
    _spec(
        extension_id="command.feature-flags",
        name="Feature flag command protection",
        description="Reviews permanent feature-flag deletion through LaunchDarkly CLI.",
        action_class="Feature flag destructive command",
        safer_alternative="Archive the flag and remove code references before permanent deletion.",
        reference_urls=(
            "https://github.com/launchdarkly/ldcli",
            "https://launchdarkly.com/docs/api/feature-flags/delete-feature-flag",
        ),
    ),
    _spec(
        extension_id="command.payment",
        name="Payment service command protection",
        description="Reviews product, coupon, and customer deletion through Stripe CLI.",
        action_class="Payment destructive command",
        safer_alternative="Inspect dependent resources and prefer archival where supported.",
        reference_urls=(
            "https://docs.stripe.com/stripe-cli/use-cli",
            "https://docs.stripe.com/api/products/delete",
            "https://docs.stripe.com/api/customers/delete",
            "https://docs.stripe.com/api/coupons/delete",
        ),
    ),
)
