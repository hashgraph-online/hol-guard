"""Shared matcher helpers for object-storage command extensions."""

from __future__ import annotations

from .command_extension_matchers import executable_matcher, safe_flag_variant, safe_option_variant
from .command_rules import AnyMatcher, CommandRuleMode, CommandRuleSeverity, CommandSafetyRule, CommandSafeVariant

_AWS_OPT = frozenset(
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
_GCLOUD_OPT = frozenset(
    {
        "--access-token-file",
        "--account",
        "--billing-project",
        "--configuration",
        "--filter",
        "--flags-file",
        "--flatten",
        "--format",
        "--impersonate-service-account",
        "--limit",
        "--page-size",
        "--project",
        "--sort-by",
        "--trace-token",
        "--verbosity",
    }
)
_GCLOUD_FLAGS = frozenset(
    {"--help", "--log-http", "--no-log-http", "--no-user-output-enabled", "--quiet", "--user-output-enabled", "-q"}
)
_AZ_OPT = frozenset({"--output", "-o", "--query", "--subscription"})
_AZ_FLAGS = frozenset({"--debug", "--only-show-errors", "--verbose"})
_MC_OPT = frozenset({"--config-dir", "-C", "--custom-header", "-H", "--resolve"})
_MC_FLAGS = frozenset(
    {"--debug", "--disable-pager", "--dp", "--dtrace", "--insecure", "--json", "--no-color", "--quiet"}
)
_NONE: frozenset[str] = frozenset()
_AWS_SKELETON_VALUES = frozenset({"input", "output", "yaml-input"})
_WRITE = "Inspect the destination and confirm overwrite or versioning controls first."
_READ = "Listing or reading objects does not change stored data."
_DELETE = "List the exact objects and confirm retention or recovery controls before deletion."


def _exe(
    name: str,
    *subs: str,
    required: frozenset[str] = _NONE,
    forbidden: frozenset[str] = _NONE,
    options: frozenset[str],
    flags: frozenset[str],
    fail_secure: bool = True,
    leading: frozenset[str] | None = None,
) -> AnyMatcher:
    return AnyMatcher(
        matchers=(
            executable_matcher(
                name,
                *subs,
                required_flags=required,
                forbidden_flags=forbidden,
                global_options_with_values=options,
                global_flags=flags,
                fail_secure_unknown_options=fail_secure,
                allow_leading_options=leading is not None,
                leading_options_with_values=leading or _NONE,
            ),
        )
    )


def _aws(*subs: str, required: frozenset[str] = _NONE, forbidden: frozenset[str] = _NONE) -> AnyMatcher:
    return _exe("aws", *subs, required=required, forbidden=forbidden, options=_AWS_OPT, flags=_AWS_FLAGS)


def _gcloud(*subs: str, required: frozenset[str] = _NONE, forbidden: frozenset[str] = _NONE) -> AnyMatcher:
    return _exe("gcloud", *subs, required=required, forbidden=forbidden, options=_GCLOUD_OPT, flags=_GCLOUD_FLAGS)


def _az(*subs: str) -> AnyMatcher:
    return _exe("az", *subs, options=_AZ_OPT, flags=_AZ_FLAGS)


def _mc(*subs: str, required: frozenset[str] = _NONE, forbidden: frozenset[str] = _NONE) -> AnyMatcher:
    return _exe(
        "mc", *subs, required=required, forbidden=forbidden, options=_MC_OPT, flags=_MC_FLAGS, fail_secure=False
    )


def _gsutil(*subs: str, required: frozenset[str] = _NONE) -> AnyMatcher:
    return _exe(
        "gsutil", *subs, required=required, options=_NONE, flags=_NONE, fail_secure=False, leading=frozenset({"-o"})
    )


def _join(*groups: AnyMatcher) -> AnyMatcher:
    return AnyMatcher(matchers=tuple(child for group in groups for child in group.matchers))


def _s3api(*operations: str) -> AnyMatcher:
    return _join(*(_aws("s3api", operation) for operation in operations))


def _rule(
    rule_id: str,
    title: str,
    matcher: AnyMatcher | None,
    action: str,
    family: str,
    *,
    mode: CommandRuleMode = "review",
    severity: CommandRuleSeverity = "high",
    safer: str = _WRITE,
    extra_safe: tuple[CommandSafeVariant, ...] = (),
    dry: tuple[AnyMatcher, str, str | None] | None = None,
    example: str | None = None,
) -> CommandSafetyRule:
    variants: list[CommandSafeVariant] = []
    if matcher is not None:
        variants.append(safe_flag_variant(matcher, variant_id="help", title=f"{title} help", flag="--help"))
        if dry is not None:
            dry_matcher, flag, inverse = dry
            variants.append(
                safe_flag_variant(
                    dry_matcher, variant_id="dry-run", title=f"{title} dry run", flag=flag, inverse_flag=inverse
                )
            )
        if family == "aws-s3":
            variants.append(
                safe_option_variant(
                    matcher,
                    variant_id="generate-cli-skeleton",
                    title=f"{title} request skeleton",
                    option="--generate-cli-skeleton",
                    allowed_values=_AWS_SKELETON_VALUES,
                )
            )
        variants.extend(extra_safe)
    return CommandSafetyRule(
        rule_id=rule_id,
        title=title,
        description=f"Identifies {title.lower()} operations.",
        severity=severity,
        risk_classes=("network_egress",) if mode == "disabled" else ("destructive_shell", "network_egress"),
        action_classes=(action,),
        safer_alternatives=(safer,),
        matcher=matcher,
        default_mode=mode,
        family=family,
        example_command=example,
        safe_variants=tuple(variants),
    )
