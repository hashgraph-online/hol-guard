"""Structured rules and metadata for Google Search Console (GSC) CLI indexing and modification commands."""

from __future__ import annotations

from .command_extension_matchers import executable_matcher, safe_flag_variant
from .command_extension_specs import CommandExtensionSpec
from .command_rules import AnyMatcher, CommandSafetyRule, CommandSafeVariant

# CLI surface verified against gsc-cli v2.2.5:
# GSC indexing and removal operations interact directly with the Google Indexing API and
# Search Console API, consuming daily quota or notifying Googlebot of deletions.
# Read-only operations (inspect, status, top-queries, top-pages, performance, sitemaps-list, audit)
# remain safe and unblocked.

_GSC_GLOBAL_FLAGS = frozenset({"--json", "-j", "--debug"})
_GSC_GLOBAL_OPTIONS = frozenset({"--domain", "-d", "--key", "-k"})

_GSC_INDEX = AnyMatcher(
    matchers=(
        executable_matcher(
            "gsc",
            "index",
            global_flags=_GSC_GLOBAL_FLAGS,
            global_options_with_values=_GSC_GLOBAL_OPTIONS,
            fail_secure_unknown_options=True,
        ),
    )
)

_GSC_REMOVE = AnyMatcher(
    matchers=(
        executable_matcher(
            "gsc",
            "remove",
            global_flags=_GSC_GLOBAL_FLAGS,
            global_options_with_values=_GSC_GLOBAL_OPTIONS,
            fail_secure_unknown_options=True,
        ),
    )
)

_GSC_INDEX_SITEMAP = AnyMatcher(
    matchers=(
        executable_matcher(
            "gsc",
            "index-sitemap",
            global_flags=_GSC_GLOBAL_FLAGS,
            global_options_with_values=_GSC_GLOBAL_OPTIONS,
            fail_secure_unknown_options=True,
        ),
    )
)

_GSC_SITEMAPS_SUBMIT = AnyMatcher(
    matchers=(
        executable_matcher(
            "gsc",
            "sitemaps-submit",
            global_flags=_GSC_GLOBAL_FLAGS,
            global_options_with_values=_GSC_GLOBAL_OPTIONS,
            fail_secure_unknown_options=True,
        ),
    )
)

_GSC_CACHE_CLEAR = AnyMatcher(
    matchers=(
        executable_matcher(
            "gsc",
            "cache",
            "clear",
            global_flags=_GSC_GLOBAL_FLAGS,
            global_options_with_values=_GSC_GLOBAL_OPTIONS,
            fail_secure_unknown_options=True,
        ),
    )
)


def _help_variants(matcher: AnyMatcher, *, title: str) -> tuple[CommandSafeVariant, ...]:
    return (
        safe_flag_variant(matcher, variant_id="help", title=title, flag="--help"),
        safe_flag_variant(matcher, variant_id="short-help", title=title, flag="-h"),
    )


GSC_ACTION_RISK_CLASSES: dict[str, tuple[str, ...]] = {
    "google search console url index request command": ("network_egress",),
    "google search console url removal request command": ("destructive_shell", "network_egress"),
    "google search console bulk sitemap index command": ("network_egress",),
    "google search console sitemap submission command": ("network_egress",),
    "google search console cache purge command": ("destructive_shell",),
}

GSC_COMMAND_RULES = (
    CommandSafetyRule(
        rule_id="command.gsc.index",
        title="GSC URL indexing notification",
        description=(
            "Identifies `gsc index`, which submits a URL_UPDATED notification directly "
            "to the Google Indexing API, consuming daily quota."
        ),
        severity="high",
        risk_classes=("network_egress",),
        action_classes=("google search console url index request command",),
        safer_alternatives=(
            "Run gsc status <url> or gsc inspect <url> to verify current index state before submitting.",
        ),
        matcher=_GSC_INDEX,
        default_mode="review",
        safe_variants=_help_variants(_GSC_INDEX, title="GSC index command help"),
        example_command="gsc index",
    ),
    CommandSafetyRule(
        rule_id="command.gsc.remove",
        title="GSC URL removal notification",
        description=(
            "Identifies `gsc remove`, which instructs Googlebot that a URL has been deleted "
            "(URL_DELETED) via the Google Indexing API."
        ),
        severity="high",
        risk_classes=("destructive_shell", "network_egress"),
        action_classes=("google search console url removal request command",),
        safer_alternatives=(
            "Run gsc inspect <url> first to verify that the URL returns 404 or 410 before requesting removal.",
        ),
        matcher=_GSC_REMOVE,
        default_mode="review",
        safe_variants=_help_variants(_GSC_REMOVE, title="GSC remove command help"),
        example_command="gsc remove",
    ),
    CommandSafetyRule(
        rule_id="command.gsc.index-sitemap",
        title="GSC bulk sitemap indexing",
        description=(
            "Identifies `gsc index-sitemap`, which submits all URLs in an XML sitemap for bulk Google indexing."
        ),
        severity="high",
        risk_classes=("network_egress",),
        action_classes=("google search console bulk sitemap index command",),
        safer_alternatives=("Run gsc inspect-sitemap first to audit sitemap URL health before batch submitting.",),
        matcher=_GSC_INDEX_SITEMAP,
        default_mode="review",
        safe_variants=_help_variants(_GSC_INDEX_SITEMAP, title="GSC index-sitemap command help"),
        example_command="gsc index-sitemap",
    ),
    CommandSafetyRule(
        rule_id="command.gsc.sitemaps-submit",
        title="GSC sitemap submission",
        description=("Identifies `gsc sitemaps-submit`, which submits or re-submits an XML sitemap to Search Console."),
        severity="medium",
        risk_classes=("network_egress",),
        action_classes=("google search console sitemap submission command",),
        safer_alternatives=("Run gsc sitemaps-list first to verify already submitted sitemaps.",),
        matcher=_GSC_SITEMAPS_SUBMIT,
        default_mode="review",
        safe_variants=_help_variants(_GSC_SITEMAPS_SUBMIT, title="GSC sitemaps-submit command help"),
        example_command="gsc sitemaps-submit",
    ),
    CommandSafetyRule(
        rule_id="command.gsc.cache-clear",
        title="GSC offline cache purge",
        description=(
            "Identifies `gsc cache clear`, which purges locally stored search performance database snapshots."
        ),
        severity="medium",
        risk_classes=("destructive_shell",),
        action_classes=("google search console cache purge command",),
        safer_alternatives=("Run gsc cache status first to check cached snapshots before purging.",),
        matcher=_GSC_CACHE_CLEAR,
        default_mode="review",
        safe_variants=_help_variants(_GSC_CACHE_CLEAR, title="GSC cache clear command help"),
        example_command="gsc cache clear",
    ),
)

GSC_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.gsc",
        name="Google Search Console command protection",
        description=(
            "Reviews Google Search Console commands that submit indexing requests, notify removals, "
            "submit sitemaps, or purge local search performance cache."
        ),
        action_classes=(
            "google search console url index request command",
            "google search console url removal request command",
            "google search console bulk sitemap index command",
            "google search console sitemap submission command",
            "google search console cache purge command",
        ),
        risk_classes=("network_egress", "destructive_shell"),
        safer_alternatives=(
            "Run gsc status <url> or gsc inspect <url> to verify current index state before submitting.",
            "Run gsc inspect <url> first to verify that the URL returns 404 or 410 before requesting removal.",
            "Run gsc inspect-sitemap first to audit sitemap URL health before batch submitting.",
            "Run gsc sitemaps-list first to verify already submitted sitemaps.",
            "Run gsc cache status first to check cached snapshots before purging.",
        ),
        reference_urls=(
            "https://github.com/ApollosWave/gsc-cli",
            "https://developers.google.com/search/apis/indexing-api/v3/quickstart",
        ),
        executables=("gsc",),
        ecosystem_ids=("gsc", "seo"),
    ),
)
