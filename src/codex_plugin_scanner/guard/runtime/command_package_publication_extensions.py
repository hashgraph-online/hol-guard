"""First-class protection for package publication and withdrawal commands."""

from __future__ import annotations

from .command_extension_matchers import executable_matcher, safe_flag_variant
from .command_extension_specs import CommandExtensionSpec
from .command_rules import AnyMatcher, CommandSafetyRule

_PUBLICATION = AnyMatcher(
    matchers=(
        executable_matcher("npm", "publish"),
        executable_matcher("npm", "unpublish"),
        executable_matcher("npm", "deprecate"),
        executable_matcher("cargo", "publish"),
        executable_matcher("cargo", "yank"),
        executable_matcher("gem", "push"),
        executable_matcher("gem", "yank"),
        executable_matcher("twine", "upload"),
        executable_matcher("poetry", "publish"),
        executable_matcher("dotnet", "nuget", "push"),
        executable_matcher("dotnet", "nuget", "delete"),
        executable_matcher("nuget", "push"),
        executable_matcher("nuget", "delete"),
    )
)

PACKAGE_PUBLICATION_COMMAND_RULES = (
    CommandSafetyRule(
        rule_id="command.package-publication.remote-mutation",
        title="Package registry publication mutation",
        description="Identifies publication, withdrawal, deprecation, or yank operations against package registries.",
        severity="critical",
        risk_classes=("supply_chain", "network_egress", "destructive_shell"),
        action_classes=("package publication command",),
        safer_alternatives=(
            "Build and inspect the exact artifact, package name, version, registry, and signing/provenance evidence first.",
        ),
        matcher=_PUBLICATION,
        safe_variants=(safe_flag_variant(_PUBLICATION, variant_id="help", title="Command help", flag="--help"),),
    ),
)

PACKAGE_PUBLICATION_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.package-publication",
        name="Package publication protection",
        description="Reviews package publication, unpublish, deprecation, yank, and registry deletion operations.",
        action_classes=("package publication command",),
        risk_classes=("supply_chain", "network_egress", "destructive_shell"),
        safer_alternatives=(
            "Inspect the exact artifact, version, destination registry, and provenance before changing public supply-chain state.",
        ),
        reference_urls=(
            "https://docs.npmjs.com/cli/commands/npm-publish",
            "https://doc.rust-lang.org/cargo/commands/cargo-publish.html",
            "https://guides.rubygems.org/command-reference/#gem-push",
            "https://twine.readthedocs.io/",
            "https://learn.microsoft.com/dotnet/core/tools/dotnet-nuget-push",
        ),
    ),
)
