"""Direct command protection for .NET and NuGet package installation."""

from __future__ import annotations

from .command_extension_matchers import executable_matcher, safe_flag_variant
from .command_extension_specs import CommandExtensionSpec
from .command_rules import AnyMatcher, CommandSafetyRule

_DOTNET_INSTALL = AnyMatcher(
    matchers=(
        executable_matcher("dotnet", "package", "add"),
        executable_matcher("dotnet", "add", "package"),
        executable_matcher("nuget", "install"),
    )
)

DOTNET_COMMAND_RULES = (
    CommandSafetyRule(
        rule_id="command.package.dotnet.install",
        title=".NET package installation",
        description="Identifies dotnet and NuGet commands that install a package into a project or package directory.",
        severity="high",
        risk_classes=("supply_chain", "network_egress", "execution"),
        action_classes=(".NET package installation command",),
        safer_alternatives=(
            "Pin the package version and source, then review provenance and package contents before installation.",
        ),
        matcher=_DOTNET_INSTALL,
        safe_variants=(safe_flag_variant(_DOTNET_INSTALL, variant_id="help", title="Command help", flag="--help"),),
    ),
)

DOTNET_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.package.dotnet",
        name=".NET package protection",
        description="Reviews .NET and NuGet package installation commands before they can introduce package code.",
        action_classes=(".NET package installation command",),
        risk_classes=("supply_chain", "network_egress", "execution"),
        safer_alternatives=(
            "Pin package versions and sources and inspect package provenance before installation.",
        ),
        reference_urls=(
            "https://learn.microsoft.com/dotnet/core/tools/dotnet-package-add",
            "https://learn.microsoft.com/nuget/reference/cli-reference/cli-ref-install",
        ),
        executables=("dotnet", "nuget"),
        project_markers=("Directory.Packages.props", "packages.config", "packages.lock.json", "nuget.config"),
        example_command="dotnet package add Newtonsoft.Json",
    ),
)
