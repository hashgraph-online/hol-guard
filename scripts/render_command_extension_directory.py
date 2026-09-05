#!/usr/bin/env python3
"""Render the contributor-facing directory from Guard's canonical registry."""

from __future__ import annotations

import argparse
from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    CommandSafetyExtension,
)
from codex_plugin_scanner.guard.runtime.extension_trust import trust_class_for

REPO_ROOT = Path(__file__).resolve().parents[1]
DIRECTORY_PATH = REPO_ROOT / "docs" / "guard" / "extensions" / "README.md"
START_MARKER = "<!-- BEGIN GENERATED EXTENSION DIRECTORY -->"
END_MARKER = "<!-- END GENERATED EXTENSION DIRECTORY -->"

CATEGORY_ORDER = (
    "Core safety",
    "Cloud and infrastructure",
    "Data and resilience",
    "Delivery and remote operations",
    "Managed services",
    "Package supply chain",
    "Specialized tools",
    "Other extensions",
)

CORE_EXTENSION_IDS = frozenset(
    {
        "command.container-runtime",
        "command.data-protection",
        "command.encoded-execution",
        "command.filesystem",
        "command.git",
        "command.guard-self-protection",
        "command.kubernetes-secrets",
        "command.shell-mutations",
        "command.system",
        "command.windows",
    }
)


def _category(extension_id: str) -> str:
    if extension_id in CORE_EXTENSION_IDS:
        return "Core safety"
    if extension_id in {
        "command.api-gateway",
        "command.cdn",
        "command.dns",
        "command.infrastructure-as-code",
        "command.kubernetes-operations",
        "command.load-balancer",
    } or extension_id.startswith("command.cloud."):
        return "Cloud and infrastructure"
    if extension_id.startswith(("command.backup.", "command.database.", "command.storage.")):
        return "Data and resilience"
    if extension_id == "command.github" or extension_id.startswith(
        ("command.cicd.", "command.platform.", "command.remote.")
    ):
        return "Delivery and remote operations"
    if extension_id in {
        "command.email",
        "command.feature-flags",
        "command.monitoring",
        "command.payment",
    } or extension_id.startswith(("command.messaging.", "command.search.")):
        return "Managed services"
    if extension_id.startswith("command.package."):
        return "Package supply chain"
    if extension_id == "command.skill-sunset" or extension_id.startswith("command.mcp-"):
        return "Specialized tools"
    return "Other extensions"


def _escape_cell(value: str) -> str:
    return " ".join(value.split()).replace("|", "\\|")


def _protection_model(extension: CommandSafetyExtension) -> str:
    if extension.required:
        return "Required core"
    if extension.delegated_protection == "package-firewall":
        return "Package Firewall"
    if trust_class_for(extension.extension_id) == "external":
        return "External opt-in"
    return "Built in"


def render_catalog() -> str:
    """Return the deterministic Markdown catalog for all built-in extensions."""

    grouped: dict[str, list[CommandSafetyExtension]] = {category: [] for category in CATEGORY_ORDER}
    for extension in BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions:
        grouped[_category(extension.extension_id)].append(extension)

    sections: list[str] = []
    for category in CATEGORY_ORDER:
        if not grouped[category]:
            continue
        rows = [
            f"### {category}",
            "",
            "| Extension | What it protects | Rules | Protection model |",
            "| :--- | :--- | ---: | :--- |",
        ]
        for extension in grouped[category]:
            description = _escape_cell(extension.description)
            protection_model = _protection_model(extension)
            rows.append(f"| `{extension.extension_id}` | {description} | {len(extension.rules)} | {protection_model} |")
        sections.append("\n".join(rows))
    return "\n\n".join(sections)


def render_document(current: str) -> str:
    """Replace the generated catalog while preserving hand-authored guidance."""

    if current.count(START_MARKER) != 1 or current.count(END_MARKER) != 1:
        raise ValueError("Extension directory must contain exactly one generated marker pair")
    prefix, remainder = current.split(START_MARKER, 1)
    _generated, suffix = remainder.split(END_MARKER, 1)
    return f"{prefix}{START_MARKER}\n\n{render_catalog()}\n\n{END_MARKER}{suffix}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail when the committed directory does not match the runtime registry.",
    )
    args = parser.parse_args(argv)

    current = DIRECTORY_PATH.read_text(encoding="utf-8")
    rendered = render_document(current)
    if args.check:
        if current != rendered:
            parser.error(
                "extension directory is stale; run `uv run python scripts/render_command_extension_directory.py`"
            )
        return 0
    DIRECTORY_PATH.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
