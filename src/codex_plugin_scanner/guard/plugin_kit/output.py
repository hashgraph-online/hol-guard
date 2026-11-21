"""Plain-text renderers for ``hol-guard plugin`` check, conformance and links results."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def write_check(result: Mapping[str, Any]) -> None:
    plugin = result.get("plugin") or {}
    name = plugin.get("name") or "(unnamed)"
    version = plugin.get("version")
    print(f"{name}{' ' + version if version else ''}")
    summary = result.get("summary") or {}
    parts = [
        f"{summary.get(key, 0)} {label}"
        for key, label in (
            ("skills", "skills"),
            ("mcp_servers", "MCP servers"),
            ("commands", "commands"),
            ("agents", "agents"),
        )
        if summary.get(key)
    ]
    if parts:
        print("  " + ", ".join(parts))
    diagnostics = result.get("diagnostics") or []
    if diagnostics:
        print()
    for item in diagnostics:
        location = f" {item.get('path')}" if item.get("path") else ""
        print(f"  {item.get('level', 'error')}: {item.get('code')}{location}")
        print(f"    {item.get('message')}")
    print()
    print("Runtimes:")
    for runtime in result.get("runtimes") or []:
        mark = "yes" if runtime.get("supported") else "no "
        dropped = runtime.get("dropped") or []
        note = f"  (drops {', '.join(dropped)})" if runtime.get("supported") and dropped else ""
        print(f"  {mark}  {runtime.get('runtime')}{note}")
    print()
    errors = int(summary.get("errors", 0))
    warnings = int(summary.get("warnings", 0))
    verdict = "passed" if result.get("passed") else "failed"
    print(f"Check {verdict}: {errors} errors, {warnings} warnings.")


_EFFECTS = {
    "reject_plugin": "Clients reject the whole plugin.",
    "ignore_field": "Clients ignore this field.",
    "invalid_component": "Clients treat this component type as invalid.",
    "disable_mcp": "Clients disable MCP for this plugin.",
    "skip_skill": "Clients skip this skill.",
    "skip_server": "Clients skip this server.",
}


def write_conformance(result: Mapping[str, Any]) -> None:
    plugin = result.get("plugin") or {}
    name = plugin.get("name") or "(unnamed)"
    version = plugin.get("version")
    print(f"{name}{' ' + version if version else ''}")
    components = result.get("components") or {}
    skills = len(components.get("skills") or [])
    servers = len(components.get("mcp_servers") or [])
    print(f"  Agent Plugins {result.get('version')}: {skills} skills, {servers} MCP servers")
    diagnostics = result.get("diagnostics") or []
    if diagnostics:
        print()
    for item in diagnostics:
        location = f" {item.get('path')}" if item.get("path") else ""
        section = f" (section {item.get('section')})" if item.get("section") else ""
        print(f"  {item.get('level', 'error')}: {item.get('code')}{location}{section}")
        print(f"    {item.get('message')}")
        effect = _EFFECTS.get(str(item.get("effect")))
        if effect:
            print(f"    {effect}")
    print()
    summary = result.get("summary") or {}
    verdict = "conforms" if result.get("passed") else "does not conform"
    print(
        f"The plugin {verdict} to {result.get('spec')}: "
        f"{int(summary.get('errors', 0))} errors, {int(summary.get('warnings', 0))} warnings."
    )


def write_links(result: Mapping[str, Any]) -> None:
    install = result.get("install") or []
    if not result.get("repository"):
        print("No GitHub repository found. Set repository in the plugin manifest to get install links.")
    for entry in install:
        print(f"{entry.get('runtime')}:")
        for command in entry.get("commands") or []:
            print(f"  {command}")
        if entry.get("verify"):
            print(f"  check: {entry['verify']}")
        print()
    hol = result.get("hol")
    if isinstance(hol, dict):
        print(f"Claim the HOL listing: {hol.get('connect')}")
        print(f"List a new plugin on HOL: {hol.get('submit')}")
        print()
    pending = [step for step in result.get("checklist") or [] if not step.get("done")]
    if pending:
        print("Next steps:")
        for step in pending:
            print(f"  - {step.get('message')}")
