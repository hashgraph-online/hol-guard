"""Render reviewed contribution data for native compilation and MCP metadata."""

from __future__ import annotations

from ..runtime.mcp_server_contribution import validate_mcp_contribution
from .errors import BuilderError
from .io import canonical_json, digest
from .models import Discovery, Metadata, Operation
from .review import DEFAULT_GUIDANCE, Decision, Review

COMMAND_SOURCE_SCHEMA = "guard.command-extension-source.v1"
COMMAND_FIXTURE_SCHEMA = "guard.command-extension-fixtures.v1"


def contribution_path(metadata: Metadata) -> str:
    family = "extensions" if metadata.kind == "cli" else "mcp-servers"
    return f"contributions/{family}/{metadata.contribution_id}.json"


def command_source_path(metadata: Metadata) -> str:
    return f"contributions/command-sources/{metadata.contribution_id}.json"


def command_fixture_path(metadata: Metadata) -> str:
    return f"tests/fixtures/command-source-{metadata.slug}.v1.json"


def test_path(metadata: Metadata) -> str:
    return f"tests/test_generated_{metadata.kind}_{metadata.slug.replace('-', '_')}_extension.py"


def revision_digest(discovery: Discovery, review: Review) -> str:
    return digest({"discovery": discovery.to_dict(), "review": review.to_dict()})


def _risks(review: Review) -> tuple[str, ...]:
    return tuple(sorted({risk for _, decision in review.entries for risk in decision.risk_classes}))


def _executable_matcher(metadata: Metadata, operation: Operation | None) -> dict[str, object]:
    return {
        "op": "executable.v1",
        "config": {
            "executables": [metadata.executable],
            "subcommands": list(operation.path if operation else ()),
            "allow_leading_options": bool(operation and operation.path),
            "leading_options_with_values": list(operation.options_with_values if operation else ()),
            "interspersed_options_with_values": list(operation.options_with_values if operation else ()),
            "interspersed_flags": list(operation.flags if operation else ()),
            "options_with_values": [],
            "required_flags": [],
            "required_flags_in_all_arguments": False,
            "required_option_values": [],
            "forbidden_flags": [],
            "inverse_flag_pairs": [],
            "fail_secure_unknown_options": bool(operation and operation.path),
        },
    }


def _literal_matcher(metadata: Metadata, argv: tuple[str, ...]) -> dict[str, object]:
    return {"op": "reviewed-literal.v1", "config": {"executable": metadata.executable, "arguments": list(argv)}}


def render_command_source(discovery: Discovery, review: Review) -> str:
    metadata = discovery.metadata
    decisions = review.by_id()
    revision = f"1.0.{int(revision_digest(discovery, review)[:16], 16)}"
    action_class = f"{metadata.catalog_id} invocation"
    permissions: list[dict[str, object]] = []
    rules: list[dict[str, object]] = []
    for operation in (None, *discovery.operations):
        suffix = "unclassified" if operation is None else operation.operation_id
        decision = Decision("review") if operation is None else decisions[operation.operation_id]
        permission_id = f"{metadata.catalog_id}.permission.{suffix}"
        title = "Unclassified invocation" if operation is None else (" ".join(operation.path) or "Root invocation")[:96]
        description = "Reviews inventoried operations; unknown invocations also require review."
        permissions.append(
            {
                "permission_id": permission_id,
                "implementation_version": revision,
                "label": title,
                "description": description,
                "risk_tier": "high" if decision.state == "block" else "medium",
                "baseline_floor": "block" if decision.state == "block" else "review",
                "default_enabled": True,
                "configurable": operation is not None,
                "fixed_reason": None if operation is not None else "Unknown operations retain review.",
                "typed_capabilities": [],
                "action_classes": [action_class],
                "dependencies": [],
                "conflicts": [],
                "implied_permissions": [],
                "introduced_version": "1.0.0",
                "deprecated": False,
                "safer_guidance": [decision.safer_alternative],
                "example_command": " ".join((metadata.executable, *(operation.path if operation else ())))[:120],
            }
        )
        rules.append(
            {
                "rule_id": f"{metadata.catalog_id}.{suffix}",
                "rule_version": revision,
                "permission_id": permission_id,
                "title": title,
                "description": description,
                "severity": "high" if decision.state == "block" else "medium",
                "risk_classes": list(decision.risk_classes),
                "action_classes": [action_class],
                "safer_alternatives": [decision.safer_alternative],
                "default_mode": "enforce" if decision.state == "block" else "review",
                "matcher": _executable_matcher(metadata, operation),
                "safe_variants": [
                    {
                        "variant_id": f"literal-{digest(list(argv))[:16]}",
                        "title": "Explicitly reviewed literal invocation",
                        "matcher": _literal_matcher(metadata, argv),
                    }
                    for argv in decision.safe_argv
                ],
            }
        )
    return canonical_json(
        {
            "schema": COMMAND_SOURCE_SCHEMA,
            "extension": {
                "extension_id": metadata.catalog_id,
                "version": "1.0.0",
                "name": metadata.name,
                "description": "Conservative operation knowledge compiled from a contributor inventory.",
                "action_classes": [action_class],
                "risk_classes": list(_risks(review)),
                "safer_alternatives": [DEFAULT_GUIDANCE],
                "reference_urls": [metadata.homepage],
                "required": False,
                "source": "built-in",
                "aliases": [],
                "dependencies": [],
                "conflicts": [],
                "ecosystem_ids": [],
                "executables": [metadata.executable],
                "project_markers": [],
                "publisher": {
                    "id": metadata.publisher_id,
                    "display_name": metadata.publisher_name,
                    "url": metadata.homepage,
                },
                "homepage": metadata.homepage,
                "icon": {"kind": "none"},
                "license": None,
                "permissions": permissions,
                "rules": rules,
            },
        }
    )


def render_command_fixture_cases(discovery: Discovery, review: Review) -> list[dict[str, object]]:
    metadata = discovery.metadata
    decisions = review.by_id()
    cases: list[dict[str, object]] = []
    for operation in discovery.operations:
        decision = decisions[operation.operation_id]
        rule_id = f"{metadata.catalog_id}.{operation.operation_id}"
        cases.append(
            {
                "id": operation.operation_id,
                "command": " ".join((metadata.executable, *operation.path)),
                "enabled_extensions": [metadata.catalog_id],
                "disabled_permissions": [],
                "expected_action": decision.state,
                "rule_id": rule_id,
                "expected_effective_segments": [0],
            }
        )
        for index, argv in enumerate(decision.safe_argv):
            cases.append(
                {
                    "id": f"{operation.operation_id}-safe-{index}",
                    "command": " ".join((metadata.executable, *argv)),
                    "enabled_extensions": [metadata.catalog_id],
                    "disabled_permissions": [],
                    "expected_action": "review",
                    "rule_id": rule_id,
                    "expected_effective_segments": [],
                }
            )
    return cases


def render_contribution(discovery: Discovery, review: Review) -> str:
    metadata = discovery.metadata
    if metadata.kind != "mcp":
        raise BuilderError("native_contract", "CLI contribution descriptors must be generated by Rust.")
    decisions = review.by_id()
    payload: dict[str, object] = {
        "schemaVersion": "guard.mcp-server-contribution.v1",
        "id": metadata.contribution_id,
        "version": "1.0.0",
        "name": metadata.name,
        "description": "Conservative operation knowledge compiled from a contributor inventory.",
        "trustClass": "external",
        "activation": "opt-in",
        "publisher": {"id": metadata.publisher_id, "displayName": metadata.publisher_name},
        "icon": {"kind": "none"},
        "homepage": metadata.homepage,
        "referenceUrls": [metadata.homepage],
        "riskClasses": list(_risks(review)),
        "saferAlternatives": [DEFAULT_GUIDANCE],
        "launch": {"kind": "package-launcher", "command": metadata.launcher, "package": metadata.package},
        "tools": [
            {"name": operation.name, "state": decisions[operation.operation_id].state}
            for operation in discovery.operations
        ]
        + [{"name": "other", "state": "inherit"}],
    }
    try:
        validate_mcp_contribution(payload)
    except ValueError as exc:
        raise BuilderError(
            "native_contract", "Generated contribution is incompatible with the installed Guard schema."
        ) from exc
    return canonical_json(payload)
