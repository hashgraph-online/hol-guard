"""Compile checked authoring contracts into ordinary in-tree contribution files."""

from __future__ import annotations

import ast

from jsonschema.exceptions import ValidationError

from ..runtime.extension_contribution import _validator as cli_contribution_validator
from ..runtime.mcp_server_contribution import validate_mcp_contribution
from .errors import BuilderError
from .io import canonical_json, digest
from .models import Discovery, Metadata, Operation
from .python_literals import LiteralCall, emit, quoted
from .review import DEFAULT_GUIDANCE, Decision, Review

RUNTIME_PATH = "src/codex_plugin_scanner/guard/runtime"


def contribution_path(metadata: Metadata) -> str:
    directory = "extensions" if metadata.kind == "cli" else "mcp-servers"
    return f"contributions/{directory}/{metadata.contribution_id}.json"


def detector_path(metadata: Metadata) -> str:
    return f"{RUNTIME_PATH}/{metadata.module_leaf}.py"


def test_path(metadata: Metadata) -> str:
    return f"tests/test_generated_{metadata.kind}_{metadata.slug.replace('-', '_')}_extension.py"


def constant_prefix(metadata: Metadata) -> str:
    return metadata.slug.upper().replace("-", "_")


def revision_digest(discovery: Discovery, review: Review) -> str:
    return digest({"discovery": discovery.to_dict(), "review": review.to_dict()})


def _risks(review: Review) -> tuple[str, ...]:
    return tuple(sorted({risk for _, decision in review.entries for risk in decision.risk_classes}))


def render_contribution(discovery: Discovery, review: Review) -> str:
    metadata = discovery.metadata
    payload: dict[str, object] = {
        "schemaVersion": f"guard.{'extension' if metadata.kind == 'cli' else 'mcp-server'}-contribution.v1",
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
    }
    if metadata.kind == "cli":
        payload.update(
            {
                "executables": [metadata.executable],
                "actionClasses": [f"{metadata.catalog_id} invocation"],
                "detector": {
                    "kind": "python-module",
                    "module": f"codex_plugin_scanner.guard.runtime.{metadata.module_leaf}",
                },
            }
        )
    else:
        decisions = review.by_id()
        payload.update(
            {
                "launch": {"kind": "package-launcher", "command": metadata.launcher, "package": metadata.package},
                "tools": [
                    {"name": operation.name, "state": decisions[operation.operation_id].state}
                    for operation in discovery.operations
                ]
                + [{"name": "other", "state": "inherit"}],
            }
        )
    try:
        if metadata.kind == "cli":
            # Shape only here. Native in-tree detector binding is additionally checked
            # by the normal contribution tests after explicit repository integration.
            cli_contribution_validator().validate(payload)
        else:
            validate_mcp_contribution(payload)
    except (ValidationError, ValueError) as exc:
        raise BuilderError(
            "native_contract", "Generated contribution is incompatible with the installed Guard schema."
        ) from exc
    return canonical_json(payload)


def _matcher_lines(operation: Operation | None) -> list[str]:
    if operation is None or not operation.path:
        return ["        matcher=ExecutableMatcher(executables=_EXECUTABLES),"]
    return [
        "        matcher=ExecutablePathSetMatcher(",
        "            executables=_EXECUTABLES,",
        *emit(LiteralCall("frozenset", (operation.path,)), prefix="            paths=", suffix=","),
        "            allow_leading_options=True,",
        *emit(
            LiteralCall("frozenset", operation.options_with_values),
            prefix="            leading_options_with_values=",
            suffix=",",
        ),
        *emit(
            LiteralCall("frozenset", operation.options_with_values),
            prefix="            interspersed_options_with_values=",
            suffix=",",
        ),
        *emit(LiteralCall("frozenset", operation.flags), prefix="            interspersed_flags=", suffix=","),
        "            fail_secure_unknown_options=True,",
        "        ),",
    ]


def _rule_lines(metadata: Metadata, operation: Operation | None, decision: Decision) -> list[str]:
    suffix = "unclassified" if operation is None else operation.operation_id
    path = () if operation is None else operation.path
    title = "Unclassified invocation" if operation is None else (" ".join(path) or "Root invocation")[:96]
    mode = "enforce" if decision.state == "block" else "review"
    example = " ".join((metadata.executable, *path))
    return [
        "    CommandSafetyRule(",
        f"        rule_id={quoted(f'{metadata.catalog_id}.{suffix}')},",
        "        rule_version=_RULE_REVISION,",
        *emit(title, prefix="        title=", suffix=","),
        '        description="Reviews inventoried operations; unknown invocations also require review.",',
        f"        severity={quoted('high' if mode == 'enforce' else 'medium')},",
        *emit(decision.risk_classes, prefix="        risk_classes=", suffix=","),
        "        action_classes=(_ACTION_CLASS,),",
        *emit((decision.safer_alternative,), prefix="        safer_alternatives=", suffix=","),
        f"        default_mode={quoted(mode)},",
        *_matcher_lines(operation),
        *emit(() if mode == "enforce" else LiteralCall("_safe_for", path), prefix="        safe_variants=", suffix=","),
        *emit(example if len(example) <= 120 else None, prefix="        example_command=", suffix=","),
        "    ),",
    ]


def render_detector(discovery: Discovery, review: Review) -> str:
    metadata = discovery.metadata
    prefix = constant_prefix(metadata)
    safe_vectors = tuple(sorted(argv for _, decision in review.entries for argv in decision.safe_argv))
    safe_rows = tuple((f"literal-{digest(list(argv))[:16]}", argv) for argv in safe_vectors)
    # The complete SHA-256 becomes a valid SemVer patch identifier. A changed
    # grammar or review cannot retain a prior rule version or remembered identity.
    revision = f"1.0.{int(revision_digest(discovery, review), 16)}"
    lines = [
        '"""Generated contributor knowledge. Review source semantics before enabling this extension."""',
        "",
        "from __future__ import annotations",
        "",
        "from .command_extension_specs import CommandExtensionSpec",
        *(
            ["from .command_path_set_matcher import ExecutablePathSetMatcher"]
            if any(row.path for row in discovery.operations)
            else []
        ),
        "from .command_reviewed_literal_matcher import ReviewedLiteralCommandMatcher",
        "from .command_rules import CommandSafetyRule, CommandSafeVariant, ExecutableMatcher",
        "",
        f"_EXECUTABLE = {quoted(metadata.executable)}",
        "_EXECUTABLES = frozenset((_EXECUTABLE,))",
        f"_ACTION_CLASS = {quoted(f'{metadata.catalog_id} invocation')}",
        f"_RULE_REVISION = {quoted(revision)}",
        *emit(safe_rows, prefix="_SAFE_ROWS: tuple[tuple[str, tuple[str, ...]], ...] = "),
        "",
        "",
        "def _safe_for(path: tuple[str, ...]) -> tuple[CommandSafeVariant, ...]:",
        "    return tuple(",
        "        CommandSafeVariant(",
        "            variant_id=variant_id,",
        '            title="Explicitly reviewed literal invocation",',
        "            matcher=ReviewedLiteralCommandMatcher(_EXECUTABLE, argv),",
        "        )",
        "        for variant_id, argv in _SAFE_ROWS",
        "        if tuple(part.lower() for part in argv[: len(path)]) == tuple(part.lower() for part in path)",
        "    )",
        "",
        "",
        f"{prefix}_COMMAND_RULES = (",
        *_rule_lines(metadata, None, Decision("review")),
    ]
    decisions = review.by_id()
    for operation in discovery.operations:
        lines.extend(_rule_lines(metadata, operation, decisions[operation.operation_id]))
    lines.extend(
        [
            ")",
            "",
            f"{prefix}_COMMAND_EXTENSION_SPECS = (",
            "    CommandExtensionSpec(",
            f"        extension_id={quoted(metadata.catalog_id)},",
            *emit(metadata.name, prefix="        name=", suffix=","),
            '        description="Reviews contributor CLI invocations without granting global approval.",',
            "        action_classes=(_ACTION_CLASS,),",
            *emit(_risks(review), prefix="        risk_classes=", suffix=","),
            *emit((DEFAULT_GUIDANCE,), prefix="        safer_alternatives=", suffix=","),
            *emit((metadata.homepage,), prefix="        reference_urls=", suffix=","),
            "        executables=(_EXECUTABLE,),",
            "    ),",
            ")",
            "",
        ]
    )
    content = "\n".join(lines)
    ast.parse(content, feature_version=(3, 10))
    return content
