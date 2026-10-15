"""Record parity vectors for the pure-text helpers behind the SFRS classifier.

Usage: ``sfrs_intermediate_vectors.py FIXTURE_DIR``. The command corpus is every
shell-looking string found in the recorded entry-point vectors. Each helper is run
by the Python implementation and its output is stored beside its input, so the
Rust port can be checked helper by helper instead of only through the entry
points. This script depends on the Python implementation and is retired with it.
"""

from __future__ import annotations

import ast
import gzip
import json
import os
import sys
from pathlib import Path

from codex_plugin_scanner.guard.runtime import (
    github_shell_bindings as gh_bindings,
)
from codex_plugin_scanner.guard.runtime import (
    github_shell_capabilities as runtime_gh_capabilities,
)
from codex_plugin_scanner.guard.runtime.github_capability_contract import github_assessment
from codex_plugin_scanner.guard.runtime import (
    github_shell_control_flow as gh_control_flow,
)
from codex_plugin_scanner.guard.runtime import (
    github_shell_redirections as gh_redirections,
)
from codex_plugin_scanner.guard.runtime.secret_file_request_services import (
    local_read_operands,
    read_only_filters,
    docker_requests,
    github_shell_capabilities as github_services,
    request_artifacts,
    shell_quote_tokens,
    shell_static_safety,
    shell_tokenization,
)

from sfrs_developer_section import EXTRAS as DEVELOPER_EXTRAS
from sfrs_developer_section import developer_section
from sfrs_vector_extras import DOCKER_EXTRAS, GITHUB_EXTRAS, SCRIPT_EXTRAS

MAX_TEXTS = 6000
HOST_MARKERS = ("michaelkantor", "runner2-port", "hol-guard/.venv", "/home/runner", "/var/folders", "~/.codex")


def _walk(value: object, found: set[str]) -> None:
    if isinstance(value, str):
        if 2 < len(value) < 2000 and " " in value and not any(marker in value for marker in HOST_MARKERS):
            found.add(value)
    elif isinstance(value, dict):
        for item in value.values():
            _walk(item, found)
    elif isinstance(value, list):
        for item in value:
            _walk(item, found)


def _corpus(fixture_dir: Path) -> list[str]:
    found: set[str] = set()
    for path in sorted(fixture_dir.glob("*.json.gz")):
        if path.name.startswith("intermediate_"):
            continue
        document = json.loads(gzip.decompress(path.read_bytes()))
        for vector in document.get("vectors", ()):
            _walk(vector["args"], found)
    found.update(DOCKER_EXTRAS)
    found.update(GITHUB_EXTRAS)
    found.update(DEVELOPER_EXTRAS)
    return sorted(found)[:MAX_TEXTS]


def _filters(segments: list[list[str]], parts: list[str]) -> dict[str, object]:
    safe = read_only_filters._read_only_lookup_target_is_safe
    filters = read_only_filters
    return {
        "targets": [[safe(part, allow_dirs=False), safe(part, allow_dirs=True)] for part in parts],
        "redirections": [
            [
                filters._read_only_lookup_arg_is_redirection(part),
                list(filters._split_attached_redirection_token(part) or []) or None,
            ]
            for part in parts
        ],
        "segments": [
            [
                filters._read_only_lookup_filter_segment_is_safe(segment[0], segment[1:]),
                filters._read_only_lookup_filter_segment_is_safe(segment[0], segment[1:], require_explicit_rg_no_config=True),
                filters._read_only_lookup_sed_args_are_safe(segment[1:], require_target=True),
                filters._read_only_lookup_head_tail_args_are_safe(segment[1:], require_target=True),
                filters._read_only_lookup_filter_grep_args_are_safe(segment[1:]),
                filters._read_only_lookup_filter_rg_args_are_safe(segment[1:]),
            ]
            for segment in segments
        ],
    }


def _operands(segments: list[list[str]], parts: list[str]) -> dict[str, object]:
    operands = local_read_operands
    return {
        "globs": [operands._search_glob_pattern_is_safe(part, root=None) for part in parts],
        "segments": [
            {
                "tokens": list(operands._shell_segment_file_operand_tokens(segment)),
                "hidden": operands._ripgrep_args_expand_hidden_files(segment[1:]),
                "roles": [
                    [list(role) for role in operands._search_file_operand_roles(name, segment[1:])]
                    for name in ("grep", "rg")
                ],
                "cat": list(operands._cat_file_operand_tokens(segment[1:])),
                "plain": list(operands._plain_file_operand_tokens(segment[1:])),
                "sed": list(operands._sed_file_operand_tokens(segment[1:])),
                "search": [operands.search_operands_are_safe(name, segment[1:], root=None) for name in ("grep", "rg")],
            }
            for segment in segments
        ],
    }


def _quote_tokens(text: str) -> dict[str, object]:
    tokens = shell_quote_tokens.shell_tokens_preserving_quote_context(text)
    segments = shell_quote_tokens.shell_token_segments(tokens)
    return {
        "tokens": [[token.raw, token.plain] for token in tokens],
        "segments": [[[token.raw, token.plain] for token in segment] for segment in segments],
    }


def _static(text: str, parts: list[str], segments: list[list[str]]) -> dict[str, object]:
    safety = shell_static_safety
    cwd, root = Path("/sfrs-nonexistent-cwd"), Path("/sfrs-nonexistent-root")
    return {
        "jq": [safety._github_jq_filter_args_are_safe(segment[1:]) for segment in segments],
        "texts": list(safety._script_interpreter_texts(parts)),
        "redirections": [safety._without_safe_inspection_redirections(segment) for segment in segments],
        "syntax": [safety._shell_syntax_check_segment_is_safe(segment[0], segment[1:]) for segment in segments],
        "escapes": [safety._shell_token_escapes_root(part, cwd=cwd, root=root) for part in parts],
        "substitution": [safety._shell_token_has_command_substitution(part) for part in parts],
        "interpreter": [
            [safety._is_python_interpreter_command(part), safety._is_script_interpreter_command(part)] for part in parts
        ],
        "payloads": [
            [None if (found := safety._interpreter_flag_payload(parts, index)) is None else [found.script_text, found.tokens_consumed]]
            for index in range(len(parts))
        ],
    }


def _github(text: str, parts: list[str], segments: list[list[str]]) -> dict[str, object]:
    gh = github_services
    return {
        "substitutions": list(gh._shell_command_substitution_payloads(text)),
        "dynamic": gh._github_shell_has_dynamic_arguments(text),
        "tokens": [
            [gh._shell_token_has_expansion(part), gh.github_argument_token_has_untrusted_expansion(part), gh._github_environment_name(part)]
            for part in parts
        ],
        "pipelines": gh._iter_shell_pipelines(parts),
        "env_index": [gh._shell_segment_env_index(segment) for segment in segments],
        "env_split": list(gh._env_split_string_payloads(parts)),
        "scripts": list(gh._shell_command_scripts(parts)),
        "persistent": gh._persistent_github_environment_requires_review(parts),
        "builtin": [gh._shell_segment_is_command_builtin_lookup(segment) for segment in segments],
        "companion": [
            gh._github_pipeline_companion_is_read_only(segment, home_dir=None, command_text=text)
            for segment in segments
        ],
        "script_review": gh._github_script_requires_review(text),
    }


ENVIRONMENT_CASES = (
    (),
    (("GH_TOKEN", "x"),),
    (("GITHUB_TOKEN", ""),),
    (("GH_CONFIG_DIR", "/tmp"),),
    (("GH_HOST", "github.com"),),
    (("GH_HOST", "GitHub.com"),),
    (("GH_HOST", "ghe.example"),),
    (("GH_HOST", "GITHUB.COM"),),
    (("GH_REPO", "owner/repo"),),
    (("GH_REPO", "../x"),),
    (("GH_REPO", "https://github.com/a/b"),),
    (("GH_REPO", "ghe.example/a/b"),),
    (("GH_REPO", "$X"),),
    (("OTHER", "1"), ("GH_ENTERPRISE_TOKEN", "t")),
)


def _environments() -> list[object]:
    gh = github_services
    return [[[list(item) for item in case], gh._github_environment_requires_review(case)] for case in ENVIRONMENT_CASES]


def _stand_in(args):
    """Deterministic substitute for the native GitHub CLI classifier."""

    joined = " ".join(args)
    if joined.startswith("pr merge"):
        capability = "merge_remote"
    elif "delete" in joined:
        capability = "delete_remote"
    elif joined.startswith(("pr view", "repo view")):
        capability = "read_remote"
    else:
        capability = "unknown"
    return github_assessment(capability, f"stub.{joined}", "stub")


def _assessment(found: object) -> object:
    if found is None:
        return None
    return {
        "capability": found.capability,
        "capabilities": list(found.capabilities),
        "reason_code": found.reason_code,
        "detail": found.detail,
    }


def _stubbed_assessment(text: str) -> object:
    original = runtime_gh_capabilities.classify_github_cli
    runtime_gh_capabilities.classify_github_cli = _stand_in
    try:
        return _assessment(github_services.classify_github_shell_capabilities(text, home_dir=None))
    finally:
        runtime_gh_capabilities.classify_github_cli = original


def _gh_shell(text: str, parts: list[str], segments: list[list[str]]) -> dict[str, object]:
    gh, b = github_services, gh_bindings
    primary = shell_tokenization._shell_segment_primary_command
    pipelines = gh._iter_shell_pipelines(parts)
    conditional, skipped = gh_control_flow.pipeline_control_flow(parts, pipelines, primary_command=primary)
    names = [frozenset(), frozenset({"x"}), frozenset({"gh2", "y"})]
    prefix = [(index, primary(segment)[1]) for index, segment in enumerate(segments)]
    return {
        "assessment": _stubbed_assessment(text),
        "normalized": b.normalize_github_lookup_assignments(text),
        "command_text": b.contains_github_command_text(text),
        "functions": [[body, head, end - start] for body, head, start, end in b.function_definition_payloads(text)],
        "parent": sorted(b.parent_expanded_variable_names(text)),
        "complex": [
            b.complex_control_flow_may_invoke_github(text, github_command_variables=one, github_command_text_variables=two)
            for one in names
            for two in names
        ],
        "connectors": sorted([key, value] for key, value in b.conditional_pipeline_connectors(parts).items()),
        "control": [sorted(conditional), sorted(skipped)],
        "scoped": [list(item) for item in b.scoped_command_substitutions(text, payloads=gh._shell_command_substitution_payloads)],
        "executes": [[b.pipeline_executes_github_text(pipeline, primary_command=primary, github_command_text_variables=one) for one in names] for pipeline in pipelines],
        "tokens": [
            [
                b.value_names_github_executable(part),
                b.is_shell_variable_name(part),
                b.token_is_shell_assignment(part),
                [b.dynamic_command_may_invoke_github(part, github_command_variables=one, github_command_text_variables=two) for one in names for two in names],
                [b.tokens_reference_github_variable([part], github_command_variables=one, github_command_text_variables=two) for one in names for two in names],
            ]
            for part in parts
        ],
        "segments": [
            {
                "exec": b.executable_control_flow_segment(segment),
                "case": [list(arm) for arm in b.case_arm_segments(segment)],
                "standalone": b.segment_is_standalone_assignment(segment),
                "updates": [
                    [list(item) for item in b.assignment_updates(segment, command_index=index, text_values=flag)]
                    for flag in (False, True)
                ],
                "persistent": [
                    [
                        list(item)
                        for item in b.persistent_assignment_updates(
                            segment, command_name=name, command_index=index, text_values=flag
                        )
                    ]
                    for flag in (False, True)
                ],
                "redirection": None if index is None else list(gh_redirections.github_shell_args_and_redirection(segment, index)),
                "definition": None
                if index is None or name is None
                else [
                    b.definition_payload(segment, command_name=kind, command_index=index) for kind in ("alias", "function")
                ],
                "exported": [
                    _exported(segment, name, index, current, suppress)
                    for current in (frozenset(), frozenset({"x", "gh2"}))
                    for suppress in (False, True)
                ],
            }
            for segment in segments
            for name, index in [primary(segment)]
        ],
    }


def _exported(segment: list[str], name: str | None, index: int | None, current: frozenset[str], suppress: bool) -> list[str]:
    exported = {"x", "z"}
    gh_bindings.update_exported_bindings(
        segment,
        command_name=name,
        command_index=index,
        current_bindings=set(current),
        exported_bindings=exported,
        suppress_removals=suppress,
    )
    return sorted(exported)


def _parses(text: str) -> bool:
    try:
        ast.parse(text)
    except (SyntaxError, ValueError):
        return False
    return True


def _script(text: str) -> dict[str, object]:
    safety = shell_static_safety
    return {
        "text": text,
        "parses": _parses(text),
        "aliased": safety._script_has_aliased_risky_import(text),
        "wait": safety._script_is_benign_wait(text),
        "observer": safety._script_is_read_only_observer(text),
    }


def _record(text: str) -> dict[str, object]:
    parts = shell_tokenization._split_shell_parts(text)
    segments = shell_tokenization._iter_shell_command_segments(parts)
    primaries = [list(shell_tokenization._shell_segment_primary_command(segment)) for segment in segments]
    return {
        "text": text,
        "parts": parts,
        "segments": segments,
        "primaries": primaries,
        "variables": list(request_artifacts._shell_variable_names(text)),
        "docker": [
            [
                shell_tokenization._docker_subcommand_index(segment[1:]),
                shell_tokenization._docker_build_args_are_sensitive(segment[1:]),
                request_artifacts._docker_buildx_subcommand_index(segment[1:]),
                shell_tokenization._docker_subcommand_help_requested(segment[1:]),
            ]
            for segment in segments
        ],
        "docker_reason": docker_requests._docker_sensitive_reason(text),
        "names": [request_artifacts._normalized_shell_command_name(part) for part in parts],
        "filters": _filters(segments, parts),
        "operands": _operands(segments, parts),
        "quote": _quote_tokens(text),
        "static": _static(text, parts, segments),
        "github": _github(text, parts, segments),
        "gh_shell": _gh_shell(text, parts, segments),
        "developer": developer_section(segments),
    }


def main() -> None:
    fixture_dir = Path(sys.argv[1])
    os.environ.pop("RIPGREP_CONFIG_PATH", None)
    corpus = _corpus(fixture_dir)
    records = [_record(text) for text in corpus]
    scripts = sorted({*SCRIPT_EXTRAS, *(text for record in records for text in record["static"]["texts"])})
    document = {
        "schema": "sfrs-intermediate.v1",
        "tokens": records,
        "scripts": [_script(text) for text in scripts],
        "environments": _environments(),
    }
    out = fixture_dir / "intermediate_tokens.json.gz"
    out.write_bytes(gzip.compress(json.dumps(document, sort_keys=True).encode("utf-8"), mtime=0))
    print(f"{len(records)} records -> {out}")


if __name__ == "__main__":
    main()
