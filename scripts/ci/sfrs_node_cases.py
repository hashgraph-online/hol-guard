"""Record parity vectors for the secret-file-request Node, GraphQL and PR-body leaves.

Usage: ``sfrs_node_cases.py FIXTURE_DIR``. Covers the Node heredoc safety,
generated Node workflow, TypeScript/GraphQL workflow and GitHub PR-body
safety modules. A small tree is built under a fresh root; paths are stored with
the ``{ROOT}`` token so the Rust port can rebuild the tree and replay every
case.

Two facts are replaced by deterministic stand-ins that the Rust replay mirrors:
secret-content classification (the marker ``SECRET``) and the native GitHub CLI
classifier's body-file operand (the value of ``--body-file`` or ``-F`` when a title is present). This
script depends on the Python implementation and is retired with it.
"""

# ruff: noqa: E501 - recorded case tables.

from __future__ import annotations

import gzip
import json
import os
import sys
import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path

import sfrs_node_data as data

from codex_plugin_scanner.guard.runtime import github_pr_body_file as body_file
from codex_plugin_scanner.guard.runtime.secret_file_request_services import github_pr_body_safety as gbs
from codex_plugin_scanner.guard.runtime.secret_file_request_services import node_generated_workflows as ngw
from codex_plugin_scanner.guard.runtime.secret_file_request_services import node_heredoc_safety as nhs
from codex_plugin_scanner.guard.runtime.secret_file_request_services import typescript_graphql_safety as tgs
from codex_plugin_scanner.guard.runtime.secret_file_request_services.shell_tokenization import _split_shell_parts

TOKEN = "{ROOT}"
SECRET_MARKER = "SECRET"


def _fake_secret(content: str, *, suppress_samples: bool = True) -> list[str]:
    return ["secret"] if SECRET_MARKER in content else []


def _body_operand(args: Sequence[str]) -> str | None:
    """Stand-in for the native classifier: the value of the body-file flag."""

    if not any(token in {"--title", "-t"} or token.startswith("--title=") for token in args):
        return None
    for index, token in enumerate(args):
        if token in {"--body-file", "-F"} and index + 1 < len(args):
            return args[index + 1]
        if token.startswith("--body-file="):
            return token.split("=", 1)[1]
    return None


def _build(root: Path) -> None:
    for name in data.TREE["dirs"]:  # type: ignore[union-attr]
        (root / name).mkdir(parents=True, exist_ok=True)
    for name, text in data.TREE["files"].items():  # type: ignore[union-attr]
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        path.chmod(0o600)
    for name, mode in data.TREE["dirs"].items():  # type: ignore[union-attr]
        (root / name).chmod(mode)


def _text(root: Path, value: object) -> object:
    if isinstance(value, str):
        return value.replace(str(root), TOKEN)
    if isinstance(value, (list, tuple)):
        return [_text(root, item) for item in value]
    if isinstance(value, (set, frozenset)):
        return sorted(_text(root, item) for item in value)
    if isinstance(value, dict):
        return [[_text(root, key), _text(root, item)] for key, item in value.items()]
    return value


def _destructive_scripts() -> list[str]:
    return [form.format(n=name) for name in data.DESTRUCTIVE_NAMES for form in data.DESTRUCTIVE_FORMS]


def _wrapped(script: str, limit: int = 3) -> list[str]:
    return [wrapper.replace("{s}", script) for wrapper in data.HEREDOC_WRAPPERS[:limit]]


def _cases(root: Path) -> tuple[list[dict[str, object]], int]:
    proj = root / "home" / "proj"
    home = root / "home"
    cases: list[dict[str, object]] = []
    raised = 0

    def add(function: str, args: list[object], call: Callable[[], object]) -> None:
        nonlocal raised
        try:
            result = call()
        except Exception:
            raised += 1
            return
        cases.append({"fn": function, "args": _text(root, args), "result": _text(root, result)})

    def fill(value: str) -> str:
        return value.replace(TOKEN, str(root))

    # Script-level leaves over the hand-written corpus.
    for number, script in enumerate(data.SCRIPTS):
        add(
            "node_script_contains_non_file_generation_risk",
            [script],
            lambda s=script: tgs._node_script_contains_non_file_generation_risk(s),
        )
        add(
            "node_script_contains_sensitive_runtime_behavior",
            [script],
            lambda s=script: tgs._node_script_contains_sensitive_runtime_behavior(s),
        )
        add(
            "contains_destructive_node_inline_script",
            [script],
            lambda s=script: tgs._contains_destructive_node_inline_script(s),
        )
        add(
            "node_script_contains_disallowed_destructive_file_call",
            [script],
            lambda s=script: nhs._node_script_contains_disallowed_destructive_file_call(s),
        )
        add(
            "script_references_destructive_file_call",
            [script, []],
            lambda s=script: tgs.script_references_destructive_file_call(s),
        )
        add(
            "script_references_destructive_file_call",
            [script, ["writeFile", "writeFileSync"]],
            lambda s=script: tgs.script_references_destructive_file_call(
                s, allowed_write_calls=frozenset({"writeFile", "writeFileSync"})
            ),
        )
        for preserve in (False, True):
            add(
                "redacted_node_inline_string_literals",
                [script, preserve],
                lambda s=script, p=preserve: tgs._redacted_node_inline_string_literals(
                    s, preserve_bracket_member_strings=p
                ),
            )
        add("node_write_file_targets", [script], lambda s=script: list(nhs._node_write_file_targets(s)))
        add("node_string_assignments", [script], lambda s=script: ngw._node_string_assignments(s))
        add(
            "text_contains_credential_exfiltration",
            [script],
            lambda s=script: gbs._text_contains_credential_exfiltration(s),
        )
        add("shell_heredoc_payloads", [script], lambda s=script: list(gbs._shell_heredoc_payloads(s)))
        for position in sorted({0, 1, 2, 5, len(script) // 2, max(len(script) - 1, 0), len(script)}):
            if position <= len(script):
                add(
                    "first_js_call_argument",
                    [script, position],
                    lambda s=script, p=position: nhs._first_js_call_argument(s, p),
                )
        for command in _wrapped(script, len(data.HEREDOC_WRAPPERS) if number < 24 else 3):
            add(
                "looks_like_safe_node_generated_file_heredoc",
                [command, script],
                lambda c=command, s=script: nhs._looks_like_safe_node_generated_file_heredoc(c, s),
            )
            add(
                "looks_like_safe_node_read_only_http_heredoc",
                [command, script],
                lambda c=command, s=script: nhs._looks_like_safe_node_read_only_http_heredoc(c, s),
            )
            add("single_node_heredoc_script", [command], lambda c=command: ngw._single_node_heredoc_script(c))
            add(
                "single_node_heredoc_delimiter_is_quoted",
                [command],
                lambda c=command: nhs._single_node_heredoc_delimiter_is_quoted(c),
            )
    for script in _destructive_scripts()[::3]:
        add(
            "script_references_destructive_file_call",
            [script, []],
            lambda s=script: tgs.script_references_destructive_file_call(s),
        )
        add(
            "script_references_destructive_file_call",
            [script, ["writeFile", "writeFileSync"]],
            lambda s=script: tgs.script_references_destructive_file_call(
                s, allowed_write_calls=frozenset({"writeFile", "writeFileSync"})
            ),
        )
        add(
            "redacted_node_inline_string_literals",
            [script, True],
            lambda s=script: tgs._redacted_node_inline_string_literals(s, preserve_bracket_member_strings=True),
        )
        add(
            "redacted_node_inline_string_literals",
            [script, False],
            lambda s=script: tgs._redacted_node_inline_string_literals(s),
        )
    for command in data.COMMAND_TEXTS:
        add("single_node_heredoc_script", [command], lambda c=command: ngw._single_node_heredoc_script(c))
        add(
            "single_node_heredoc_delimiter_is_quoted",
            [command],
            lambda c=command: nhs._single_node_heredoc_delimiter_is_quoted(c),
        )
        add(
            "looks_like_safe_node_generated_file_heredoc",
            [command, command],
            lambda c=command: nhs._looks_like_safe_node_generated_file_heredoc(c, c),
        )
    # Generated-file heredocs with a fixed set of write targets.
    for path in data.PATHS:
        for expression in (f"'{path}'", f'"{path}"', f"`{path}`", path):
            script = f"fs.writeFileSync({expression}, data);"
            for command in _wrapped(script, 2):
                add(
                    "looks_like_safe_node_generated_file_heredoc",
                    [command, script],
                    lambda c=command, s=script: nhs._looks_like_safe_node_generated_file_heredoc(c, s),
                )
            assignments = {"dir": "/tmp/work", "name": "x"}
            add(
                "node_write_target_is_safe_generated_file",
                [expression, assignments],
                lambda e=expression, a=assignments: nhs._node_write_target_is_safe_generated_file(e, a),
            )
            add(
                "node_write_target_is_safe_generated_file",
                [expression, {}],
                lambda e=expression: nhs._node_write_target_is_safe_generated_file(e, {}),
            )
        add(
            "node_generated_path_contains_shell_expansion",
            [path],
            lambda p=path: nhs._node_generated_path_contains_shell_expansion(p),
        )
        add(
            "node_generated_path_has_safe_extension",
            [path],
            lambda p=path: nhs._node_generated_path_has_safe_extension(p),
        )
        add("node_generated_path_has_safe_root", [path], lambda p=path: ngw._node_generated_path_has_safe_root(p))
        add(
            "node_template_placeholders_are_safe_filename_fragments",
            [path],
            lambda p=path: ngw._node_template_placeholders_are_safe_filename_fragments(p),
        )
        add(
            "node_path_without_template_placeholders",
            [path],
            lambda p=path: ngw._node_path_without_template_placeholders(p),
        )
        add("path_text_looks_sensitive", [path], lambda p=path: gbs._path_text_looks_sensitive(p))
        add("strip_shell_quotes", [path], lambda p=path: tgs._strip_shell_quotes(p))
        add("contains_shell_expansion", [path], lambda p=path: tgs._contains_shell_expansion(p))
    for _name in ("dir", "name", "x", "dir2"):
        for expression in (
            "dir",
            "name",
            "x",
            "dir2",
            " dir ",
            "'/tmp/x.json'",
            "`${dir}/a.json`",
            "`${name}.json`",
            "`/tmp/${name}/${x}.md`",
        ):
            assignments = {"dir": "/tmp/work", "name": "out.json", "x": "/var/tmp/x.csv", "dir2": "/home/u/../x.txt"}
            add(
                "node_write_target_is_safe_generated_file",
                [expression, assignments],
                lambda e=expression, a=assignments: nhs._node_write_target_is_safe_generated_file(e, a),
            )
    for placeholder in data.PLACEHOLDERS:
        add(
            "node_template_placeholder_is_safe_filename_fragment",
            [placeholder],
            lambda p=placeholder: ngw._node_template_placeholder_is_safe_filename_fragment(p),
        )
        add(
            "node_template_placeholders_are_safe_filename_fragments",
            ["/tmp/a-${" + placeholder + "}.json"],
            lambda p=placeholder: ngw._node_template_placeholders_are_safe_filename_fragments(
                "/tmp/a-${" + p + "}.json"
            ),
        )
        add(
            "node_generated_path_contains_shell_expansion",
            ["/tmp/a-${" + placeholder + "}.json"],
            lambda p=placeholder: nhs._node_generated_path_contains_shell_expansion("/tmp/a-${" + p + "}.json"),
        )
        add(
            "node_generated_path_has_safe_extension",
            ["/tmp/a-${" + placeholder + "}.json"],
            lambda p=placeholder: nhs._node_generated_path_has_safe_extension("/tmp/a-${" + p + "}.json"),
        )
    for line in data.ASSIGN_LINES:
        add("node_string_assignment_from_line", [line], lambda ln=line: ngw._node_string_assignment_from_line(ln))
        add("node_string_assignments", [line], lambda ln=line: ngw._node_string_assignments(ln))
        add(
            "node_string_assignments",
            [f"{line}\nfs.writeFileSync(a, 1);"],
            lambda ln=line: ngw._node_string_assignments(f"{ln}\nfs.writeFileSync(a, 1);"),
        )
    chain = "const a = '/tmp';\nconst b = `${a}/x`;\nconst c = `${b}/y`;\nconst d = `${c}/z`;\nconst e = `${d}/w`;\nconst a = '/var/tmp';"
    add("node_string_assignments", [chain], lambda: ngw._node_string_assignments(chain))
    reverse = "const c = `${b}/y`;\nconst b = `${a}/x`;\nconst a = '/tmp';"
    add("node_string_assignments", [reverse], lambda: ngw._node_string_assignments(reverse))
    for value, assignments in data.EXPAND_CASES:
        add(
            "node_expand_template_value",
            [value, assignments],
            lambda v=value, a=assignments: ngw._node_expand_template_value(v, a),
        )
    for literal in data.LITERALS:
        add("js_string_literal_text", [literal], lambda v=literal: ngw._js_string_literal_text(v))
    for value, quote in data.QUOTED_LITERALS:
        add("read_js_quoted_literal", [value, quote], lambda v=value, q=quote: ngw._read_js_quoted_literal(v, q))
    for snippet in data.JS_SNIPPETS:
        pieces = [snippet] if snippet else []
        add("last_non_whitespace_character", [pieces], lambda p=pieces: tgs._last_non_whitespace_character(p))
        add("js_slash_starts_regex", [pieces], lambda p=pieces: tgs._js_slash_starts_regex(p))
        split = [snippet[:1], snippet[1:]] if snippet else []
        add("last_non_whitespace_character", [split], lambda p=split: tgs._last_non_whitespace_character(p))
        add("js_slash_starts_regex", [split], lambda p=split: tgs._js_slash_starts_regex(p))
    add(
        "last_non_whitespace_character",
        [["a", " ", "b  "]],
        lambda: tgs._last_non_whitespace_character(["a", " ", "b  "]),
    )
    add(
        "last_non_whitespace_character",
        [["a", "  ", "\n"]],
        lambda: tgs._last_non_whitespace_character(["a", "  ", "\n"]),
    )
    add("last_non_whitespace_character", [[" ", "\t"]], lambda: tgs._last_non_whitespace_character([" ", "\t"]))
    # Node inline eval and find/fd actions.
    for parts in data.NODE_PARTS:
        add(
            "contains_destructive_node_inline_eval",
            [parts],
            lambda p=parts: ngw._contains_destructive_node_inline_eval(p),
        )
        if parts[:1] == ["node"]:
            add(
                "segment_contains_destructive_node_inline_eval",
                [parts[1:]],
                lambda p=parts: ngw._segment_contains_destructive_node_inline_eval(p[1:]),
            )
        text = " ".join(parts)
        shell_parts = _split_shell_parts(text) if text.strip() else []
        add(
            "contains_destructive_node_inline_eval",
            [shell_parts],
            lambda p=shell_parts: ngw._contains_destructive_node_inline_eval(p),
        )
    for token in data.EVAL_FLAG_TOKENS:
        add("is_combined_node_inline_eval_flag", [token], lambda t=token: ngw._is_combined_node_inline_eval_flag(t))
    for parts in data.FD_PARTS:
        for home_dir in (home, None):
            add(
                "find_or_fd_uses_write_or_exec_action",
                [parts, None if home_dir is None else str(home_dir)],
                lambda p=parts, h=home_dir: ngw._find_or_fd_uses_write_or_exec_action(p, home_dir=h),
            )
    # GraphQL workflows.
    for rest in data.GRAPHQL_REST:
        for target in (data.GRAPHQL_PATH, "/tmp/other.graphql"):
            add(
                "graphql_workflow_rest_args_are_safe",
                [rest, target],
                lambda r=rest, t=target: ngw._graphql_workflow_rest_args_are_safe(r, t),
            )
        for quote, label, sep in (
            ("'", "EOF", "\n"),
            ('"', "EOF", "&& "),
            ("'", "Q_1", ";"),
            ("", "EOF", "\n"),
            ("'", "EOF", " "),
        ):
            command = _graphql_command(data.GRAPHQL_PATH, data.GRAPHQL_BODY, rest, quote, label, sep)
            add(
                "looks_like_safe_graphql_query_file_workflow",
                [command],
                lambda c=command: ngw._looks_like_safe_graphql_query_file_workflow(c),
            )
    for path in [*data.GRAPHQL_PATHS, str(root / "pr-threads-query.graphql"), str(proj / "pr-threads-query.graphql")]:
        add(
            "looks_like_temporary_pr_threads_query_path",
            [path],
            lambda p=path: ngw._looks_like_temporary_pr_threads_query_path(p),
        )
        add("graphql_query_file_substitution_refs", [path], lambda p=path: tgs._graphql_query_file_substitution_refs(p))
        add("graphql_query_file_argument_values", [path], lambda p=path: tgs._graphql_query_file_argument_values(p))
        for quote in ("", "'", '"'):
            quoted = f"{quote}{path}{quote}"
            command = _graphql_command(quoted, data.GRAPHQL_BODY, f"gh api graphql -F query=@{path} -F n=1")
            add(
                "looks_like_safe_graphql_query_file_workflow",
                [command],
                lambda c=command: ngw._looks_like_safe_graphql_query_file_workflow(c),
            )
        for argument in (
            f"query=@{path}",
            f"query=$(cat {path})",
            f'query=$(cat "{path}")',
            f"query=$(cat '{path}')",
            f"query=@{path}x",
            "query=",
            "n=1",
            "n",
            "=1",
            "n=@a",
            "n=a/b",
            "n=${X}",
            "n=a*",
        ):
            add(
                "graphql_workflow_field_arg_is_safe",
                [argument, path],
                lambda a=argument, p=path: tgs._graphql_workflow_field_arg_is_safe(a, p),
            )
    graphql_commands = [
        _graphql(data.GRAPHQL_PATH, "mutation { x }", data.GRAPHQL_REST[0]),
        _graphql(data.GRAPHQL_PATH, "subscription { x }", data.GRAPHQL_REST[0]),
        _graphql(data.GRAPHQL_PATH, "{ x }", data.GRAPHQL_REST[0]),
        _graphql(data.GRAPHQL_PATH, "queryX { x }", data.GRAPHQL_REST[0]),
        _graphql(data.GRAPHQL_PATH, "query { mutationish }", data.GRAPHQL_REST[0]),
        _graphql(data.GRAPHQL_PATH, "query {\n  a\n}\n", data.GRAPHQL_REST[0]),
        _graphql(data.GRAPHQL_PATH, "query { é }", data.GRAPHQL_REST[0]),
        _graphql(data.GRAPHQL_PATH, "query { x }\nEOF\nrm -rf /", data.GRAPHQL_REST[0]),
        _graphql("/tmp/pr-threads-query.gql", data.GRAPHQL_BODY, data.GRAPHQL_REST[0]),
        _graphql("/tmp/.env.graphql", data.GRAPHQL_BODY, "gh api graphql -F query=@/tmp/.env.graphql"),
        _graphql("/tmp/a*.graphql", data.GRAPHQL_BODY, "gh api graphql -F query=@/tmp/a*.graphql"),
        "  \n" + _graphql(data.GRAPHQL_PATH, data.GRAPHQL_BODY, data.GRAPHQL_REST[0]),
        _graphql(data.GRAPHQL_PATH, data.GRAPHQL_BODY, data.GRAPHQL_REST[0]).replace("cat >", "cat>"),
        _graphql(data.GRAPHQL_PATH, data.GRAPHQL_BODY, data.GRAPHQL_REST[0]).replace("cat >", "cat >>"),
        "",
        "cat > /tmp/pr-threads-query.graphql",
    ]
    for command in graphql_commands:
        add(
            "looks_like_safe_graphql_query_file_workflow",
            [command],
            lambda c=command: ngw._looks_like_safe_graphql_query_file_workflow(c),
        )
    # TypeScript workflows.
    for command in data.TS_COMMANDS:
        add(
            "looks_like_contained_temporary_typescript_workflow",
            [command],
            lambda c=command: tgs._looks_like_contained_temporary_typescript_workflow(c),
        )
    for command in data.UNMODELED_COMMANDS:
        for names in data.UNMODELED_NAMES:
            for parts in data.UNMODELED_PARTS[:2]:
                add(
                    "contains_unmodeled_inline_interpreter_eval",
                    [command, parts, names],
                    lambda c=command, p=parts, n=names: tgs._contains_unmodeled_inline_interpreter_eval(c, p, n),
                )
    for names in data.UNMODELED_NAMES:
        for name in names:
            add(
                "is_unmodeled_inline_interpreter_command",
                [name],
                lambda n=name: tgs._is_unmodeled_inline_interpreter_command(n),
            )
    for parts in data.UNMODELED_PARTS:
        add(
            "contains_unmodeled_inline_interpreter_eval",
            [" ".join(parts), parts, parts[:1]],
            lambda p=parts: tgs._contains_unmodeled_inline_interpreter_eval(" ".join(p), p, p[:1]),
        )
    for parts in data.PYTEST_PARTS:
        for cwd in (proj, None):
            add(
                "contains_unsafe_pytest_binary_invocation",
                [parts, None if cwd is None else str(cwd)],
                lambda p=parts, c=cwd: tgs._contains_unsafe_pytest_binary_invocation(p, cwd=c),
            )
    # PR body safety.
    # The real GitHub CLI classifier rejects flag combinations the stand-in cannot
    # model (for example ``--web``), so those commands are not recorded.
    for command in (fill(item) for item in data.GH_BODY_COMMANDS):
        add(
            "gh_pr_create_segment_with_bounded_output",
            [command],
            lambda c=command: _tokens(gbs._gh_pr_create_segment_with_bounded_output(c)),
        )
        for cwd, home_dir in ((proj, home), (home, home), (None, home), (proj, None)):
            args = [command, None if cwd is None else str(cwd), None if home_dir is None else str(home_dir)]
            add(
                "gh_pr_create_uses_safe_static_body_file",
                args,
                lambda c=command, w=cwd, h=home_dir: gbs._gh_pr_create_uses_safe_static_body_file(c, cwd=w, home_dir=h),
            )
            add(
                "gh_pr_edit_uses_safe_static_body_file",
                args,
                lambda c=command, w=cwd, h=home_dir: gbs._gh_pr_edit_uses_safe_static_body_file(c, cwd=w, home_dir=h),
            )
    for tokens in data.BOUNDED_CONSUMERS:
        add("bounded_output_consumer", [tokens], lambda t=tokens: gbs._bounded_output_consumer(tuple(t)))
    for path in data.SENSITIVE_PATHS + data.PATHS:
        add("path_text_looks_sensitive", [path], lambda p=path: gbs._path_text_looks_sensitive(p))
    for text in data.CREDENTIAL_TEXTS:
        add(
            "text_contains_credential_exfiltration",
            [text],
            lambda t=text: gbs._text_contains_credential_exfiltration(t),
        )
    for command in data.HEREDOC_COMMANDS:
        add("shell_heredoc_payloads", [command], lambda c=command: list(gbs._shell_heredoc_payloads(c)))
    for segment in data.CONSTRAINT_SEGMENTS:
        add(
            "shell_read_segment_can_emit_stdout",
            [segment],
            lambda s=segment: gbs._shell_read_segment_can_emit_stdout(s),
        )
    for args in data.SEARCH_ARGS:
        add("search_args_use_quiet_mode", [args], lambda a=args: gbs._search_args_use_quiet_mode(a))
    for args in data.FIND_ARG_LISTS:
        filled = [fill(item) for item in args]
        add("find_exec_reads_file_content", [filled], lambda a=filled: gbs._find_exec_reads_file_content(a))
        add("find_target_candidates", [filled], lambda a=filled: list(gbs._find_target_candidates(a)))
    for candidate in data.FIND_CANDIDATES:
        filled = fill(candidate)
        for cwd, home_dir in ((proj, home), (None, None)):
            add(
                "find_target_candidate_is_sensitive",
                [filled, None if cwd is None else str(cwd), None if home_dir is None else str(home_dir)],
                lambda c=filled, w=cwd, h=home_dir: gbs._find_target_candidate_is_sensitive(c, cwd=w, home_dir=h),
            )
    for segment in data.READ_SEGMENTS:
        filled = [fill(item) for item in segment]
        for cwd, home_dir in ((proj, home), (home, home), (None, None)):
            args = [filled, None if cwd is None else str(cwd), None if home_dir is None else str(home_dir)]
            add(
                "shell_segment_reads_sensitive_path",
                args,
                lambda s=filled, w=cwd, h=home_dir: gbs._shell_segment_reads_sensitive_path(s, cwd=w, home_dir=h),
            )
            if filled[:1] == ["find"]:
                add(
                    "find_segment_reads_sensitive_path",
                    args,
                    lambda s=filled, w=cwd, h=home_dir: gbs._find_segment_reads_sensitive_path(s, cwd=w, home_dir=h),
                )
    return cases, raised


def _tokens(segment: object) -> object:
    if segment is None:
        return None
    return [[token.raw, token.plain] for token in segment]  # type: ignore[attr-defined]


def _graphql(path: str, body: str, rest: str, quote: str = "'", label: str = "EOF", sep: str = "\n") -> str:
    return data._graphql(path, body, rest, quote, label, sep)


_graphql_command = _graphql


def main() -> None:
    fixture_dir = Path(sys.argv[1])
    saved_cwd = os.getcwd()
    saved_env = dict(os.environ)
    with tempfile.TemporaryDirectory(prefix="sfrs-node-") as scratch:
        root = Path(scratch).resolve()
        _build(root)
        os.chdir(root / "home" / "proj")
        os.environ.clear()
        os.environ.update({"PATH": str(root / "bin"), "TMPDIR": str(root / "tmp"), "HOME": str(root / "home")})
        body_file.classify_secret_content = _fake_secret
        gbs.static_markdown_pr_body_file_operand = _body_operand
        try:
            cases, raised = _cases(root)
        finally:
            os.environ.clear()
            os.environ.update(saved_env)
            os.chdir(saved_cwd)
        document = {"schema": "sfrs-node.v1", "tree": data.TREE, "cases": cases}
    out = fixture_dir / "sfrs_node.json.gz"
    out.write_bytes(gzip.compress(json.dumps(document, sort_keys=True).encode("utf-8"), mtime=0))
    print(f"{len(cases)} cases ({raised} raising, dropped) -> {out}")


if __name__ == "__main__":
    main()
