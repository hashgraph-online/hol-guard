"""Record parity vectors for the PR body-file, ephemeral-body and Actions read checks.

Usage: ``SFRS_GH_CLASSIFIER=<guard-command-source binary> sfrs_github_body_cases.py
FIXTURE_DIR`` with the repository ``src`` on ``PYTHONPATH``. GitHub CLI
classification is answered by the Rust classifier, as in production. A fixed tree is built under a fresh root; every case runs with a
recorded environment (``PATH``, ``TMPDIR``, ``HOME``, ...) and stores the result
with the ``{ROOT}`` token so the Rust port can rebuild the tree and replay it.
Secret-content classification and executable trust are replaced by fixed stubs
that the replay host mirrors. Retired with the Python implementation.
"""

# ruff: noqa
from __future__ import annotations

import gzip
import os
import sys
import tempfile
from pathlib import Path

import sfrs_github_body_data as _data
import sfrs_github_body_tree as _tree

for _module in (_tree, _data):
    globals().update({k: v for k, v in vars(_module).items() if not k.startswith("__")})


def _segments(text: str):
    masked = mask_complete_heredocs(text, extract_heredocs(text))
    return sqt.shell_token_segments(sqt.shell_tokens_preserving_quote_context(masked))


def _ephemeral_cases(add) -> None:
    for text in _body_texts():
        add("eph_safe", [text], eph.gh_pr_create_uses_safe_ephemeral_body(text))
        for position, segment in enumerate(_segments(text)):
            add("eph_assignment", [text, position], eph._assignment_variable(segment))
            for variable in ("f", "body"):
                add("eph_writer", [text, position, variable], eph._heredoc_writer_is_safe(segment, variable=variable))
                add("eph_cat", [text, position, variable], eph._body_cat_is_safe(segment, variable=variable))
                add("eph_grep", [text, position, variable], eph._body_grep_is_safe(segment, variable=variable))
                add("eph_echo", [text, position, variable], eph._echo_is_safe(segment, variable=variable))
                add("eph_pr_create", [text, position, variable], eph._pr_create_is_safe(segment, variable=variable))
    for raw in QUOTED_WORDS:
        add("eph_quoted_word", [raw], eph._is_one_fully_quoted_word(raw))
        for allow in (True, False):
            add("eph_static_argument", [raw, allow], eph._static_shell_argument(raw, allow_unquoted=allow))


def _body_file_cases(root: Path, add) -> None:
    for arguments in ARG_LISTS_EDIT:
        add("bf_edit_operand", [arguments], bf.static_markdown_pr_edit_body_file_operand(arguments))
    for name in NAMES:
        add("bf_markdown_name", [name], bf._is_pr_body_markdown_name(name))
    home = root / "home"
    proj = home / "proj"
    for text in NUMBER_TEXTS:
        add(
            "bf_edit_operand",
            [[text, "-F", "a.md"]],
            bf.static_markdown_pr_edit_body_file_operand([text, "-F", "a.md"]),
        )
    sensitive = [
        "/x/.aws/pr-body.md",
        "/x/.DOCKER/y",
        "/x/.gnupg",
        "/x/.kube/c",
        "/x/.ssh/id",
        "/x/.sshx/id",
        "/x/ssh/id",
        "/x/.env",
        "/x/.ENV.local",
        "/x/Credentials-pr-body.md",
        "/x/id_rsa.md",
        "/x/ID_ED25519-pr-body.md",
        "/x/secrets.md",
        "/x/token.md",
        "/x/Tokens.md",
        "/x/tok.md",
        "/x/pr-body.md",
        "/x/\u0130.ssh",
        "/",
        "/x/.environment",
        "/x/a/.ssh",
        "/x/.SSH/k",
    ]
    for item in sensitive:
        add("bf_looks_sensitive", [item], bf._path_looks_sensitive(Path(item)))
    for item in (
        proj / "pr-body.md",
        proj / "x.md",
        root / "tmp" / "pr-body.md",
        home / "CascadeProjects" / "app" / "pr-body.md",
        home / "CascadeProjects",
        home / "CascadeProjectsX" / "a",
        home / ".omp/agent/sessions/s1/s2/local/pr-body.md",
        home / ".omp/agent/sessions/s1/s2/local",
        home / ".omp/agent/sessions/s1/s2/other/pr-body.md",
        home / ".omp/agent/sessions/s1/pr-body.md",
        home / ".omp/agent/sessions/s1/s2/local/a/b",
        Path("/"),
        Path("/opt/x"),
    ):
        add("bf_cascade_root", [str(item), str(home)], bf._cascade_projects_authored_root(item, home_dir=home))
        add("bf_omp_root", [str(item), str(home)], bf._omp_session_authored_root(item, home_dir=home))
    operands = [
        "pr-body.md",
        "./pr-body.md",
        "docs/a-pr-body.md",
        "docs/../pr-body.md",
        "PR-BODY.MD",
        "pr-body.markdown",
        "pr_body_x.md",
        "x-pr-body.md",
        "real/pr-body.md",
        "dirlink/pr-body.md",
        "link-pr-body.md",
        "hard-pr-body.md",
        "dangling-pr-body.md",
        "secret-pr-body.md",
        "empty-pr-body.md",
        "big-pr-body.md",
        "limit-pr-body.md",
        "bad-pr-body.md",
        "gw-pr-body.md",
        "ow-pr-body.md",
        "ro-pr-body.md",
        "old-pr-body.md",
        "day-pr-body.md",
        "future-pr-body.md",
        "soon-pr-body.md",
        "credentials-pr-body.md",
        "token-pr-body.md",
        ".ssh/pr-body.md",
        "notes.txt",
        "pr-body.md.bak",
        "pr-body",
        "open/pr-body.md",
        "open/inner/pr-body.md",
        "pr-b\u00f6dy.md",
        "sp ace-pr-body.md",
        "dirpr-body.md",
        "a-pr-body.md",
        "missing-pr-body.md",
        " pr-body.md",
        "pr-body.md ",
        "",
        "~",
        "~/proj/pr-body.md",
        "~/CascadeProjects/app/pr-body.md",
        "~/.omp/agent/sessions/s1/s2/local/pr-body.md",
        "~/.omp/agent/sessions/s1/pr-body.md",
        "~/nothing/pr-body.md",
        "~x/pr-body.md",
        "C:\\x\\pr-body.md",
        "..\\pr-body.md",
        "dir\\pr-body.md",
        "\\\\server\\share\\pr-body.md",
        "../CascadeProjects/app/pr-body.md",
        "../../tmp/pr-body.md",
        str(proj / "pr-body.md"),
        str(root / "tmp" / "pr-body.md"),
        str(root / "tmp" / "work" / "pr-body.md"),
        str(home / "CascadeProjects" / "app" / "pr-body.md"),
        str(home / ".omp/agent/sessions/s1/s2/local/pr-body.md"),
        str(proj / "link-pr-body.md"),
        "-",
        "pr-body.md\n",
        "\u00e9.md",
        "pr-body.md\x00",
    ]
    for operand in operands:
        variants = [(proj, home), (proj, None), (None, home), (None, None)]
        if operand in DOCS_OPERANDS:
            variants.append((proj / "docs", home))
        for cwd, home_dir in variants:
            if "\x00" in operand and cwd is None:
                continue
            args = [operand, str(cwd) if cwd else None, str(home_dir) if home_dir else None]
            add("bf_is_safe", args, _call_safe(operand, cwd, home_dir))
        if cwd_ok(operand):
            add(
                "bf_resolve",
                [operand, str(proj), str(home)],
                _call(lambda: bf._resolve_operand(operand, cwd=proj, home_dir=home)),
            )
        resolved = _call(lambda: bf._resolve_operand(operand, cwd=proj, home_dir=home))
        if isinstance(resolved, str):
            add(
                "bf_authored_root",
                [resolved, str(proj), str(home)],
                bf._authored_location_root(Path(resolved), cwd=proj, home_dir=home),
            )
            authored = bf._authored_location_root(Path(resolved), cwd=proj, home_dir=home)
            if authored is not None:
                add(
                    "bf_chain",
                    [resolved, str(authored)],
                    bf._ancestor_chain_is_controlled(Path(resolved), root=authored),
                )
    chains = [
        (proj / "pr-body.md", proj),
        (proj / "docs" / "a-pr-body.md", proj),
        (proj / "open" / "inner" / "pr-body.md", proj),
        (proj / "open" / "pr-body.md", proj),
        (proj / "pr-body.md", proj / "docs"),
        (proj / "pr-body.md", home),
        (proj / "pr-body.md", root / "stk"),
        (root / "stk" / "pr-body.md", root / "stk"),
        (root / "stk" / "work" / "pr-body.md", root / "stk"),
        (root / "tmp" / "work" / "pr-body.md", root / "tmp"),
        (root / "tmp" / "pr-body.md", root / "tmp"),
        (root / "tmp" / "pr-body.md", root / "missing"),
        (proj / "pr-body.md", proj / "pr-body.md"),
        (proj / "pr-body.md", Path("/")),
        (root / "bin" / "gh", root / "bin"),
    ]
    for candidate, authority in chains:
        add("bf_chain", [str(candidate), str(authority)], bf._ancestor_chain_is_controlled(candidate, root=authority))
    uid = os.getuid()
    for item in (
        proj,
        proj / "docs",
        proj / "open",
        root / "stk",
        root / "bin",
        proj / "pr-body.md",
        root / "missing",
        Path("/"),
        proj / "link-pr-body.md",
    ):
        add("bf_private_dir", [str(item)], bf._private_directory_owned_by_current_user(item, uid=uid))
        add("bf_private_dir", [str(item), "other"], bf._private_directory_owned_by_current_user(item, uid=uid + 1))


DOCS_OPERANDS = {"a-pr-body.md", "./a-pr-body.md", "missing-pr-body.md", "", "~/CascadeProjects/app/pr-body.md"}


def cwd_ok(operand: str) -> bool:
    return "\x00" not in operand


def _call(function):
    try:
        value = function()
    except Exception as error:  # noqa: BLE001 - recorded as a sentinel so replay can match it
        return {"$raises": type(error).__name__}
    return str(value) if isinstance(value, Path) else value


def _call_safe(operand: str, cwd: Path | None, home: Path | None):
    return _call(lambda: bf.github_pr_body_file_is_safe(operand, cwd=cwd, home_dir=home))


def _expand(template: str, root: Path) -> str:
    return (
        template.replace("{root}", str(root))
        .replace("{bin}", str(root / "bin"))
        .replace("{bad}", str(root / "badbin"))
        .replace("{tmp}", str(root / "tmp"))
    )


def _run_with_env(root: Path, env: dict[str, str], function):
    saved = dict(os.environ)
    os.environ.clear()
    os.environ.update(env)
    tempfile.tempdir = None
    try:
        return _call(function)
    finally:
        os.environ.clear()
        os.environ.update(saved)
        tempfile.tempdir = None


def _actions_cases(root: Path, add_env) -> None:
    base = _env_base(root)
    proj = root / "home" / "proj"
    for env_extra in ENV_VARIANTS:
        env = {**base, **env_extra}
        add_env(env, "aw_env_safe", [str(root)], lambda: aw.shell_read_execution_environment_is_safe(cwd=root))
        for text in (
            "gh run view 1 --repo o/r",
            "echo hi",
            "id=1\ngh run view $id --repo o/r --log\n",
            "gh run view 1 --repo o/r | head -5",
        ):
            add_env(
                env,
                "aw_workflow",
                [text, None],
                lambda text=text: aw.is_nonexecuting_github_actions_read_workflow(text),
            )
            add_env(
                env,
                "aw_workflow",
                [text, str(root)],
                lambda text=text: aw.is_nonexecuting_github_actions_read_workflow(text, cwd=root),
            )
    for value in LOADER_VALUES:
        value = _expand(value, root)
        for key in ("LD_LIBRARY_PATH", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "LD_AUDIT", "LD_FOO"):
            env = {**base, key: value}
            add_env(env, "aw_env_safe", [str(root)], lambda: aw.shell_read_execution_environment_is_safe(cwd=root))
            add_env(env, "aw_env_safe", [str(proj)], lambda: aw.shell_read_execution_environment_is_safe(cwd=proj))
        env = dict(base)
        for cwd in (root, proj, root / "bin"):
            add_env(
                env,
                "aw_loader_paths",
                [value, str(cwd)],
                lambda cwd=cwd, value=value: aw._trusted_loader_paths(value, cwd=cwd),
            )
    for template in PATH_VARIANTS:
        env = {**base, "PATH": _expand(template, root)}
        for name in PATH_NAMES:
            for cwd in (root, proj):
                add_env(
                    env,
                    "aw_path_command",
                    [name, str(cwd)],
                    lambda name=name, cwd=cwd: aw._path_command_for_cwd(name, cwd=cwd),
                )
            add_env(
                env,
                "aw_trusted_exec",
                [[name], str(root)],
                lambda name=name: aw._trusted_pipeline_executables((name,), cwd=root),
            )
        for names in (["gh", "grep", "sort", "head"], ["gh", "rg", "tail"], ["gh"], []):
            add_env(
                env,
                "aw_trusted_exec",
                [names, str(root)],
                lambda names=names: aw._trusted_pipeline_executables(tuple(names), cwd=root),
            )
    no_path = {key: value for key, value in base.items() if key != "PATH"}
    add_env(no_path, "aw_path_command", ["gh", str(root)], lambda: aw._path_command_for_cwd("gh", cwd=root))
    add_env(
        no_path, "aw_trusted_exec", [["gh"], str(root)], lambda: aw._trusted_pipeline_executables(("gh",), cwd=root)
    )
    for item, within in (
        (root / "tmp", root / "tmp"),
        (root / "tmp" / "lib", root / "tmp"),
        (root / "bin", root / "tmp"),
        (root / "tmp", root / "missing"),
        (root / "tmp" / "work", root / "tmp" / "lib"),
        (root, root / "tmp"),
        (root / "tmp" / "lib", root / "tmp" / "lib"),
    ):
        add_env(
            base,
            "aw_within",
            [str(item), str(within)],
            lambda item=item, within=within: aw._path_is_within(item, within),
        )
    texts = list(WORKFLOWS)
    for text in texts:
        for cwd in (None, root, proj):
            add_env(
                base,
                "aw_workflow",
                [text, str(cwd) if cwd else None],
                lambda text=text, cwd=cwd: aw.is_nonexecuting_github_actions_read_workflow(text, cwd=cwd),
            )
        segments = aw._pipeline_segments(text)
        add_env(base, "aw_segments", [text], lambda text=text: aw._pipeline_segments(text))
        for values in VALUE_SETS:
            add_env(
                base,
                "aw_pipeline",
                [text, values, None],
                lambda text=text, values=values: aw._safe_github_read_pipeline(text, dict(values)),
            )
            add_env(
                base,
                "aw_text_pipeline",
                [text, values],
                lambda text=text, values=values: aw._safe_text_filter_pipeline(text, dict(values)),
            )
            add_env(base, "aw_echo", [text, values], lambda text=text, values=values: aw._safe_echo(text, dict(values)))
        if segments:
            add_env(
                base,
                "aw_metadata_pipeline",
                [segments, str(root)],
                lambda s=segments: aw._safe_actions_log_metadata_pipeline(s, cwd=root),
            )
            add_env(
                base,
                "aw_failed_pipeline",
                [segments, str(root)],
                lambda s=segments: aw._safe_failed_log_filter_pipeline(s, cwd=root),
            )
            add_env(
                {**base, "PATH": str(root / "badbin")},
                "aw_metadata_pipeline",
                [segments, str(root)],
                lambda s=segments: aw._safe_actions_log_metadata_pipeline(s, cwd=root),
            )
            add_env(
                {**base, "PATH": str(root / "badbin")},
                "aw_failed_pipeline",
                [segments, str(root)],
                lambda s=segments: aw._safe_failed_log_filter_pipeline(s, cwd=root),
            )
            if all(segments):
                add_env(base, "aw_bound_matches", [segments], lambda s=segments: aw._filters_bound_emitted_matches(s))
                if len(segments) > 1:
                    add_env(
                        base,
                        "aw_bound_matches",
                        [segments[1:]],
                        lambda s=segments: aw._filters_bound_emitted_matches(s[1:]),
                    )
    for tokens in TOKEN_LISTS:
        add_env(base, "aw_stderr", [tokens], lambda tokens=tokens: aw._without_safe_stderr_redirect(tokens))
        add_env(base, "aw_github_cmd", [tokens], lambda tokens=tokens: aw._safe_actions_github_command(tokens))
        add_env(base, "aw_output_kind", [tokens], lambda tokens=tokens: aw._github_output_kind(tokens))
        add_env(base, "aw_filter", [tokens], lambda tokens=tokens: aw._safe_emitted_output_filter(tokens))
        add_env(base, "aw_log_args", [tokens], lambda tokens=tokens: aw._safe_run_log_metadata_args(tokens))
        add_env(base, "aw_log_grep", [tokens], lambda tokens=tokens: aw._safe_log_metadata_grep(tokens))
        for values in VALUE_SETS:
            add_env(
                base,
                "aw_substitute",
                [tokens, values],
                lambda tokens=tokens, values=values: aw._substitute_number_variables(tokens, dict(values)),
            )
            add_env(
                base,
                "aw_echo_tokens",
                [tokens, values],
                lambda tokens=tokens, values=values: aw._safe_echo_tokens(tokens, dict(values)),
            )
        if tokens:
            add_env(
                base, "aw_bound_matches", [[tokens]], lambda tokens=tokens: aw._filters_bound_emitted_matches([tokens])
            )
    for args in ARG_VARIANTS:
        add_env(base, "aw_run_view", [args], lambda args=args: aw._safe_run_view_args(args))
        add_env(base, "aw_api_options", [args], lambda args=args: aw._safe_api_options(args))
    for value in COUNT_VALUES:
        add_env(base, "aw_bounded_count", [value, 100], lambda value=value: aw._bounded_count(value))
        add_env(base, "aw_bounded_count", [value, 120], lambda value=value: aw._bounded_count(value, maximum=120))


def main() -> None:
    fixture_dir = Path(sys.argv[1])
    install_offline_github_classifier(Path(os.environ["SFRS_GH_CLASSIFIER"]))
    cases: list[dict[str, object]] = []
    saved_cwd = os.getcwd()
    with tempfile.TemporaryDirectory(prefix="sfrs-gh-") as scratch:
        root = Path(scratch).resolve()
        _build(root)
        bf.classify_secret_content = _fake_secret
        eph.classify_secret_content = _fake_secret
        aw.git_binary_path_is_trusted = _trust_factory(root)
        os.chdir(root)
        os.environ.update(_env_base(root))

        def add(function: str, args: list[object], result: object) -> None:
            cases.append(
                {
                    "fn": function,
                    "env": _text(root, _env_base(root)),
                    "args": _text(root, args),
                    "result": _text(root, result),
                }
            )

        def add_env(env: dict[str, str], function: str, args: list[object], call) -> None:
            result = _run_with_env(root, env, call)
            cases.append(
                {"fn": function, "env": _text(root, env), "args": _text(root, args), "result": _text(root, result)}
            )

        def add_body(function: str, args: list[object], result: object) -> None:
            add(function, args, result)

        tempfile.tempdir = None
        with_env = _run_with_env
        # Body-file and ephemeral cases run under the default environment.
        saved = dict(os.environ)
        os.environ.clear()
        os.environ.update(_env_base(root))
        tempfile.tempdir = None
        _ephemeral_cases(add_body)
        _body_file_cases(root, add_body)
        os.environ.clear()
        os.environ.update(saved)
        tempfile.tempdir = None
        _actions_cases(root, add_env)
        # A second temp location: the sticky world-writable directory.
        stk_env = {**_env_base(root), "TMPDIR": str(root / "stk")}
        for operand in (
            "../../stk/pr-body.md",
            str(root / "stk" / "pr-body.md"),
            str(root / "stk" / "work" / "pr-body.md"),
        ):
            for cwd in (root / "home" / "proj", root / "stk"):
                add_env(
                    stk_env,
                    "bf_is_safe",
                    [operand, str(cwd), str(root / "home")],
                    lambda operand=operand, cwd=cwd: bf.github_pr_body_file_is_safe(
                        operand, cwd=cwd, home_dir=root / "home"
                    ),
                )
        del with_env
        os.chdir(saved_cwd)
        document = {"schema": "sfrs-github-body.v1", "tree": TREE, "cases": cases}
    raises = sum(1 for case in cases if isinstance(case["result"], dict) and "$raises" in case["result"])
    out = fixture_dir / "github_body.json.gz"
    out.write_bytes(gzip.compress(json.dumps(document, sort_keys=True).encode("utf-8"), mtime=0))
    print(f"{len(cases)} cases ({raises} raising) -> {out}")


if __name__ == "__main__":
    main()
