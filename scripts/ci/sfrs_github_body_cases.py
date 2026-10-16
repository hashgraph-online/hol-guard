"""Record parity vectors for the PR body-file check.

Ephemeral-body and Actions read cases are carried forward unchanged from the
existing fixture; their Python implementation is retired.

Usage: ``SFRS_GH_CLASSIFIER=<guard-command-source binary> sfrs_github_body_cases.py
FIXTURE_DIR`` with the repository ``src`` on ``PYTHONPATH``. GitHub CLI
classification is answered by the Rust classifier, as in production. A fixed tree is built under a fresh root; every case runs with a
recorded environment (``PATH``, ``TMPDIR``, ``HOME``, ...) and stores the result
with the ``{ROOT}`` token so the Rust port can rebuild the tree and replay it.
Secret-content classification is replaced by a fixed stub that the replay
host mirrors. Retired with the Python implementation.
"""

# ruff: noqa
from __future__ import annotations

import gzip
import json
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


def _retired_cases(fixture_dir: Path) -> list[dict[str, object]]:
    """Ephemeral-body and Actions-read cases, frozen when their Python owner retired."""

    document = json.loads(gzip.decompress((fixture_dir / "github_body.json.gz").read_bytes()))
    return [case for case in document["cases"] if str(case["fn"]).startswith(_RETIRED_PREFIXES)]


_RETIRED_PREFIXES = ("aw_", "eph_")


def main() -> None:
    fixture_dir = Path(sys.argv[1])
    install_offline_github_classifier(Path(os.environ["SFRS_GH_CLASSIFIER"]))
    cases: list[dict[str, object]] = []
    saved_cwd = os.getcwd()
    with tempfile.TemporaryDirectory(prefix="sfrs-gh-") as scratch:
        root = Path(scratch).resolve()
        _build(root)
        bf.classify_secret_content = _fake_secret
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
        # Body-file cases run under the default environment.
        saved = dict(os.environ)
        os.environ.clear()
        os.environ.update(_env_base(root))
        tempfile.tempdir = None
        _body_file_cases(root, add_body)
        os.environ.clear()
        os.environ.update(saved)
        tempfile.tempdir = None
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
        cases.extend(_retired_cases(fixture_dir))
        document = {"schema": "sfrs-github-body.v1", "tree": TREE, "cases": cases}
    raises = sum(1 for case in cases if isinstance(case["result"], dict) and "$raises" in case["result"])
    out = fixture_dir / "github_body.json.gz"
    out.write_bytes(gzip.compress(json.dumps(document, sort_keys=True).encode("utf-8"), mtime=0))
    print(f"{len(cases)} cases ({raises} raising) -> {out}")


if __name__ == "__main__":
    main()
