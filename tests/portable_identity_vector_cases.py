"""Portable project identity vectors shared with the native resolver.

Each case is a declarative file tree, a workspace inside it and the identity
``resolve_portable_project_identity`` derives for that workspace. The tree
never names the directory it is built in, so the identity (which hashes only
the canonical remote and the workspace path relative to the repository) is the
same wherever a test materializes it. The Rust resolver reads the same fixture.

Regenerate the checked-in fixture with
``python -m tests.portable_identity_vector_cases``.
"""

from __future__ import annotations

import base64
import json
import random
import tempfile
from collections.abc import Callable
from pathlib import Path

from codex_plugin_scanner.guard.project_identity import resolve_portable_project_identity

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "portable-project-identity.v1.json"
SCHEMA = "guard.portable-project-identity.vectors.v1"
CORPUS_SEEDS = range(1, 61)

_ZERO_OID = "0" * 40
_ONE_OID = "1" * 40
_SIGNATURE = "Guard Test <guard@example.invalid> 1700000000 +0000"
_FETCH = "+refs/heads/*:refs/remotes/origin/*"

Entry = dict[str, object]
Case = dict[str, object]


def _file(path: str, text: str, *, pad: int = 0) -> Entry:
    entry: Entry = {"path": path, "text": text}
    if pad:
        entry["pad"] = pad
    return entry


def _config(remote: str) -> str:
    return (
        "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n"
        f'\tlogallrefupdates = true\n[remote "origin"]\n\turl = {remote}\n\tfetch = {_FETCH}\n'
    )


def _clone_line(remote: str, *, previous: str = _ZERO_OID) -> str:
    return f"{previous} {_ONE_OID} {_SIGNATURE}\tclone: from {remote}\n"


def _repo(
    root: str,
    remote: str,
    *,
    config: str | None = None,
    reflog: str | None = None,
    clone_remote: str | None = None,
) -> list[Entry]:
    head_log = reflog if reflog is not None else _clone_line(clone_remote or remote)
    return [
        _file(f"{root}/README.md", "guard\n"),
        _file(f"{root}/.git/config", config if config is not None else _config(remote)),
        _file(f"{root}/.git/logs/HEAD", head_log),
    ]


def _case(case_id: str, tree: list[Entry], workspace: str = "repo") -> Case:
    return {"id": case_id, "tree": tree, "workspace": workspace}


def _remote_cases() -> list[Case]:
    remotes = {
        "https_github": "https://github.com/Owner/Repository.git",
        "https_github_explicit_default_port": "https://github.com:443/owner/repository.GIT",
        "ssh_url_port_2201": "ssh://git@example.invalid:2201/owner/repository.git",
        "ssh_url_port_2202": "ssh://git@example.invalid:2202/owner/repository.git",
        "ssh_url_default_port": "ssh://git@example.invalid:22/owner/repository.git",
        "scp_with_user": "git@example.invalid:owner/repository.git",
        "scp_without_user": "example.invalid:owner/repository",
        "scp_user_with_colon": "a:b@Example.invalid:Owner/Repo.git",
        "scp_slash_before_colon": "example.invalid/owner:repository",
        "ghe_host_lowercases_path": "https://Acme.GHE.com/Org/Repo.git",
        "other_host_keeps_path_case": "https://gitlab.example/Group/Sub/Project.git",
        "trailing_slash": "https://example.invalid/owner/repo/",
        "http_nondefault_port": "http://example.invalid:8080/o/r",
        "git_scheme_default_port": "git://example.invalid:9418/o/r.git",
        "port_out_of_range": "https://example.invalid:70000/o/r",
        "port_with_letters": "https://example.invalid:abc/o/r",
        "port_leading_zero": "https://example.invalid:0443/o/r",
        "file_scheme": "file:///srv/repository.git",
        "empty_path": "https://example.invalid/",
        "only_git_suffix": "https://example.invalid/.git",
        "userinfo_and_default_port": "https://user:pw@example.invalid:443/o/r.git",
        "hostname_zone": "ssh://git@Host%25Zone/o/r",
        "uppercase_scheme": "HTTPS://GitHub.com/O/R",
        "query_and_fragment": "https://example.invalid/o/r.git?x=1#y",
        "fragment_before_query": "https://example.invalid/o/r#y?x=1",
        "empty_hostname": "https://:443/o/r",
        "inner_space": "https://example.invalid/o/r ; comment",
        "ipv6_explicit_port": "ssh://git@[::1]:9418/owner/repo.git",
        "ipv6_address_suffix": "ssh://git@[::1:9418]/owner/repo.git",
    }
    return [_case(f"remote_{name}", _repo("repo", remote)) for name, remote in remotes.items()]


def _layout_cases() -> list[Case]:
    remote = "https://github.com/example/trusted-repository.git"
    external = [
        _file("external-git/config", f'[remote "origin"]\n\turl = {remote}\n'),
        _file("external-git/logs/HEAD", _clone_line(remote)),
    ]
    pointer = [_file("pointer/.git", "gitdir: ../repo/.git\n"), *_repo("repo", remote)]
    git_symlink = [*external, {"path": "workspace/.git", "symlink": "external-git"}]
    config_symlink = [
        *external,
        {"path": "workspace/.git/config", "symlink": "external-git/config"},
        _file("workspace/.git/logs/HEAD", _clone_line(remote)),
    ]
    logs_symlink = [
        *external,
        _file("workspace/.git/config", f'[remote "origin"]\n\turl = {remote}\n'),
        {"path": "workspace/.git/logs", "symlink": "external-git/logs"},
    ]
    head_symlink = [
        *external,
        _file("workspace/.git/config", f'[remote "origin"]\n\turl = {remote}\n'),
        {"path": "workspace/.git/logs/HEAD", "symlink": "external-git/logs/HEAD"},
    ]
    monorepo = [*_repo("repo", remote), {"path": "repo/apps/first", "dir": True}]
    monorepo.append({"path": "repo/apps/second", "dir": True})
    deep = [*_repo("repo", remote), {"path": "repo/a/b", "dir": True}]
    inner_remote = "https://github.com/example/inner-repository.git"
    unconfigured_inner = [*_repo("repo", remote), {"path": "repo/inner/.git", "dir": True}]
    nested = [*_repo("repo", remote), *_repo("repo/inner", inner_remote), {"path": "repo/inner/src", "dir": True}]
    return [
        _case("layout_gitdir_pointer_file", pointer, "pointer"),
        _case("layout_git_directory_symlink", git_symlink, "workspace"),
        _case("layout_config_symlink", config_symlink, "workspace"),
        _case("layout_logs_symlink", logs_symlink, "workspace"),
        _case("layout_head_symlink", head_symlink, "workspace"),
        _case("layout_logs_missing", [_file("repo/.git/config", _config(remote))]),
        _case("layout_config_missing", [_file("repo/.git/logs/HEAD", _clone_line(remote))]),
        _case("layout_config_is_directory", [*external, {"path": "repo/.git/config", "dir": True}]),
        _case("layout_monorepo_first", monorepo, "repo/apps/first"),
        _case("layout_monorepo_second", monorepo, "repo/apps/second"),
        _case("layout_git_two_levels_up", deep, "repo/a/b"),
        _case("layout_walk_stops_at_unconfigured_git", unconfigured_inner, "repo/inner"),
        _case("layout_walk_stops_at_nearest_repository", nested, "repo/inner/src"),
        _case("layout_workspace_is_file", _repo("repo", remote), "repo/README.md"),
        _case("layout_non_git_workspace", [{"path": "plain", "dir": True}], "plain"),
        _case("layout_filesystem_root", [], "/"),
    ]


def _reflog_cases() -> list[Case]:
    remote = "https://github.com/example/repo.git"
    commit = f"{_ZERO_OID} {_ONE_OID} {_SIGNATURE}\tcommit (initial): initial\n"
    checkout = f"{_ONE_OID} {_ONE_OID} {_SIGNATURE}\tcheckout: moving from main to dev\n"
    cases = {
        "no_clone_provenance": commit + checkout,
        "previous_oid_not_zero": _clone_line(remote, previous=_ONE_OID),
        "clone_not_first_line": commit + _clone_line(remote),
        "clone_remote_differs": _clone_line("https://github.com/example/other.git"),
        "clone_canonically_equal": _clone_line("git@github.com:Example/Repo.git"),
        "file_clone_then_real_clone": _clone_line("file:///srv/repo.git") + _clone_line(remote),
        "unicode_line_separator": f"noise\u2028{_clone_line(remote)}",
        "form_feed_separator": f"noise\x0c{_clone_line(remote)}",
        "unit_separator_in_fields": f"{_ZERO_OID}\x1f{_ONE_OID} {_SIGNATURE}\tclone: from {remote}\n",
        "single_field": f"{_ZERO_OID}\tclone: from {remote}\n",
        "no_tab": f"{_ZERO_OID} {_ONE_OID} clone: from {remote}\n",
        "crlf_lines": _clone_line(remote).replace("\n", "\r\n"),
        "clone_remote_padded": f"{_ZERO_OID} {_ONE_OID} {_SIGNATURE}\tclone: from   {remote}  \n",
    }
    built = [_case(f"reflog_{name}", _repo("repo", remote, reflog=log)) for name, log in cases.items()]
    invalid = _repo("repo", remote)
    invalid[2] = {"path": "repo/.git/logs/HEAD", "base64": base64.b64encode(b"\xff\xfe" + b"x\n").decode()}
    built.append(_case("reflog_invalid_utf8", invalid))
    oversized = _repo("repo", remote)
    oversized[2] = _file("repo/.git/logs/HEAD", _clone_line(remote), pad=4 * 1024 * 1024)
    built.append(_case("reflog_oversized", oversized))
    return built


def _config_cases() -> list[Case]:
    remote = "https://example.invalid/owner/repository.git"
    origin = f'[remote "origin"]\n\turl = {remote}\n'
    configs = {
        "valueless_keys": _config(remote) + "\n[guard-test]\n\tbare\n",
        "crlf": _config(remote).replace("\n", "\r\n"),
        "bare_cr": _config(remote).replace("\n", "\r"),
        "bom": "\ufeff" + _config(remote),
        "missing_section_header": f"url = {remote}\n{origin}",
        "leading_delimiter": f"[core]\n\t= x\n{origin}",
        "inline_semicolon_kept": f'[remote "origin"]\n\turl = {remote} ; note\n',
        "uppercase_key": f'[remote "origin"]\n\tURL = {remote}\n',
        "colon_delimiter": f'[remote "origin"]\n\turl: {remote}\n',
        "capitalized_section": f'[Remote "origin"]\n\turl = {remote}\n',
        "default_fallback": f'[DEFAULT]\nurl = {remote}\n[remote "origin"]\n\tfetch = {_FETCH}\n',
        "default_without_origin": f"[DEFAULT]\nurl = {remote}\n[core]\n\tbare = false\n",
        "origin_valueless_url": '[remote "origin"]\n\turl\n',
        "origin_blank_url": '[remote "origin"]\n\turl =   \n',
        "continuation_into_url": f'[remote "origin"]\nurl = {remote}\n\tfetch = {_FETCH}\n',
        "continuation_scp_url": '[remote "origin"]\nurl = git@example.invalid:o/r\n\tmore\n',
        "empty_line_in_value": f'[remote "origin"]\nurl = {remote}\n\n\tmore\n',
        "section_trailing_text": f'[remote "origin"] # trailing\n\turl = {remote}\n',
        "duplicate_url": f'[remote "origin"]\n\turl = https://example.invalid/a/b\n\turl = {remote}\n',
        "duplicate_section": f'{origin}[core]\n\tbare = false\n[remote "origin"]\n\turl = {remote}\n',
        "comment_lines": f'# lead\n[remote "origin"]\n; mid\n\t# indented\n\turl = {remote}\n',
    }
    built = [_case(f"config_{name}", _repo("repo", remote, config=text)) for name, text in configs.items()]
    invalid = _repo("repo", remote)
    invalid[1] = {"path": "repo/.git/config", "base64": base64.b64encode(b"[core]\n\xc3\x28\n").decode()}
    built.append(_case("config_invalid_utf8", invalid))
    oversized = _repo("repo", remote, config=_config(remote))
    oversized[1] = _file("repo/.git/config", _config(remote), pad=1024 * 1024)
    built.append(_case("config_oversized", oversized))
    return built


_CORPUS_REMOTES = (
    "https://github.com/Owner/Repo.git",
    "git@example.invalid:team/app.git",
    "ssh://git@example.invalid:2222/team/app",
    "https://gitlab.example/Group/Sub/Project.git",
    "http://example.invalid:8080/a/b/",
)


def _corpus_config(rng: random.Random, remote: str) -> str:
    indent = rng.choice(["\t", "    ", "", " "])
    delim = rng.choice([" = ", "=", " : ", ":", "\t=\t"])

    def noise() -> list[str]:
        roll = rng.random()
        if roll < 0.2:
            return [rng.choice(["# note", "; note", f"{indent}# indented", "  ;x = y"])]
        if roll < 0.35:
            return [rng.choice(["", "   ", "\t"])]
        return []

    core = ["[core]", f"{indent}repositoryformatversion{delim}0", f"{indent}bare{delim}false"]
    if rng.random() < 0.3:
        core.append(f"{indent}valueless")
    header = rng.choice(['[remote "origin"]'] * 4 + ['[Remote "origin"]', '[remote "Origin"]', '[remote  "origin"]'])
    origin = [header]
    if rng.random() < 0.85:
        origin.append(f"{indent}{rng.choice(['url', 'url', 'URL', 'Url'])}{delim}{remote}")
        if rng.random() < 0.15:
            origin.append(f"{indent}\t{rng.choice(['tail', '/x', 'git@h:p'])}")
    origin.append(f"{indent}fetch{delim}{_FETCH}")
    if rng.random() < 0.3:
        origin.append(f"{indent}  {rng.choice(['+refs/tags/*', 'extra'])}")
    sections = [origin]
    if rng.random() < 0.5:
        sections.append(['[remote "upstream"]', f"{indent}url{delim}https://example.invalid/up/stream.git"])
    if rng.random() < 0.3:
        default = ["[DEFAULT]"]
        if rng.random() < 0.7:
            default.append(f"url{delim}{rng.choice(_CORPUS_REMOTES)}")
        sections.append(default)
    if rng.random() < 0.4:
        sections.append(['[branch "main"]', f"{indent}remote{delim}origin", f"{indent}merge{delim}refs/heads/main"])
    rng.shuffle(sections)
    lines = [*noise(), *core]
    for section in sections:
        for line in section:
            lines.extend(noise())
            lines.append(line)
    return "\n".join(lines) + rng.choice(["\n", "", "\n\n"])


def _corpus_cases() -> list[Case]:
    cases: list[Case] = []
    for seed in CORPUS_SEEDS:
        rng = random.Random(seed)
        remote = rng.choice(_CORPUS_REMOTES)
        clone = remote if rng.random() < 0.85 else rng.choice(_CORPUS_REMOTES)
        config = _corpus_config(rng, remote)
        cases.append(_case(f"corpus_{seed:02d}", _repo("repo", remote, config=config, clone_remote=clone)))
    return cases


def vector_cases() -> list[Case]:
    """Every case, in fixture order, without its derived identity."""
    return [*_remote_cases(), *_layout_cases(), *_reflog_cases(), *_config_cases(), *_corpus_cases()]


def materialize(case: Case, root: Path) -> Path:
    """Build ``case``'s tree under ``root`` and return its workspace path."""
    tree = case["tree"]
    assert isinstance(tree, list)
    for entry in tree:
        target = root / str(entry["path"])
        target.parent.mkdir(parents=True, exist_ok=True)
        if entry.get("dir"):
            target.mkdir(parents=True, exist_ok=True)
        elif "symlink" in entry:
            linked = root / str(entry["symlink"])
            target.symlink_to(linked, target_is_directory=linked.is_dir())
        elif "base64" in entry:
            target.write_bytes(base64.b64decode(str(entry["base64"])))
        else:
            data = str(entry["text"]).encode("utf-8") + b"\n" * int(str(entry.get("pad", 0)))
            target.write_bytes(data)
    workspace = str(case["workspace"])
    return Path(workspace) if workspace.startswith("/") else root / workspace


def derive(case: Case, root: Path) -> str | None:
    """The identity the Python resolver derives for ``case`` built under ``root``."""
    return resolve_portable_project_identity(materialize(case, root))


def build_fixture(make_root: Callable[[str], Path]) -> dict[str, object]:
    cases = []
    for case in vector_cases():
        cases.append({**case, "identity": derive(case, make_root(str(case["id"])))})
    return {"schema": SCHEMA, "cases": cases}


def _write_fixture() -> None:
    with tempfile.TemporaryDirectory() as scratch:
        base = Path(scratch).resolve()
        fixture = build_fixture(lambda case_id: base / case_id)
    FIXTURE_PATH.write_text(json.dumps(fixture, indent=1, ensure_ascii=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    _write_fixture()
