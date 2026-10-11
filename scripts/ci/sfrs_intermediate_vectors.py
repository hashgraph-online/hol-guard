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

from codex_plugin_scanner.guard.runtime.secret_file_request_services import (
    local_read_operands,
    read_only_filters,
    docker_requests,
    request_artifacts,
    shell_quote_tokens,
    shell_static_safety,
    shell_tokenization,
)

MAX_TEXTS = 6000
HOST_MARKERS = ("michaelkantor", "runner2-port", "hol-guard/.venv", "/home/runner", "/var/folders", "~/.codex")


DOCKER_EXTRAS = (
    "docker run alpine true",
    "docker login registry.example",
    "docker push example/app:1",
    "docker ps",
    "docker --help",
    "docker build --help",
    "docker build -t app .",
    "docker build --build-arg API_TOKEN=abc .",
    "docker build --build-arg TOKEN .",
    "docker build --build-arg NAME=$SECRET_KEY .",
    "docker build --secret id=x,src=.env .",
    "docker build -o type=local,dest=out .",
    "docker build --label token=ghp_abc .",
    "docker buildx build --push -t app .",
    "docker buildx --builder b build --secret id=x .",
    "docker buildx ls",
    "docker buildx build --build-arg PASSWORD=x .",
    "docker compose up -d",
    "docker compose ps",
    "docker compose exec web sh",
    "docker compose run web true",
    "docker compose --env-file prod.env up",
    "docker compose -f a.yml -p proj config",
    "docker compose build --build-arg API_KEY=x",
    "docker compose frobnicate",
    "docker compose -- up",
    "docker compose -- run web",
    "docker --context prod ps",
    "docker --context default ps",
    "docker -c prod ps",
    "docker -cprod ps",
    "docker -H tcp://host:2375 ps",
    "docker -Htcp://host ps",
    "docker --host=ssh://u@h ps",
    "docker --tlsverify ps",
    "docker --tls ps",
    "docker --config /tmp/x ps",
    "docker --config=/tmp/x ps",
    "DOCKER_HOST=tcp://h:1 docker ps",
    "DOCKER_HOST=unix:///var/run/docker.sock docker ps",
    "DOCKER_CONTEXT=prod docker ps",
    "DOCKER_CONTEXT=default docker ps",
    "DOCKER_TLS_VERIFY=1 docker ps",
    "DOCKER_TLS_VERIFY=0 docker ps",
    "DOCKER_CERT_PATH=/x docker ps",
    "DOCKER_CONFIG=/x docker ps",
    "export DOCKER_HOST=tcp://h:1 && docker ps",
    "export DOCKER_HOST=unix:///x; docker ps",
    "export DOCKER_CONTEXT=prod; docker compose ps",
    "env DOCKER_HOST=tcp://h docker ps",
    "env -i DOCKER_HOST=tcp://h docker ps",
    "env -u DOCKER_HOST docker ps",
    "env -S 'docker run x'",
    "env docker run x",
    "env",
    "env FOO=1",
    "sudo docker ps",
    "cd /tmp && docker ps && docker login",
    "docker ps | docker run x",
    "docker ps && echo hi > .docker/config.json",
    "cat ~/.docker/config.json",
    "docker --debug ps",
    "docker -D run x",
    "docker -l debug build -t a .",
    "docker image build --build-arg X=1 .",
    "docker builder build .",
)


SCRIPT_EXTRAS = (
    "import os as o; o.remove('x')",
    "import os, sys as s",
    "import os.path as p",
    "import json as j, subprocess",
    "from subprocess import run as r",
    "from os import path",
    "from os import path as p",
    "from os.path import join as j",
    "from .os import path as p",
    "from collections import OrderedDict as od",
    "from os import (\n    path as p,\n)",
    "if True:\n    import shutil as sh",
    "x = 1; import pathlib as pl",
    "print('import os as o')",
    "# import os as o\nprint(1)",
    "x = \"\"\"\nimport os as o\n\"\"\"",
    "import os as",
    "def broken(:\n  import os as o",
    "sleep 1",
    "sleep 1.5",
    "import time; time.sleep(2)",
    "time.sleep( 3 )",
    "print(open('f').read())",
    "open('f', 'w').write('x')",
    "Path('f').write_text('x')",
    "print(1)",
    "",
    "  ",
)


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
        for vector in document["vectors"]:
            _walk(vector["args"], found)
    found.update(DOCKER_EXTRAS)
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
    }


def main() -> None:
    fixture_dir = Path(sys.argv[1])
    os.environ.pop("RIPGREP_CONFIG_PATH", None)
    corpus = _corpus(fixture_dir)
    records = [_record(text) for text in corpus]
    scripts = sorted({*SCRIPT_EXTRAS, *(text for record in records for text in record["static"]["texts"])})
    document = {"schema": "sfrs-intermediate.v1", "tokens": records, "scripts": [_script(text) for text in scripts]}
    out = fixture_dir / "intermediate_tokens.json.gz"
    out.write_bytes(gzip.compress(json.dumps(document, sort_keys=True).encode("utf-8"), mtime=0))
    print(f"{len(records)} records -> {out}")


if __name__ == "__main__":
    main()
