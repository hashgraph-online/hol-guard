"""Generate CPython 3.12/UCD 15 reference cases for the final eight IR operations.

Run from the repository root with PYTHONPATH=src and the locked Python 3.12
interpreter. --check verifies checked-in fixtures without changing them.
Canonical argument vectors isolate matcher behavior from shell parser behavior.
The native implementation returns explicit uncertainty for unsupported Unicode
case conversion and URL authority normalization; marked cases retain the Python
answer and require that uncertainty instead of an empty native match result.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import random
import re
import sys
import unicodedata
from pathlib import Path
from types import SimpleNamespace

from codex_plugin_scanner.guard.runtime.command_curl_parsing import (
    CURL_LONG_OPTIONS_WITH_VALUES,
    CURL_SHORT_OPTIONS_WITH_VALUES,
)
from codex_plugin_scanner.guard.runtime.command_database_matchers import (
    ArgumentCommandMatcher,
    CommandSequenceMatcher,
    LeadingSubcommandMatcher,
)
from codex_plugin_scanner.guard.runtime.command_framework_extensions import PhpArtisanScriptMatcher
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from codex_plugin_scanner.guard.runtime.command_platform_extensions import _ZeroOperandFlagMatcher
from codex_plugin_scanner.guard.runtime.command_repo2nb_extensions import Repo2nbUnresolvedExpansionMatcher
from codex_plugin_scanner.guard.runtime.command_reviewed_literal_matcher import ReviewedLiteralCommandMatcher
from codex_plugin_scanner.guard.runtime.command_search_messaging_extensions import CurlElasticsearchDeleteMatcher


def serializable(value):
    if isinstance(value, dict):
        return {key: serializable(item) for key, item in value.items()}
    if isinstance(value, (set, frozenset)):
        return [serializable(item) for item in sorted(value)]
    if isinstance(value, (tuple, list)):
        return [serializable(item) for item in value]
    return value


def generate():
    definitions, cases = [], []

    def definition(op, matcher):
        index = len(definitions)
        definitions.append({"op": op, "config": serializable(dataclasses.asdict(matcher))})
        return index, matcher

    def add(definition, executable, arguments, *, error=None, extra=(), raw=None):
        index, matcher = definition
        segments = [SimpleNamespace(executable=executable, arguments=tuple(arguments))]
        segments.extend(SimpleNamespace(executable=name, arguments=tuple(args)) for name, args in extra)
        model = SimpleNamespace(segments=tuple(segments))
        if raw is not None:
            segment = segments[0]
            segment.tokens = (executable, *arguments)
            segment.environment_names = segment.wrapper_chain = ()
            segment.path_overridden, segment.pipeline_index = False, 0
            model.dialect, model.transport, model.confidence = "posix", "shell_string", "exact"
            model.raw_text, model.normalized_text = raw, raw.strip()
            model.wrapper_chain = model.redirects = model.embedded_commands = ()
            model.path_overridden = False
        case = {
            "definition": index,
            "segments": [[item.executable, list(item.arguments)] for item in segments],
            "expected": [e.segment_index for e in matcher.match(model)],
        }
        if raw is not None:
            case["raw"] = raw
        if error is not None:
            case["native_error"] = error
        cases.append(case)

    argument = definition("argument-command.v1", ArgumentCommandMatcher(frozenset({" DB "}), " RESET ", 3, 1))
    for value in [
        "reset database",
        "res data",
        "re data",
        "reset",
        "reset ",
        "reset\tdata",
        "RESET\x1cDATA",
        " reset\u2003payload ",
        "reset\u00a0数据",
        "resetting data",
        "help reset data",
        "res\x1c\x1f数据",
    ]:
        add(argument, "/usr/bin/DB", ["ignored", value])
    add(argument, "db", ["reset data"])
    add(argument, "other", ["ignored", "reset data"])
    add(argument, "db", ["ignored", "réset data"], error="unsupported_unicode_case_mapping")
    add(
        argument,
        None,
        ["ignored", "reset data"],
        extra=[("db", ["ignored", "reset data"]), ("db", ["ignored", "res data"])],
    )

    sequence = definition(
        "command-sequence.v1",
        CommandSequenceMatcher(
            frozenset({"db"}),
            (("get", 1), ("set", 2), ("delete", 1), ("debug", 0), ("reset", 0)),
            frozenset({"delete", "reset"}),
            frozenset({"-H", "--host"}),
            frozenset({"--help", "-h"}),
        ),
    )
    for args in [
        [],
        ["delete"],
        ["del", "key"],
        ["d", "key"],
        ["de", "key"],
        ["get", "reset"],
        ["get", "key", "reset"],
        ["set", "key", "reset"],
        ["set", "key", "value", "reset"],
        ["get", "key", "unknown", "reset"],
        ["--host", "reset", "get", "key"],
        ["--host=host", "reset"],
        ["-Hhost", "reset"],
        ["-h", "reset"],
        ["reset", "--help"],
        ["--host", "--help", "reset"],
        ["--", "reset", "--help"],
        ["RESET"],
        ["  reset  "],
        ["", "reset"],
        ["--unknown", "reset"],
        ["--HOST", "host", "reset"],
        ["-H", "host", "res"],
    ]:
        add(sequence, "db", args)
    add(sequence, "db", ["rÉset"], error="unsupported_unicode_case_mapping")

    leading = definition(
        "leading-subcommand.v1",
        LeadingSubcommandMatcher(
            frozenset({"db"}),
            ("cluster", "delete"),
            frozenset({"-H", "--host"}),
            frozenset({"--dry-run"}),
            frozenset({"--force"}),
            frozenset({"--context", "-n"}),
            frozenset({"--help", "-h"}),
        ),
    )
    for args in [
        ["cluster", "delete", "--force"],
        ["cluster", "delete"],
        ["--force", "cluster", "delete"],
        ["-H", "host", "cluster", "delete", "--force"],
        ["--host", "--force", "cluster", "delete"],
        ["cluster", "--context", "prod", "delete", "--force"],
        ["cluster", "--context=prod", "delete", "--force"],
        ["cluster", "--context", "delete", "--force"],
        ["cluster", "-n", "namespace", "delete", "--force"],
        ["cluster", "-nnamespace", "delete", "--force"],
        ["cluster", "delete", "--help", "--force"],
        ["cluster", "delete", "-vh", "--force"],
        ["cluster", "delete", "-v=h", "--force"],
        ["--host", "--help", "cluster", "delete", "--force"],
        ["--", "cluster", "delete", "--force"],
        ["--dry-run", "cluster", "delete", "--force"],
        ["cluster", "delete", "--dry-run", "--force"],
        ["CLUSTER", "DELETE", "--FORCE"],
        ["cluster", "delete", "--force=false"],
        ["cluster", "delete", "--force", "--no-force"],
        ["cluster", "--context"],
        ["cluster", "--context=prod"],
    ]:
        add(leading, "db", args)
    add(leading, "db", ["cluster", "delete", "--force", "dataé"], error="unsupported_unicode_case_mapping")

    php = definition("php-artisan-script.v1", PhpArtisanScriptMatcher(("migrate:fresh",)))
    php_help = definition("php-artisan-script.v1", PhpArtisanScriptMatcher(("migrate:fresh",), frozenset({"--help"})))
    for args in [
        ["artisan", "migrate:fresh"],
        ["/srv/artisan", "migrate:fresh"],
        ["C:\\app\\ARTISAN", "MIGRATE:FRESH"],
        ["-c", "config.ini", "artisan", "migrate:fresh"],
        ["-dfoo=bar", "artisan", "migrate:fresh"],
        ["--define=x", "artisan", "migrate:fresh"],
        ["--php-ini", "artisan", "migrate:fresh"],
        ["artisan.php", "migrate:fresh"],
        ["artisan", "--env", "production", "migrate:fresh"],
        ["artisan", "--env", "--help", "migrate:fresh"],
        ["artisan", "migrate:fresh", "--help"],
        ["artisan", "migrate:fresh", "--help=false"],
        ["artisan", "migrate:fresh", "--help", "--no-help"],
        ["artisan", "--", "migrate:fresh", "--help"],
        ["artisan", "migrate:fresh", "--", "--help"],
        ["artisan", "other", "migrate:fresh"],
        ["-c"],
        [],
    ]:
        for definition_ in [php, php_help]:
            add(definition_, "PHP.EXE", args)
    add(php, "php", ["artisan", "migrate:fresh", "é"])

    zero = definition(
        "zero-operand-flags.v1",
        _ZeroOperandFlagMatcher(frozenset({"deploy"}), frozenset({"--prod"}), frozenset({"-C", "--cwd"})),
    )
    for args in [
        [],
        ["--prod"],
        ["--prod=false"],
        ["--prod", "--no-prod"],
        ["--prod", "project"],
        ["--cwd", "project", "--prod"],
        ["--cwd", "--prod"],
        ["-Cproject", "--prod"],
        ["--prod", "--"],
        ["--", "--prod"],
        ["--unknown", "--prod"],
        ["--PROD"],
        ["--prod", "--cwd"],
        ["--prod", "-"],
        ["--prod", "-vh"],
    ]:
        add(zero, "deploy", args)

    curl = definition("curl-elasticsearch-delete.v1", CurlElasticsearchDeleteMatcher())
    url = "http://localhost:9200/items"
    for args in [
        ["-X", "DELETE", url],
        ["-XDELETE", url],
        ["-vXDELETE", url],
        ["-X", "DELETE", "-X", "GET", url],
        ["-X", "GET", "--request=DELETE", url],
        ["--REQUEST", "DELETE", url],
        ["-xDELETE", url],
        ["--request", "DELETE", "--url", url],
        ["--request=DELETE", "--url=" + url],
        ["-XDELETE", url, "--next", "-XGET", url],
        ["-XDELETE", "https://example.com/", "--next", url],
        ["-XGET", url, "--next", "-XDELETE", url],
        ["-XDELETE", "--", url],
        ["--", "-XDELETE", url],
        ["-XDELETE", "--request"],
        ["-XDELETE", "--url"],
        ["--request", "--next", url],
        ["-XDELETE", "--url", "--next", url],
        ["-XDELETE", "--unknown", url],
        ["-XDELETE", "-éXGET", url],
        ["-XDELETE", "-éXDELETE", url],
    ]:
        add(curl, "curl", args)
    for option in sorted(CURL_LONG_OPTIONS_WITH_VALUES):
        add(curl, "curl", [option, "--request=DELETE", url])
        add(curl, "curl", ["-XDELETE", option, url])
    for option in sorted(CURL_SHORT_OPTIONS_WITH_VALUES):
        add(curl, "curl", ["-v" + option, "--request=DELETE", url])
        add(curl, "curl", ["-XDELETE", "-" + option, url])
    urls = [
        "localhost:9200/items",
        "elasticsearch/items",
        "https://elasticsearch/items",
        "ftp://localhost:9200/items",
        "http://elasticsearch",
        "http://elasticsearch/",
        "http://elasticsearch/?x=1",
        "http://elasticsearch/#x",
        "http://foo.elasticsearch.test/items",
        "http://notelasticsearch/items",
        "http://user:password@localhost:9200/items",
        "http://user@user@localhost:9200/items",
        "http://:9200/items",
        "http:///items",
        "http://localhost:/items",
        "http://elasticsearch:65536/items",
        "http://elasticsearch:-1/items",
        "http://elasticsearch:+9200/items",
        "http://elasticsearch: 9200/items",
        "http://localhost:0009200/items",
        "http://elasticsearch:abc/items",
        "http://[::1]:9200/items",
        "http://[::1%eth0]:9200/items",
        "http://[::1%]:9200/items",
        "http://[::1%a%b]:9200/items",
        "http://[::1]extra:9200/items",
        "http://prefix[::1]:9200/items",
        "http://[127.0.0.1]:9200/items",
        "http://[v1.elasticsearch]/items",
        "http://[V1.elasticsearch]/items",
        "http://[vAB.a]:9200/items",
        "http://[v1.]:9200/items",
        "http://[::1/items",
        "http://a]b/items",
        "http://[user]@localhost:9200/items",
        "http://[user]@elasticsearch/items",
        "http://[user]@[::1]:9200/items",
        "\x00 HTTP://elasticsearch/items",
        "http://elastic\tsearch/items",
        "http://elasticsearch/a\nb",
        "http://localhost:9200/数据",
        "elasticsearch/数据",
        "'http://elasticsearch/items'",
        '"http://elasticsearch/items"',
        "$ELASTICSEARCH_HOST/items",
        "${ELASTICSEARCH_URL}/items",
        "$ELASTICSEARCH_HOST",
        "http://localhost:9200//",
        "http://localhost:9200?path=/items",
        "//localhost:9200/items",
        "http://elasticsearch./items",
        "http://.elasticsearch/items",
    ]
    for target in urls:
        add(curl, "curl", ["-XDELETE", target])
    for target in ["http://é:9200/items", "http://elasticsearch\uff1a9200/items", "http://\uff45lasticsearch/items"]:
        add(curl, "curl", ["-XDELETE", target], error="unsupported_url_authority_normalization")
    add(curl, "curl", ["-XDELETE", "--héader", url], error="unsupported_unicode_case_mapping")
    # Deterministic mixtures challenge grouping, option consumption, and overrides.
    rng = random.Random(32029)
    pieces = [
        ["-XDELETE"],
        ["-XGET"],
        ["--next"],
        [url],
        ["--url", url],
        ["--header", "-XDELETE"],
        ["--data", url],
        ["--"],
        ["-v"],
        ["--request", "delete"],
    ]
    for _ in range(100):
        add(curl, "curl", [token for _ in range(rng.randrange(1, 7)) for token in rng.choice(pieces)])

    repo = definition("repo2nb-expansion.v1", Repo2nbUnresolvedExpansionMatcher())
    for launcher in repo[1].launchers:
        for tail in [["$FLAGS"], ["${FLAGS}"], ["`flags`"], ["literal"], ["--output", "$DEST"]]:
            add(repo, launcher[0], [*launcher[1:], "reverse", *tail])
    for args in [
        ["-n", "1", "repo2nb", "reverse", "$FLAGS"],
        ["-n1", "repo2nb", "reverse", "$FLAGS"],
        ["-P", "1", "repo2nb", "reverse", "$FLAGS"],
        ["--", "repo2nb", "reverse", "$FLAGS"],
        ["-", "repo2nb", "reverse", "$FLAGS"],
        ["--unknown", "repo2nb", "reverse", "$FLAGS"],
        ["--unknown", "value", "repo2nb", "reverse", "$FLAGS"],
    ]:
        add(repo, "xargs", args)
    for args in [["--help", "reverse", "$FLAGS"], ["sync", "$FLAGS"], ["reverse", "literal"], ["reverse", "é$FLAGS"]]:
        add(repo, "repo2nb", args)
    add(
        repo,
        "other",
        ["reverse", "$FLAGS"],
        extra=[
            ("repo2nb", ["reverse", "$FLAGS"]),
            ("repo2nb", ["reverse", "literal"]),
            ("repo2nb", ["reverse", "$FLAGS"]),
        ],
    )

    add(repo, "printf", ["café"])

    for flag in ("-k", "-i", "-h"):
        required = definition("php-artisan-script.v1", PhpArtisanScriptMatcher(("migrate:fresh",), frozenset({flag})))
        for value in ("-\u212a", "-\u0130h", "-ih"):
            add(required, "php", ["artisan", "migrate:fresh", value])
    for option in ("-\u212ac", "-\u0130c"):
        add(php, "php", [option, "config.ini", "artisan", "migrate:fresh"])
    for marker in ("i", "k"):
        custom = definition(
            "repo2nb-expansion.v1",
            Repo2nbUnresolvedExpansionMatcher(launchers=(("k",),), expansion_markers=frozenset({marker})),
        )
        for argument in ("\u212a", "\u0130", "opaque数据"):
            add(custom, "\u212a", ["reverse", argument])

    unicode_commands = [
        "printf café",
        "python -m json.tool café",
        "python script.py café",
        "php script.php café",
        'php -r "echo café;"',
        "repo2nb --help café",
        "repo2nb reverse café",
        "repo2nb reverse café$FLAGS",
        "repo2nb sync café",
        "curl -I http://localhost/café",
        "curl -XGET http://é:9200/items",
        "curl -XDELETE http://localhost:9200/café",
        "db --help café",
        "git diff -- café",
        "git status -- café",
        'psql -c "SELECT café"',
        'psql -c "DELETE FROM café"',
        "oc get pod café",
        "oc delete pod café",
        "dotnet add café.csproj package Example",
        "terraform -var café apply",
        "find . -name café",
        "ansible-playbook café.yml --help",
    ]
    unicode_parser_cases = [
        [index, text, [item.segment_index for item in matcher.match(parse_shell_command(text))]]
        for text in unicode_commands
        for index, matcher in (php, repo)
    ]

    literal = definition("reviewed-literal.v1", ReviewedLiteralCommandMatcher("tool", ("--help",)))
    for raw, args in [
        ("tool --help", ["--help"]),
        (" tool --help", ["--help"]),
        ("tool --help ", ["--help"]),
        ("tool  --help", ["--help"]),
        ("tool '--help'", ["--help"]),
        ("tool --help extra", ["--help", "extra"]),
        ("tool --HELP", ["--HELP"]),
    ]:
        add(literal, "tool", args, raw=raw)
    return (
        json.dumps(
            {
                "semantic_profile": "cpython-3.12-ucd-15.0.0",
                "source": "c4bd916fb0d0f375a4e2de0d1e498a0a533f63c8",
                "definitions": definitions,
                "cases": cases,
                "unicode_parser_cases": unicode_parser_cases,
            },
            indent=2,
            ensure_ascii=False,
        )
        + "\n"
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if sys.version_info[:2] != (3, 12) or unicodedata.unidata_version != "15.0.0":
        raise SystemExit("These fixtures require CPython 3.12/UCD 15.0.0")
    ascii_mapping = {
        chr(value): chr(value).lower()
        for value in range(128, sys.maxunicode + 1)
        if any(character.isascii() for character in chr(value).lower())
    }
    if ascii_mapping != {"\u0130": "i\u0307", "\u212a": "k"}:
        raise SystemExit("CPython lowercase-to-ASCII profile changed")
    for value in range(128, sys.maxunicode + 1):
        character = chr(value)
        lowered = character.lower()
        if character in ascii_mapping:
            continue
        if len(lowered) != 1 or character.isalnum() != lowered.isalnum() or character.isalpha() != lowered.isalpha():
            raise SystemExit("Opaque lowercase character boundaries changed")
    path = Path(__file__).with_name("remaining-matchers.v1.json")
    content = generate()
    if args.check:
        if path.read_text() != content:
            raise SystemExit("remaining matcher fixtures are stale")
    else:
        path.write_text(content)
    # These data are copied into the Rust curl parser, not inferred at runtime.
    rust_source = path.parent.parent / "src" / "command_curl_operations.rs"
    source = rust_source.read_text()
    expected = "const SHORT_VALUE_OPTIONS: &str = " + json.dumps("".join(sorted(CURL_SHORT_OPTIONS_WITH_VALUES))) + ";"
    table = source.split("const LONG_VALUE_OPTIONS: &[&str] = &[", 1)[1].split("];", 1)[0]
    long_options = re.findall(r'"([^"]+)"', table)
    if expected not in source or long_options != sorted(CURL_LONG_OPTIONS_WITH_VALUES):
        raise SystemExit("Rust curl option table differs from the Python contract")
    print(f"{len(json.loads(content)['cases'])} reference cases verified")


if __name__ == "__main__":
    main()
