"""Regenerate Rust specialized matcher vectors using the Python implementation.

Run from the repository root with its locked Python 3.12 environment:
    uv run --frozen python rust/crates/guard-command/testdata/generate_specialized_fixtures.py --check

Inputs are canonical segments, so parser differences cannot hide a matcher
regression. Values include deliberately awkward existing Python semantics.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import random
import sys
from pathlib import Path

from codex_plugin_scanner.guard.runtime import command_operand_matchers as operand
from codex_plugin_scanner.guard.runtime import command_structured_matchers as structured
from codex_plugin_scanner.guard.runtime.command_model import CanonicalCommand, CommandSegment

DESTINATIONS = [
    "local",
    "s3://bucket",
    "s3://",
    "s3://界",
    "S3://bucket",
    "@host",
    "界:先",
    "host:/path",
    "host:",
    "user@host:path",
    "first@next@host:path",
    "[::1]:/srv",
    "[]:path",
    "[ ]:path",
    "[::1]:",
    "C:\\backup",
    "1:path",
    "a:path",
    "é:path",
    "\u0345:path",
    "a\x1cname:path",
    "name with space:path",
    "a/b:path",
    "alias:",
    "alias:subpath",
    "alias",
    "alias/",
    "alias\\",
    "alias\\/",
    "alias/\\",
    "界界",
    "界",
    ".",
    "..",
    "-remote",
    "a@b",
    "http://host/path",
    "",
    "-",
    "--",
]


def command(segments: list[list[object]]) -> CanonicalCommand:
    values = tuple(
        CommandSegment(
            text="",
            tokens=(),
            executable=executable,
            arguments=tuple(arguments),
            environment_names=tuple(names),
            wrapper_chain=(),
            path_overridden=False,
            execution_context="top",
            pipeline_index=index,
            start=0,
            end=0,
        )
        for index, (executable, arguments, names) in enumerate(segments)
    )
    return CanonicalCommand(
        raw_text="",
        normalized_text="",
        dialect="argv",
        transport="argv",
        extraction_provenance="specialized-matcher-oracle",
        wrapper_chain=(),
        segments=values,
        redirects=(),
        embedded_commands=(),
        confidence="exact",
    )


def generate() -> str:
    definitions: list[dict[str, object]] = []
    cases: list[dict[str, object]] = []

    def add(op: str, matcher_type: type, config: dict[str, object], arguments: list[list[str]]) -> None:
        kwargs = dict(config)
        for field in dataclasses.fields(matcher_type):
            if field.name not in kwargs:
                continue
            if str(field.type).startswith("frozenset"):
                kwargs[field.name] = frozenset(kwargs[field.name])
            elif field.name == "subcommands":
                kwargs[field.name] = tuple(kwargs[field.name])
            elif field.name == "required_key_values":
                kwargs[field.name] = tuple(tuple(pair) for pair in kwargs[field.name])
        matcher = matcher_type(**kwargs)
        matcher_index = len(definitions)
        definitions.append({"op": op, "config": config})
        # Multiple matches in order, absent executable, alternate basename
        # separators, preserved raw first arguments, and unrelated segments.
        for index, args in enumerate(arguments):
            segments = [["tool", args, []]]
            if index % 11 == 0:
                segments = [[None, args, []], ["other", args, []], ["C:\\bin\\TOOL", args, []], ["/bin/tool", args, []]]
            expected = [item.segment_index for item in matcher.match(command(segments))]
            cases.append({"m": matcher_index, "s": segments, "matches": expected})

    rng = random.Random(320109)
    arguments = [
        [],
        ["one"],
        ["one", "two"],
        ["--", "one", "two"],
        ["-", "one"],
        ["-o", "ignored", "one", "two"],
        ["-oignored", "one", "two"],
        ["-vo", "ignored", "one", "two"],
        ["-v!o", "ignored", "one"],
        ["--target", "ignored", "one", "two"],
        ["--TARGET=ignored", "one", "two"],
        ["--SAFE", "one", "two"],
        ["--safe", "one", "two"],
        ["one", "--safe", "two"],
        ["--", "--safe", "two"],
        ["-n", "one", "two"],
        ["-F"],
        ["-vo"],
        ["-v=o", "one"],
        ["-\u0345o", "one", "two"],
        ["-éF", "ignored", "one", "two"],
        ["-²F", "ignored", "one", "two"],
        ["-v\x1co", "one", "two"],
        ["-\U00011f02F", "ignored", "one", "two"],
    ]
    tokens = [
        "a",
        "b",
        "--",
        "-",
        "--safe",
        "--SAFE",
        "-n",
        "-o",
        "-vo",
        "-ov",
        "-v!o",
        "-F",
        "--target",
        "--TARGET=value",
        "--unknown",
        "s3://bucket",
    ]
    arguments.extend([rng.choices(tokens, k=rng.randrange(0, 9)) for _ in range(75)])
    add(
        "leading-operand-count.v1",
        structured.LeadingOperandCountMatcher,
        {
            "executables": [" TOOL ", ""],
            "minimum_operands": 2,
            "options_with_values": [" --TARGET ", "-o", "-F"],
            "forbidden_flags": [" --SAFE ", "-n"],
        },
        arguments,
    )

    prefix_args = [
        ["remote", "push", "src", "s3://bucket"],
        ["REMOTE", "PUSH", "src", "s3://bucket"],
        ["--root", "elsewhere", "remote", "push", "src", "s3://bucket"],
        ["-C/tmp", "remote", "push", "src", "s3://bucket"],
        ["remote", "push", "s3://bucket", "local"],
        ["remote", "push", "--target", "src", "s3://bucket"],
        ["remote", "push", "--TARGET", "src", "s3://bucket"],
        ["remote", "push", "-t", "src", "s3://bucket"],
        ["remote", "push", "--config", "s3://bucket", "src", "local"],
        ["remote", "push", "src", "--", "-x", "s3://bucket"],
        ["remote", "push", "src", "-f", "s3://bucket"],
        ["remote", "push", "src", "-vf", "s3://bucket"],
        ["--", "remote", "push", "src", "界:先"],
        ["remote", "push", "src", "界:"],
        ["remote"],
        [],
    ]
    prefix_args.extend([["remote", "push", "src", value] for value in DESTINATIONS])
    prefix_args.extend([rng.choices([*tokens, "remote", "push", "@host"], k=rng.randrange(0, 10)) for _ in range(60)])
    add(
        "subcommand-operand-prefix.v1",
        structured.SubcommandOperandPrefixMatcher,
        {
            "executables": ["tool"],
            "subcommands": [" REMOTE ", "", " Push "],
            "operand_prefixes": ["s3://", "@", "界:", ""],
            "leading_options_with_values": ["--root", "-C"],
            "options_with_values": ["--config", "-f", "--target", "-t"],
            "leading_operands_to_skip": 1,
            "options_supplying_leading_operands": ["--target", "-t"],
        },
        prefix_args,
    )
    add(
        "subcommand-operand-prefix.v1",
        structured.SubcommandOperandPrefixMatcher,
        {
            "executables": ["tool"],
            "subcommands": ["push"],
            "operand_prefixes": ["@"],
            "options_with_values": [" --config ", "--CONFIG"],
            "leading_operands_to_skip": 1000,
        },
        [["push", "source", "@host"], ["push", "--CONFIG", "source", "@host"]],
    )

    settings = [
        "ProxyCommand=curl host",
        "ProxyCommand=NONE",
        "ProxyCommand=off",
        "ProxyCommand=",
        "ProxyCommand none",
        "ProxyCommand\x1cRUN",
        " ProxyCommand = run ",
        " proxycommand =none",
        "LocalCommand=echo ok",
        "PermitLocalCommand=yes",
        "PermitLocalCommand=no",
        "",
        "other=run",
    ]
    option_args = [["-o", value] for value in settings]
    option_args += [["-o" + value] for value in settings]
    option_args += [["--option=" + value] for value in settings]
    option_args += [
        ["-o", "ProxyCommand=none", "-o", "ProxyCommand=run"],
        ["-o", "ProxyCommand=run", "-o", "ProxyCommand=none"],
        ["--", "-o", "ProxyCommand=run"],
        ["--safe", "-o", "ProxyCommand=run"],
        ["--SAFE", "-o", "ProxyCommand=run"],
        ["-no", "ProxyCommand=run"],
        ["-voProxyCommand=run"],
        ["-vo", "ProxyCommand=run"],
        ["-v!oProxyCommand=run"],
        ["-\u0345oProxyCommand=run"],
        ["-²oProxyCommand=run"],
        ["-éopayload", "-o", "ProxyCommand=run"],
        ["-Jopayload", "-o", "ProxyCommand=run"],
        ["-O", "ProxyCommand=run"],
        ["--optionProxyCommand=run"],
        ["--option", "ProxyCommand=run"],
        ["-o", "-oProxyCommand=run"],
        ["-o"],
        ["--option"],
        ["-o", "permitlocalcommand=yes", "-o", "localcommand=run"],
        ["-o", "permitlocalcommand=no", "-o", "permitlocalcommand=yes", "-o", "localcommand=run"],
        ["-o", "permitlocalcommand=yes", "-o", "permitlocalcommand=no", "-o", "localcommand=run"],
    ]
    option_args.extend(
        [
            rng.choices(["-o", "--option", "--safe", "--", "-vo", "-J", *settings], k=rng.randrange(0, 12))
            for _ in range(75)
        ]
    )
    option_config = {
        "executables": ["tool"],
        "option_names": [" -o ", "--option"],
        "value_keys": [" ProxyCommand ", "LocalCommand"],
        "ignored_values": [" NONE ", " off "],
        "forbidden_flags": [" --SAFE ", "-n"],
        "cluster_options_with_values": [" -p ", "-J", "-i"],
    }
    add("option-value-key.v1", structured.OptionValueKeyMatcher, option_config, option_args)
    add(
        "option-value-key.v1",
        structured.OptionValueKeyMatcher,
        dict(option_config, required_key_values=[[" PermitLocalCommand ", " YES "], ["", "empty"]]),
        option_args,
    )
    # Prefix precedence must be based on longest option, preserving the legacy
    # behavior where a longer long-option prefix can consume a short match.
    add(
        "option-value-key.v1",
        structured.OptionValueKeyMatcher,
        {"executables": ["tool"], "option_names": ["-o", "-option", "--option"], "value_keys": ["proxycommand"]},
        [
            ["-optionProxyCommand=run"],
            ["--optionProxyCommand=run"],
            ["-oProxyCommand=run"],
            ["-option", "ProxyCommand=run"],
            ["--option", "ProxyCommand=run"],
        ],
    )

    add(
        "environment-name.v1",
        structured.EnvironmentNameMatcher,
        {"executables": ["tool"], "environment_names": [" LD_PRELOAD ", "bash_env", ""]},
        [[]],
    )
    env_index = len(definitions) - 1
    env_matcher = structured.EnvironmentNameMatcher(frozenset({"tool"}), frozenset({"LD_PRELOAD", "BASH_ENV"}))
    for names in [
        [],
        ["ld_preload"],
        ["BASH_ENV"],
        [" LD_PRELOAD "],
        ["else"],
        ["BASH_ENV", "bash_env"],
        ["else", "LD_PRELOAD"],
        ["PATH"],
    ]:
        segments = [["tool", ["--", "operand"], names], ["other", [], names], ["TOOL", [], names]]
        cases.append(
            {
                "m": env_index,
                "s": segments,
                "matches": [item.segment_index for item in env_matcher.match(command(segments))],
            }
        )

    common = {
        "executables": ["tool"],
        "options_with_values": ["--config", "-F", "-o"],
        "forbidden_flags": ["--safe", "-n"],
        "excluded_first_arguments": ["creds"],
    }
    copy_args = [["source", value] for value in DESTINATIONS]
    copy_args += [[value, "local"] for value in DESTINATIONS]
    copy_args += [
        [],
        ["s3://bucket"],
        ["--use-sudo"],
        ["--safe", "source", "s3://bucket"],
        ["--SAFE", "source", "s3://bucket"],
        ["source", "-n", "s3://bucket"],
        ["--", "-n", "s3://bucket"],
        ["--config", "source", "s3://bucket"],
        ["--CONFIG", "source", "s3://bucket"],
        ["--config=value", "source", "s3://bucket"],
        ["-vF", "ignored", "source", "s3://bucket"],
        ["-Fignored", "source", "s3://bucket"],
        ["-v!F", "source", "s3://bucket"],
        ["source", "--config", "s3://bucket"],
        ["creds", "source", "s3://bucket"],
        ["Creds", "source", "s3://bucket"],
        ["-v", "creds", "s3://bucket"],
        ["creds", "--use-sudo", "source", "remote:out"],
        ["--use-sudo", "source", "remote:out"],
        ["--USE-SUDO", "source", "remote:out"],
        ["--use-sudo", "--", "source", "remote:out"],
        ["--", "--use-sudo", "source", "remote:out"],
        ["--config", "--use-sudo", "source", "remote:out"],
    ]
    copy_args.extend(
        [rng.choices(tokens + DESTINATIONS + ["--use-sudo", "creds"], k=rng.randrange(0, 10)) for _ in range(75)]
    )
    add(
        "trailing-operand-prefix.v1",
        operand.TrailingOperandPrefixMatcher,
        dict(common, operand_prefixes=["s3://", "@", "界:", ""]),
        copy_args,
    )
    add("trailing-operand-host-target.v1", operand.TrailingOperandHostTargetMatcher, common, copy_args)
    add("trailing-operand-remote-alias.v1", operand.TrailingOperandRemoteAliasMatcher, common, copy_args)
    add(
        "trailing-operand-remote-alias.v1",
        operand.TrailingOperandRemoteAliasMatcher,
        dict(common, allow_bare_names=True),
        copy_args,
    )
    add(
        "trailing-operand-remote-alias.v1",
        operand.TrailingOperandRemoteAliasMatcher,
        dict(common, allow_bare_names=True, bare_names_only=True),
        copy_args,
    )
    add(
        "operand-gated-flags.v1",
        operand.OperandGatedFlagMatcher,
        dict(common, required_flags=[" --USE-SUDO "]),
        copy_args,
    )

    # One definition/case per line keeps a regenerated vector diff reviewable.
    def encode(item: object) -> str:
        return json.dumps(item, ensure_ascii=True, sort_keys=True, separators=(",", ":"))

    return (
        '{\n  "schema_version":1,\n  "python_runtime":"3.12",\n  "random_seed":320109,\n  "matchers":[\n'
        + ",\n".join("    " + encode(item) for item in definitions)
        + '\n  ],\n  "cases":[\n'
        + ",\n".join("    " + encode(item) for item in cases)
        + "\n  ]\n}\n"
    )


def main() -> None:
    if sys.version_info[:2] != (3, 12):
        raise SystemExit("the specialized matcher oracle requires the supported Python 3.12 runtime")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    target = Path(__file__).with_name("specialized-matchers.v1.json")
    result = generate()
    if args.check:
        if target.read_text(encoding="utf-8") != result:
            raise SystemExit("specialized matcher vectors differ from the Python implementation")
    else:
        target.write_text(result, encoding="utf-8")
    print(f"verified {len(json.loads(result)['cases'])} Python specialized matcher vectors")


if __name__ == "__main__":
    main()
