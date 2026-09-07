"""Offline parsers reject ambiguous input and never turn metadata into authority."""

from __future__ import annotations

import copy
import json
import os
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.extension_builder.discover import discover
from codex_plugin_scanner.guard.extension_builder.errors import BuilderError
from codex_plugin_scanner.guard.extension_builder.io import MAX_INPUT_BYTES, canonical_json, parse_json, read_bytes
from codex_plugin_scanner.guard.extension_builder.models import load_discovery, validate_metadata
from codex_plugin_scanner.guard.extension_builder.source_cli import cli_surface, help_surface
from codex_plugin_scanner.guard.extension_builder.source_click import click_surface
from codex_plugin_scanner.guard.extension_builder.source_mcp import mcp_surface
from codex_plugin_scanner.guard.extension_builder.source_oclif import oclif_surface
from tests.extension_builder_support import cli_document, make_discovery, mcp_document, metadata


@pytest.mark.parametrize(
    "content",
    [
        b'{"x":1,"x":2}',
        b'{"x":NaN}',
        b'{"x":Infinity}',
        b'{"x":-Infinity}',
        b'{"x":1e999}',
        b"[] trailing",
        b"\xff",
        b"{",
        b"",
    ],
)
def test_rejects_invalid_json_without_echoing_input(content: bytes) -> None:
    with pytest.raises(BuilderError) as caught:
        parse_json(content)
    assert len(str(caught.value)) < 160


def test_json_limits_are_complete_or_fail() -> None:
    with pytest.raises(BuilderError, match="byte limit"):
        parse_json(b" " * (MAX_INPUT_BYTES + 1))
    with pytest.raises(BuilderError, match="structure budget"):
        parse_json(("[" * 34 + "0" + "]" * 34).encode())
    with pytest.raises(BuilderError, match="structure budget"):
        parse_json(json.dumps([0] * 50_001).encode())


def test_source_read_requires_a_regular_bounded_file(tmp_path: Path) -> None:
    with pytest.raises(BuilderError):
        read_bytes(tmp_path)
    large = tmp_path / "large.json"
    large.write_bytes(b"x" * (MAX_INPUT_BYTES + 1))
    with pytest.raises(BuilderError, match="regular file"):
        read_bytes(large)
    missing = tmp_path / "missing"
    with pytest.raises(BuilderError):
        read_bytes(missing)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX named-pipe behavior")
def test_fifo_is_rejected_without_waiting_for_a_writer(tmp_path: Path) -> None:
    fifo = tmp_path / "export"
    os.mkfifo(fifo)
    with pytest.raises(BuilderError, match="regular file"):
        read_bytes(fifo)


@pytest.mark.parametrize("ancestor", [False, True])
def test_source_symlinks_are_rejected(tmp_path: Path, ancestor: bool) -> None:
    real = tmp_path / "real"
    real.mkdir()
    (real / "source.json").write_text("{}", encoding="utf-8")
    linked = tmp_path / "linked"
    try:
        linked.symlink_to(real if ancestor else real / "source.json", target_is_directory=ancestor)
    except OSError:
        pytest.skip("Symlink creation is unavailable for this account")
    with pytest.raises(BuilderError, match="Symlink"):
        read_bytes(linked / "source.json" if ancestor else linked)


@pytest.mark.parametrize(
    "slug", ["../escape", "A", "a_b", "a.b", "-a", "a-", "a--b", "con", "nul", "com1", "a" * 41, "mcp-foo"]
)
def test_invalid_cli_slugs_are_rejected(slug: str) -> None:
    with pytest.raises(BuilderError):
        validate_metadata(replace(metadata(), slug=slug))


@pytest.mark.parametrize("executable", ["/bin/demo", "../demo", "demo status", "demo;echo", "$(id)", "", "a" * 65])
def test_executable_is_a_literal_basename(executable: str) -> None:
    with pytest.raises(BuilderError):
        validate_metadata(replace(metadata(), executable=executable))


@pytest.mark.parametrize(
    "homepage",
    [
        "http://example.test",
        "file:///tmp/source",
        "https://user:pass@example.test",
        "https://example.test?token=secret",
        "https://example.test:444",
        "https://example.test/\n",
    ],
)
def test_references_cannot_contain_credentials_or_query_secrets(homepage: str) -> None:
    with pytest.raises(BuilderError):
        validate_metadata(replace(metadata(), homepage=homepage))


@pytest.mark.parametrize("value", ["bad\nname", "bad\x1bname", "bad\u202ename", "bad\ud800name"])
def test_publishable_metadata_rejects_controls_and_surrogates(value: str) -> None:
    with pytest.raises(BuilderError):
        validate_metadata(replace(metadata(), name=value))


@pytest.mark.parametrize(
    "package", ["https://example.test/a", "@example/demo@1.0.0", "demo --yes", "../demo", "", "demo;"]
)
def test_mcp_package_identity_is_not_a_launch_command(package: str) -> None:
    with pytest.raises(BuilderError):
        validate_metadata(replace(metadata("mcp"), package=package))


def test_cli_surface_preserves_nested_paths_and_option_arity(tmp_path: Path) -> None:
    discovery = make_discovery(tmp_path)
    operation = next(row for row in discovery.operations if row.path == ("items", "list"))
    assert operation.flags == ("--help", "--json", "--version")
    assert operation.options_with_values == ("--profile",)
    assert operation.hints == ("read-name",)
    assert load_discovery(discovery.to_dict()) == discovery


@pytest.mark.parametrize(
    "document",
    [
        {"schemaVersion": "unknown", "commands": []},
        {"schemaVersion": "guard.cli-surface.v1", "commands": [], "execute": True},
        {"schemaVersion": "guard.cli-surface.v1", "commands": [{"path": ["x"], "flags": ["--x", "--x"]}]},
        {
            "schemaVersion": "guard.cli-surface.v1",
            "commands": [{"path": ["x"], "flags": ["--x"], "optionsWithValues": ["--x"]}],
        },
        {"schemaVersion": "guard.cli-surface.v1", "commands": [{"path": ["x"] * 9}]},
        {"schemaVersion": "guard.cli-surface.v1", "commands": [{"path": ["x"], "description": {}}]},
    ],
)
def test_cli_surface_rejects_ambiguous_or_unknown_grammar(document: object) -> None:
    with pytest.raises(BuilderError):
        cli_surface(document)


def test_discovery_rejects_runtime_colliding_paths(tmp_path: Path) -> None:
    source = tmp_path / "duplicates.json"
    source.write_text(
        canonical_json(
            {"schemaVersion": "guard.cli-surface.v1", "commands": [{"path": ["Status"]}, {"path": ["status"]}]}
        ),
        encoding="utf-8",
    )
    with pytest.raises(BuilderError, match="colliding"):
        discover("cli", source, metadata())


def test_dictionary_order_does_not_change_normalized_operation_identity() -> None:
    source = cli_document()
    reordered = dict(reversed(list(source.items())))
    assert cli_surface(source) == cli_surface(reordered)


@pytest.mark.parametrize("heading", ["Commands:", "Available Commands:", "Subcommands:"])
def test_help_sections_are_consumed_without_running_the_target(heading: str) -> None:
    data = (
        f"Demo\n\n{heading}\n  list    List items\n  delete  Delete items\n\nOptions:\n"
        "  --profile VALUE  Select profile\n  -h, --help       Show help\n"
    ).encode()
    operations, limitations = help_surface(data)
    assert [row.path for row in operations] == [(), ("list",), ("delete",)]
    assert operations[0].options_with_values == ("--profile",)
    assert operations[0].flags == ("--help", "-h")
    assert limitations == ("help-inventory-partial",)


def test_help_ansi_and_unrecognized_grammar_are_explicit() -> None:
    operations, limitations = help_surface(b"\x1b[32mUsage: demo [options]\x1b[0m\n")
    assert len(operations) == 1
    assert "unrecognized-help-grammar" in limitations
    with pytest.raises(BuilderError, match="control"):
        help_surface(b"\x1b]0;malicious title\x07")
    with pytest.raises(BuilderError, match="operation limit"):
        help_surface(("Commands:\n" + "".join(f"  cmd{i}  Description\n" for i in range(256))).encode())


def test_click_export_handles_nested_inherited_and_boolean_options() -> None:
    option = {
        "param_type_name": "option",
        "opts": ["--profile", "-p"],
        "secondary_opts": [],
        "nargs": 1,
        "is_flag": False,
    }
    child = {
        "params": [
            {"param_type_name": "option", "opts": ["--color"], "secondary_opts": ["--no-color"], "is_flag": True}
        ]
    }
    operations, _ = click_surface({"command": {"params": [option], "commands": {"show": child}}})
    assert operations[1].path == ("show",)
    assert operations[1].flags == ("--color", "--no-color")
    assert operations[1].options_with_values == ("--profile", "-p")


def test_actual_click_context_information_export() -> None:
    import click

    @click.group()
    def example() -> None:
        pass

    @example.command()
    @click.option("--force", is_flag=True)
    @click.option("--name", "-n", multiple=True)
    @click.argument("items", nargs=-1)
    def remove(force: bool, name: tuple[str, ...], items: tuple[str, ...]) -> None:
        raise AssertionError("Discovery must not invoke a target command")

    operations, _ = click_surface(click.Context(example).to_info_dict())
    assert operations[1].path == ("remove",)
    assert operations[1].flags == ("--force", "--help")
    assert operations[1].options_with_values == ("--name", "-n")


@pytest.mark.parametrize(
    "document", [{}, {"params": [None]}, {"params": [{"param_type_name": "option", "opts": ["--pair"], "nargs": 2}]}]
)
def test_click_rejects_malformed_or_multivalue_grammar(document: object) -> None:
    with pytest.raises(BuilderError):
        click_surface(document)


@pytest.mark.parametrize("separator, expected", [("colon", ("items:list",)), ("space", ("items", "list"))])
def test_oclif_preserves_topic_separator_and_aliases(separator: str, expected: tuple[str, ...]) -> None:
    document = {
        "commands": {
            "items:list": {
                "aliases": ["ls"],
                "flags": {
                    "json": {"type": "boolean", "char": "j"},
                    "color": {"type": "boolean", "allowNo": True},
                    "profile": {"type": "option", "charAliases": ["p"]},
                },
            }
        }
    }
    operations, _ = oclif_surface(document, topic_separator=separator)
    assert operations[0].path == expected
    assert operations[1].path == ("ls",)
    assert "--no-color" in operations[0].flags
    assert operations[0].options_with_values == ("--profile", "-p")


@pytest.mark.parametrize(
    "flags",
    [
        {"x": {"type": "unknown"}},
        {"x": {"type": "option", "multiple": True}},
        {"x": {"type": "option", "allowNo": True}},
    ],
)
def test_oclif_rejects_unsupported_flag_arity(flags: object) -> None:
    with pytest.raises(BuilderError):
        oclif_surface({"commands": {"demo": {"flags": flags}}})


def test_oclif_rejects_nonstring_alias_without_a_type_error() -> None:
    with pytest.raises(BuilderError):
        oclif_surface({"commands": {"demo": {"flags": {}, "aliases": [[]]}}})


def test_mcp_annotations_remain_only_untrusted_hints(tmp_path: Path) -> None:
    discovery = make_discovery(tmp_path, "mcp")
    read = next(row for row in discovery.operations if row.name == "read_item")
    assert "read-only-hint" in read.hints
    assert '"annotations":' not in canonical_json(discovery.to_dict())


def test_mcp_complete_jsonrpc_and_cursor_chain() -> None:
    first = {"jsonrpc": "2.0", "id": 1, "result": {"tools": [mcp_document()["tools"][0]], "nextCursor": "page2"}}
    last = {"jsonrpc": "2.0", "id": 2, "result": {"resultType": "complete", "tools": [mcp_document()["tools"][1]]}}
    operations, _ = mcp_surface(
        {"pages": [{"requestCursor": None, "response": first}, {"requestCursor": "page2", "response": last}]}
    )
    assert len(operations) == 2
    assert len(mcp_surface(last)[0]) == 1


@pytest.mark.parametrize(
    "document",
    [
        {"tools": [], "nextCursor": "missing"},
        {"error": {"message": "private diagnostic"}},
        {"resultType": "input_required", "tools": []},
        {"jsonrpc": "1.0", "id": 1, "result": {"tools": []}},
        {"pages": []},
        {"pages": [{"requestCursor": "not-first", "response": {"tools": []}}]},
        {"pages": [{"requestCursor": None, "response": {"tools": [], "nextCursor": "again"}}]},
        {
            "pages": [
                {"requestCursor": None, "response": {"tools": []}},
                {"requestCursor": None, "response": {"tools": []}},
            ]
        },
        {
            "pages": [
                {"requestCursor": None, "response": {"tools": [], "nextCursor": "a"}},
                {"requestCursor": "a", "response": {"tools": [], "nextCursor": "a"}},
            ]
        },
    ],
)
def test_mcp_rejects_incomplete_or_ambiguous_protocol_exports(document: object) -> None:
    with pytest.raises(BuilderError):
        mcp_surface(document)


@pytest.mark.parametrize(
    "schema",
    [
        {"type": "string"},
        {"type": "object", "$ref": "https://example.test/private"},
        {"type": "object", "$schema": "https://example.test/schema"},
        {"type": "object", "properties": []},
        {"type": "object", "properties": {"x": {"type": "impossible"}}},
    ],
)
def test_mcp_schema_validation_is_local_and_strict(schema: object) -> None:
    with pytest.raises(BuilderError):
        mcp_surface({"tools": [{"name": "read_item", "inputSchema": schema}]})


@pytest.mark.parametrize("name", ["other", "OTHER", "../read", "tool name", "é", "x" * 129])
def test_mcp_tool_names_reject_fallback_or_unsafe_identity(name: str) -> None:
    with pytest.raises(BuilderError):
        mcp_surface({"tools": [{"name": name, "inputSchema": {"type": "object"}}]})


def test_mcp_runtime_normalization_collisions_fail_before_rendering(tmp_path: Path) -> None:
    source = tmp_path / "duplicate-tools.json"
    source.write_text(
        canonical_json(
            {"tools": [{"name": name, "inputSchema": {"type": "object"}} for name in ("read_item", "read-item")]}
        ),
        encoding="utf-8",
    )
    with pytest.raises(BuilderError, match="colliding"):
        discover("mcp", source, metadata("mcp"))


def test_snapshot_and_review_provenance_changes_are_detected(tmp_path: Path) -> None:
    discovery = make_discovery(tmp_path)
    modified = copy.deepcopy(discovery.to_dict())
    modified["sourceSha256"] = "f" * 64
    with pytest.raises(BuilderError, match="binding digest"):
        load_discovery(modified)
    modified = copy.deepcopy(discovery.to_dict())
    modified["schemaVersion"] = "guard.extension-discovery.v2"
    with pytest.raises(BuilderError, match="versioned"):
        load_discovery(modified)


def test_snapshot_replay_rejects_identity_overrides(tmp_path: Path) -> None:
    source = tmp_path / "snapshot.json"
    discovery = make_discovery(tmp_path)
    source.write_text(canonical_json(discovery.to_dict()), encoding="utf-8")
    assert discover("snapshot", source) == discovery
    with pytest.raises(BuilderError, match="overrides"):
        discover("snapshot", source, metadata())
    with pytest.raises(BuilderError, match="overrides"):
        discover("snapshot", source, topic_separator="space")
