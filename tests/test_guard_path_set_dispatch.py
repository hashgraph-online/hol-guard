"""Executable indexing must preserve every path-set match and unknown matcher fallback."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.runtime.command_extension_observations import observe_command_extensions
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from codex_plugin_scanner.guard.runtime.command_path_set_matcher import ExecutablePathSetMatcher
from codex_plugin_scanner.guard.runtime.command_rules import AnyMatcher, matcher_index_hints


def test_path_set_dispatch_is_executable_bound_without_keyword_false_candidates() -> None:
    matcher = ExecutablePathSetMatcher(executables=frozenset({"gcloud"}), paths=frozenset({("projects", "delete")}))
    hints = matcher_index_hints(matcher)
    assert hints.complete and hints.executables == frozenset({"gcloud"}) and hints.keywords == frozenset()
    combined = matcher_index_hints(AnyMatcher((matcher,)))
    assert combined == hints


@pytest.mark.parametrize(
    "text",
    [
        "echo harmless",
        "echo projects delete",
        "gcloud projects delete example",
        "/usr/bin/gcloud projects delete example",
        "GCLOUD projects delete example",
        "env gcloud projects delete example",
        "command gcloud projects delete example",
        "printf ok && gcloud projects delete example",
        "gcloud projects delete example | cat",
        "aws s3 rm s3://example/file",
        "az group delete --name example",
        "git status",
        "kubectl delete namespace example",
        "terraform destroy",
        "gh repo delete example/repo",
        "rm -rf ./build",
        "docker system prune --all",
        "gcloud --unknown x projects delete example",
    ],
)
def test_indexed_observations_equal_unfiltered_observations(text: str) -> None:
    registry = BUILT_IN_COMMAND_EXTENSION_REGISTRY
    command = parse_shell_command(text)
    every_rule = tuple(rule.rule_id for extension in registry.extensions for rule in extension.rules)
    assert registry.observations(command) == observe_command_extensions(command, registry.extensions, every_rule)


def test_unknown_child_keeps_composite_matcher_in_full_scan_fallback() -> None:
    class UnknownMatcher:
        def match(self, _command):
            return ()

    known = ExecutablePathSetMatcher(executables=frozenset({"gcloud"}), paths=frozenset({("projects", "delete")}))
    assert not matcher_index_hints(AnyMatcher((known, UnknownMatcher()))).complete
