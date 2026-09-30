"""Focused regressions for specialized structured command variants."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import main
from tests.native_command_test_support import (
    extract_sensitive_tool_action_request_native_test as extract_sensitive_tool_action_request,
)
from tests.native_command_test_support import inspect_command_native_test as inspect_command
from tests.native_command_test_support import real_native_review_fixture


def _assert_native_unavailable(command: str) -> None:
    payload = real_native_review_fixture(command).payload
    extensions = payload["command_extensions"]
    assert extensions["evaluation_error"] == "native_command_evaluation_failed"
    assert extensions["observations"] == []
    assert extensions["permission_observations"] == []
    assert extensions["binding"]["observation_count"] == 0
    assert extensions["binding"]["uncertainty_count"] == 1
    assert payload["minimum_action"] == "block"


@pytest.mark.parametrize(
    ("command", "rule_id", "action_class"),
    [
        ("git push origin +main", "command.git.force-push", "git destructive command"),
        (
            "git push origin +refs/heads/main:refs/heads/main",
            "command.git.force-push",
            "git destructive command",
        ),
        ("git push --repo origin +main", "command.git.force-push", "git destructive command"),
        (
            "curl -X DELETE localhost:9200/customer-index --next -X GET https://api.example.test/items",
            "command.search.elasticsearch.delete",
            "Elasticsearch destructive command",
        ),
        (
            "curl -sXDELETE localhost:9200/customer-index",
            "command.search.elasticsearch.delete",
            "Elasticsearch destructive command",
        ),
        (
            "ssh -voProxyCommand='sh -c id' host.example",
            "command.remote.ssh.configured-execution",
            "SSH configured execution command",
        ),
        (
            "ssh -4oRemoteCommand='id' host.example",
            "command.remote.ssh.configured-execution",
            "SSH configured execution command",
        ),
    ],
)
def test_specialized_variants_feed_runtime_classification(
    command: str,
    rule_id: str,
    action_class: str,
    tmp_path: Path,
) -> None:
    payload = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)
    match = extract_sensitive_tool_action_request(
        "Shell",
        {"command": command},
        cwd=tmp_path,
        home_dir=tmp_path,
    )

    assert payload["status"] == "review"
    assert payload["controlling_rule_id"] == rule_id
    assert match is not None
    assert match.action_class == action_class


@pytest.mark.parametrize(
    "body",
    [
        "'$(rm -rf ./build)'",
        '"$(rm -rf ./build)"',
        "prefix 'quoted text' $(rm -rf ./build)",
        "'`rm -rf ./build`'",
    ],
)
def test_unquoted_data_heredoc_expands_substitutions_despite_body_quotes(body: str, tmp_path: Path) -> None:
    command = f"cat <<EOF\n{body}\nEOF"
    _assert_native_unavailable(command)


@pytest.mark.parametrize(
    "substitution",
    [
        "$(sh -c 'rm -rf ./build')",
        '$(sh -c "rm -rf ./build")',
        "$(sh -c 'sh -c \"rm -rf ./build\"')",
    ],
)
def test_heredoc_substitution_shell_wrappers_feed_cli_and_runtime_classification(
    substitution: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    command = f"cat <<EOF\n{substitution}\nEOF"

    exit_code = main(["guard", "command", "test", "--json", command])
    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 2
    assert payload["status"] == "native_unavailable"
    assert payload["minimum_action"] == "review"
    assert payload["rules"] == []
    _assert_native_unavailable(command)


@pytest.mark.parametrize(
    "command",
    [
        "cat <<'EOF'\n$(sh -c 'rm -rf ./build')\nEOF",
        "cat <<EOF\n\\$(sh -c 'rm -rf ./build')\nEOF",
    ],
)
def test_literal_shell_wrapped_heredoc_substitutions_remain_safe_at_cli_and_runtime_boundaries(
    command: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = main(["guard", "command", "test", "--json", command])
    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 2
    assert payload["status"] == "native_unavailable"
    assert payload["minimum_action"] == "review"
    assert payload["rules"] == []
    _assert_native_unavailable(command)


SPECIALIZED_SAFE_VARIANT_CASES = (
    "cat <<'EOF'\n'$(rm -rf ./build)'\nEOF",
    "cat <<EOF\n\\$(rm -rf ./build)\nEOF",
    "cat <<EOF\n\\`rm -rf ./build\\`\nEOF",
    "curl -X DELETE https://api.example.test/items --next -X GET localhost:9200/customer-index",
    "curl -sXGET localhost:9200/customer-index",
    "curl -X DELETE --data localhost:9200/customer-index https://api.example.test/items",
    "curl -X DELETE --data=localhost:9200/customer-index https://api.example.test/items",
    "curl -X DELETE --output localhost:9200/customer-index https://api.example.test/items",
    "curl -X DELETE --header localhost:9200/customer-index https://api.example.test/items",
    "curl -X DELETE -Hlocalhost:9200/customer-index https://api.example.test/items",
    "curl -X DELETE --user localhost:9200/customer-index https://api.example.test/items",
    "curl -X DELETE --cert localhost:9200/customer-index https://api.example.test/items",
    "curl -X DELETE --key localhost:9200/customer-index https://api.example.test/items",
    "curl -X DELETE --cacert localhost:9200/customer-index https://api.example.test/items",
    "curl -X DELETE --proxy-user localhost:9200/customer-index https://api.example.test/items",
    "curl -X DELETE --url-query localhost:9200/customer-index https://api.example.test/items",
    "curl -X DELETE -o localhost:9200/customer-index https://api.example.test/items",
    "curl -oXDELETE localhost:9200/customer-index",
    "ssh -pvoProxyCommand='sh -c id' host.example",
    "ssh -FvoProxyCommand='sh -c id' host.example",
    "ssh -v4 host.example",
    "git push +origin",
    "git push --repo +origin main",
    "git push --repo=+origin main",
    "git push --push-option +audit origin main",
    "git push --push-option=+audit origin main",
    "git push -o +audit origin main",
    "git push -o+audit origin main",
    "git push -n origin +main",
    "git push origin +main -n",
)


def test_specialized_literal_observer_and_option_value_variants_remain_safe(tmp_path: Path) -> None:
    for case_id, command in enumerate(SPECIALIZED_SAFE_VARIANT_CASES, start=1):
        if command.startswith("cat <<"):
            _assert_native_unavailable(command)
            continue
        payload = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)
        rule_ids = {rule["rule_id"] for rule in payload["rules"]}
        assert rule_ids.isdisjoint(
            {
                "command.search.elasticsearch.delete",
                "command.remote.ssh.configured-execution",
                "command.git.force-push",
            }
        ), f"specialized-safe-{case_id:03}: {command!r}"
