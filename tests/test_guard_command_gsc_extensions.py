"""Structured Google Search Console (GSC) CLI command extension tests."""

from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    risk_classes_for_command_action,
)
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from tests.command_extension_contracts import (
    assert_safe_command_cases,
    enable_local_admin_extension_layer,
)

_INDEX_ACTION = "google search console url index request command"
_REMOVE_ACTION = "google search console url removal request command"
_INDEX_SITEMAP_ACTION = "google search console bulk sitemap index command"
_SITEMAPS_SUBMIT_ACTION = "google search console sitemap submission command"
_CACHE_CLEAR_ACTION = "google search console cache purge command"

_INDEX_RULE = "command.gsc.index"
_REMOVE_RULE = "command.gsc.remove"
_INDEX_SITEMAP_RULE = "command.gsc.index-sitemap"
_SITEMAPS_SUBMIT_RULE = "command.gsc.sitemaps-submit"
_CACHE_CLEAR_RULE = "command.gsc.cache-clear"

_SENSITIVE_TOKENS = ("secret-page", "my-private-domain.com", "confidential-sitemap.xml")

GSC_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    ("gsc index https://my-private-domain.com/secret-page", _INDEX_ACTION, _INDEX_RULE),
    ("gsc index https://example.com/page --json", _INDEX_ACTION, _INDEX_RULE),
    ("gsc index -d example.com https://example.com/page", _INDEX_ACTION, _INDEX_RULE),
    ("gsc.exe index https://example.com/page", _INDEX_ACTION, _INDEX_RULE),
    ("gsc.cmd index https://example.com/page", _INDEX_ACTION, _INDEX_RULE),
    ("gsc index", _INDEX_ACTION, _INDEX_RULE),
    ("gsc index --unknown-flag", _INDEX_ACTION, _INDEX_RULE),
    ("gsc remove https://my-private-domain.com/secret-page", _REMOVE_ACTION, _REMOVE_RULE),
    ("gsc remove https://example.com/page -j", _REMOVE_ACTION, _REMOVE_RULE),
    ("gsc.exe remove https://example.com/page", _REMOVE_ACTION, _REMOVE_RULE),
    ("gsc.cmd remove https://example.com/page", _REMOVE_ACTION, _REMOVE_RULE),
    ("gsc remove", _REMOVE_ACTION, _REMOVE_RULE),
    ("gsc index-sitemap confidential-sitemap.xml", _INDEX_SITEMAP_ACTION, _INDEX_SITEMAP_RULE),
    ("gsc index-sitemap https://example.com/sitemap.xml", _INDEX_SITEMAP_ACTION, _INDEX_SITEMAP_RULE),
    ("gsc.exe index-sitemap sitemap.xml", _INDEX_SITEMAP_ACTION, _INDEX_SITEMAP_RULE),
    ("gsc index-sitemap", _INDEX_SITEMAP_ACTION, _INDEX_SITEMAP_RULE),
    ("gsc sitemaps-submit https://example.com/sitemap.xml", _SITEMAPS_SUBMIT_ACTION, _SITEMAPS_SUBMIT_RULE),
    ("gsc.exe sitemaps-submit https://example.com/sitemap.xml", _SITEMAPS_SUBMIT_ACTION, _SITEMAPS_SUBMIT_RULE),
    ("gsc sitemaps-submit", _SITEMAPS_SUBMIT_ACTION, _SITEMAPS_SUBMIT_RULE),
    ("gsc cache clear", _CACHE_CLEAR_ACTION, _CACHE_CLEAR_RULE),
    ("gsc cache clear example.com", _CACHE_CLEAR_ACTION, _CACHE_CLEAR_RULE),
    ("gsc.exe cache clear", _CACHE_CLEAR_ACTION, _CACHE_CLEAR_RULE),
    ("gsc index https://example.com; gsc inspect https://example.com", _INDEX_ACTION, _INDEX_RULE),
    ("zsh -lc 'gsc index https://example.com'", _INDEX_ACTION, _INDEX_RULE),
)


def test_gsc_rules_stay_inert_until_enabled(tmp_path: Path) -> None:
    for command, _action_class, rule_id in GSC_REVIEW_CASES:
        evaluation = evaluate_command(command, cwd=tmp_path, home_dir=tmp_path)
        assert evaluation.controlling_rule_id != rule_id
        assert all(item.extension.extension_id != "command.gsc" for item in evaluation.extension_observations)


def test_enabled_gsc_commands_reach_review(tmp_path: Path) -> None:
    for command, action_class, rule_id in GSC_REVIEW_CASES:
        evaluation = evaluate_command(
            command,
            cwd=tmp_path,
            home_dir=tmp_path,
            extension_control_layers=(enable_local_admin_extension_layer("command.gsc"),),
        )
        matched = {
            item.rule.rule_id
            for item in evaluation.extension_observations
            if item.extension.extension_id == "command.gsc"
        }
        assert rule_id in matched, command
        assert evaluation.controlling_rule_id == rule_id
        assert any(item.match.action_class == action_class for item in evaluation.matches)


def test_registry_observations_attribute_gsc_rules(tmp_path: Path) -> None:
    for command, _action_class, expected_rule in GSC_REVIEW_CASES:
        observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(
            parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)
        )
        matched = {item.rule.rule_id for item in observations if item.extension.extension_id == "command.gsc"}
        assert expected_rule in matched, command


GSC_SAFE_COMMANDS: tuple[str, ...] = (
    "gsc inspect https://example.com/page",
    "gsc status https://example.com/page",
    "gsc top-queries",
    "gsc top-pages",
    "gsc performance",
    "gsc sitemaps-list",
    "gsc inspect-sitemap sitemap.xml",
    "gsc audit",
    "gsc cache query 'search console'",
    "gsc cache status",
    "gsc cache warm",
    "gsc cache diff snap1 snap2",
    "gsc --help",
    "gsc -h",
    "gsc index --help",
    "gsc index -h",
    "gsc remove --help",
    "gsc remove -h",
    "gsc index-sitemap --help",
    "gsc index-sitemap -h",
    "gsc sitemaps-submit --help",
    "gsc sitemaps-submit -h",
    "gsc cache clear --help",
    "gsc cache clear -h",
    "gsc doctor",
    "gsc where",
    "gsc domains",
    "gsc use",
    "echo gsc index https://example.com",
    "grep 'gsc index' docs",
    "notgsc index https://example.com",
    "gsc-cli index https://example.com",
)


def test_gsc_read_help_and_unrelated_commands_remain_safe(tmp_path: Path) -> None:
    assert_safe_command_cases(GSC_SAFE_COMMANDS, tmp_path)


def test_enabled_gsc_help_and_read_commands_do_not_review(tmp_path: Path) -> None:
    for command in (
        "gsc inspect https://example.com/page",
        "gsc status https://example.com/page",
        "gsc top-queries",
        "gsc performance",
        "gsc sitemaps-list",
        "gsc inspect-sitemap sitemap.xml",
        "gsc audit",
        "gsc --help",
        "gsc index --help",
        "gsc remove --help",
        "gsc index-sitemap --help",
        "gsc sitemaps-submit --help",
        "gsc cache clear --help",
    ):
        evaluation = evaluate_command(
            command,
            cwd=tmp_path,
            home_dir=tmp_path,
            extension_control_layers=(enable_local_admin_extension_layer("command.gsc"),),
        )
        assert evaluation.controlling_rule_id not in {
            _INDEX_RULE,
            _REMOVE_RULE,
            _INDEX_SITEMAP_RULE,
            _SITEMAPS_SUBMIT_RULE,
            _CACHE_CLEAR_RULE,
        }
        assert all(
            not item.effective_evidence
            for item in evaluation.extension_observations
            if item.extension.extension_id == "command.gsc"
        )


def test_gsc_evidence_omits_sensitive_urls(tmp_path: Path) -> None:
    command = "gsc index https://my-private-domain.com/secret-page"
    evaluation = evaluate_command(
        command,
        cwd=tmp_path,
        home_dir=tmp_path,
        extension_control_layers=(enable_local_admin_extension_layer("command.gsc"),),
    )
    gsc_matches = [item.match for item in evaluation.matches if item.extension.extension_id == "command.gsc"]
    assert gsc_matches
    serialized = json.dumps(
        [
            {
                "rule_id": match.rule.rule_id,
                "reason": match.reason,
                "action_class": match.action_class,
                "evidence": [item.to_dict() for item in match.matcher_evidence],
            }
            for match in gsc_matches
        ]
    )
    for token in _SENSITIVE_TOKENS:
        assert token not in serialized
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.gsc")
    assert extension is not None
    catalog = json.dumps(extension.to_dict())
    for token in ("secret-page", "my-private-domain.com", "confidential-sitemap.xml"):
        assert token not in catalog
    for permission in extension.permissions:
        assert permission.example_command in {
            "gsc index",
            "gsc remove",
            "gsc index-sitemap",
            "gsc sitemaps-submit",
            "gsc cache clear",
        }


def test_gsc_extension_publishes_references_and_action_risks() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.gsc")
    assert extension is not None
    assert extension.reference_urls == (
        "https://github.com/ApollosWave/gsc-cli",
        "https://developers.google.com/search/apis/indexing-api/v3/quickstart",
    )
    assert all(url.startswith("https://") for url in extension.reference_urls)
    assert risk_classes_for_command_action(_INDEX_ACTION) == ("network_egress",)
    assert risk_classes_for_command_action(_REMOVE_ACTION) == ("destructive_shell", "network_egress")
    assert risk_classes_for_command_action(_INDEX_SITEMAP_ACTION) == ("network_egress",)
    assert risk_classes_for_command_action(_SITEMAPS_SUBMIT_ACTION) == ("network_egress",)
    assert risk_classes_for_command_action(_CACHE_CLEAR_ACTION) == ("destructive_shell",)
    payload = extension.to_dict()
    assert payload["enabled"] is False
    assert payload["trust_class"] == "external"
    assert payload["activation"] == "opt-in"
    assert payload["publisher"]["id"] == "community"
