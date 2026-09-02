from __future__ import annotations

from dataclasses import replace

from codex_plugin_scanner.guard.runtime.action_explanation_builder import (
    ExplanationBuildContext,
    action_explanation_cache_key,
    build_action_explanation,
    explanation_matches_current_action,
    semantic_facts_from_action,
)
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command


def test_builder_accepts_typed_envelope_and_existing_canonical_command() -> None:
    canonical = parse_shell_command("rm -rf ./build")
    explanation = build_action_explanation(
        action_envelope={
            "action_type": "shell_command",
            "command": "rm -rf ./build",
            "tool_name": "Bash",
            "target_paths": ["./build"],
        },
        action_identity="approval:123",
        actor_label="Cursor",
        canonical_command=canonical,
    )
    assert explanation.action_identity == "approval:123"
    assert explanation.canonical_identity == canonical.security_identity
    assert explanation.kind == "file_delete"
    assert explanation.everyday.targets[0].label.endswith("build")
    assert explanation.technical.command_display is None


def test_decision_context_changes_reason_metadata_not_action_semantics() -> None:
    canonical = parse_shell_command("npm install left-pad@1.3.0")
    base = dict(
        action_envelope={"action_type": "shell_command", "command": canonical.raw_text},
        action_identity="approval:package",
        actor_label="Codex",
        canonical_command=canonical,
    )
    allowed = build_action_explanation(
        **base,
        build_context=ExplanationBuildContext(reason_codes=("policy_allow",), policy_source="local"),
    )
    blocked = build_action_explanation(
        **base,
        build_context=ExplanationBuildContext(reason_codes=("policy_block",), policy_source="managed"),
    )
    assert allowed.kind == blocked.kind == "package_install"
    assert allowed.everyday.headline == blocked.everyday.headline
    assert "policy_allow" in allowed.technical.reason_codes
    assert "policy_block" in blocked.technical.reason_codes


def test_compound_builder_preserves_order_and_identity() -> None:
    canonical = parse_shell_command("cd project && rm -rf build && npm install")
    explanation = build_action_explanation(
        action_envelope={"action_type": "shell_command", "command": canonical.raw_text},
        action_identity="approval:compound",
        actor_label="Claude Code",
        canonical_command=canonical,
    )
    assert explanation.kind == "compound_action"
    assert explanation.canonical_identity == canonical.security_identity
    assert "ordered actions" in explanation.everyday.headline
    assert "Delete a folder" in explanation.everyday.summary
    assert explanation.everyday.safer_alternatives
    assert explanation.technical.available is False


def test_compound_technical_projection_is_retention_and_authorization_bound() -> None:
    canonical = parse_shell_command("rm -rf build && npm install")
    visible = build_action_explanation(
        action_envelope={"action_type": "shell_command", "command": canonical.raw_text},
        action_identity="approval:compound-technical",
        actor_label="Cursor",
        canonical_command=canonical,
        exact_details_authorized=True,
        retained=True,
    )
    assert visible.technical.available is True
    assert visible.technical.command_display == canonical.raw_text
    assert len(visible.technical.segments) == 2

    hidden = build_action_explanation(
        action_envelope={"action_type": "shell_command", "command": canonical.raw_text},
        action_identity="approval:compound-technical",
        actor_label="Cursor",
        canonical_command=canonical,
        exact_details_authorized=True,
        retained=False,
    )
    assert hidden.technical.available is False
    assert hidden.technical.unavailable_reason == "not_retained"
    assert hidden.technical.command_display is None


def test_semantic_fact_model_is_bounded_and_uses_typed_targets() -> None:
    canonical = parse_shell_command("curl --data token=x https://example.test/private")
    facts = semantic_facts_from_action(
        action_envelope={
            "action_type": "shell_command",
            "command": canonical.raw_text,
            "network_hosts": ["typed.example.test"],
            "target_paths": ["/very/private/path"],
        },
        action_identity="a" * 900,
        actor_label="Cursor",
        canonical_command=canonical,
    )
    assert len(facts.action_identity) <= 512
    assert facts.network_hosts == ("typed.example.test",)
    assert facts.canonical_identity == canonical.security_identity


def test_builder_does_not_promote_flags_to_typed_operands() -> None:
    canonical = parse_shell_command("rm ./build -rf")
    facts = semantic_facts_from_action(
        action_envelope={"action_type": "shell_command", "command": canonical.raw_text},
        action_identity="approval:rm-flags",
        actor_label="Cursor",
        canonical_command=canonical,
    )
    assert facts.operands == ()
    explanation = build_action_explanation(
        action_envelope={"action_type": "shell_command", "command": canonical.raw_text},
        action_identity="approval:rm-flags",
        actor_label="Cursor",
        canonical_command=canonical,
    )
    assert explanation.kind == "file_delete"
    assert "build" in explanation.everyday.summary
    assert "item named rf" not in explanation.everyday.summary


def test_cache_key_covers_identity_catalog_renderer_locale_and_redaction() -> None:
    base = action_explanation_cache_key(action_identity="a", canonical_identity="c")
    assert base != action_explanation_cache_key(action_identity="b", canonical_identity="c")
    assert base != action_explanation_cache_key(action_identity="a", canonical_identity="d")
    assert base != action_explanation_cache_key(action_identity="a", canonical_identity="c", catalog_digest="f" * 64)
    assert base != action_explanation_cache_key(action_identity="a", canonical_identity="c", locale="fr-FR")
    assert base != action_explanation_cache_key(action_identity="a", canonical_identity="c", redaction_version="2")


def test_identity_matcher_fails_closed_for_action_canonical_and_catalog_mismatches() -> None:
    canonical = parse_shell_command("rm -rf build")
    explanation = build_action_explanation(
        action_envelope={"action_type": "shell_command", "command": canonical.raw_text},
        action_identity="approval:1",
        actor_label="Cursor",
        canonical_command=canonical,
    )
    assert explanation_matches_current_action(
        explanation,
        action_identity="approval:1",
        canonical_identity=canonical.security_identity,
        catalog_digest=explanation.catalog_digest,
    )
    assert not explanation_matches_current_action(
        explanation,
        action_identity="approval:2",
        canonical_identity=canonical.security_identity,
    )
    assert not explanation_matches_current_action(
        explanation,
        action_identity="approval:1",
        canonical_identity="command:v1:other",
    )
    assert not explanation_matches_current_action(
        replace(explanation, catalog_digest="a" * 64),
        action_identity="approval:1",
        canonical_identity=canonical.security_identity,
        catalog_digest="b" * 64,
    )
