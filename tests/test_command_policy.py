from __future__ import annotations

from codex_plugin_scanner.guard.policy_document_yaml import parse_policy_document_yaml
from codex_plugin_scanner.guard.runtime.command_policy import (
    compile_command_policy_rules,
    evaluate_command_policy_rules,
)


def test_policy_command_expression_enforces_strongest_matching_action() -> None:
    document = parse_policy_document_yaml(
        """
apiVersion: guard.hashgraphonline.com/v1alpha1
kind: GuardPolicy
metadata:
  id: policy.command-runtime
  name: Command runtime
  revision: 1
spec:
  defaults:
    mode: prompt
    defaultAction: warn
  rolloutState: draft
  rules:
    - id: review-compose
      enabled: true
      effect: review
      match:
        commands:
          combinator: all
          conditions:
            - field: command
              operator: startsWith
              value: docker compose
      lifetime:
        mode: permanent
        expiresAt: null
      provenance:
        source: suggested-memory
        receiptIds: []
        suggestionId: suggestion-001
        createdAt: 2026-07-24T00:00:00Z
        createdBy: test
    - id: block-production-compose
      enabled: true
      effect: block
      match:
        commands:
          combinator: all
          conditions:
            - field: command
              operator: glob
              value: docker compose * --detach
      lifetime:
        mode: permanent
        expiresAt: null
      provenance:
        source: suggested-memory
        receiptIds: []
        suggestionId: suggestion-001
        createdAt: 2026-07-24T00:00:00Z
        createdBy: test
"""
    )

    rules = compile_command_policy_rules(document)
    blocked = evaluate_command_policy_rules(rules, "docker compose up --detach")
    unmatched = evaluate_command_policy_rules(rules, "git status")

    assert blocked.action == "block"
    assert blocked.matching_rule_ids == ("review-compose", "block-production-compose")
    assert unmatched.action == "allow"
    assert unmatched.matching_rule_ids == ()
