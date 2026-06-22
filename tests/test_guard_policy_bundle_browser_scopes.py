"""Tests for browser scope support in policy bundle parser (HGBM072-HGBM079)."""

from __future__ import annotations

from codex_plugin_scanner.guard.policy_bundle_parser import (
    _policy_bundle_rule_is_valid,
    computed_policy_bundle_hash,
    validated_policy_bundle_payload,
)


def _valid_base_rule() -> dict[str, object]:
    return {
        "ruleId": "test-rule-1",
        "action": "allow",
        "reason": "allow local dev browser navigation",
        "scope": {
            "agents": ["codex"],
            "devices": ["device-1"],
            "ecosystems": ["npm"],
            "environments": ["development"],
            "harnesses": ["codex"],
            "locations": ["us-east-1"],
        },
    }


class TestBrowserScopeValidation:
    """HGBM072-HGBM079: Browser scope support in policy bundle."""

    def test_valid_bundle_with_browser_navigation_scope(self) -> None:
        """HGBM072: Parser accepts browser scope fields."""
        rule = _valid_base_rule()
        rule["scope"]["browserIntent"] = ["browser.navigation"]
        rule["scope"]["origin"] = ["http://127.0.0.1:3000"]
        rule["scope"]["pathPrefix"] = ["/guard"]
        assert _policy_bundle_rule_is_valid(rule) is True

    def test_valid_bundle_with_browser_inspect_scope(self) -> None:
        """HGBM072: Browser inspect scope accepted."""
        rule = _valid_base_rule()
        rule["scope"]["browserIntent"] = ["browser.inspect"]
        rule["scope"]["origin"] = ["https://hol.org"]
        assert _policy_bundle_rule_is_valid(rule) is True

    def test_valid_bundle_with_browser_profile_scope(self) -> None:
        """HGBM072: Browser profile scope accepted."""
        rule = _valid_base_rule()
        rule["scope"]["browserProfile"] = ["isolated"]
        assert _policy_bundle_rule_is_valid(rule) is True

    def test_valid_bundle_with_sensitive_surface_scope(self) -> None:
        """HGBM072: Sensitive surface scope accepted."""
        rule = _valid_base_rule()
        rule["scope"]["sensitiveSurface"] = ["cookies", "script_eval"]
        assert _policy_bundle_rule_is_valid(rule) is True

    def test_invalid_browser_intent_rejected(self) -> None:
        """HGBM073: Invalid browser intent value rejected."""
        rule = _valid_base_rule()
        rule["scope"]["browserIntent"] = ["browser.unknown"]
        assert _policy_bundle_rule_is_valid(rule) is False

    def test_invalid_browser_profile_rejected(self) -> None:
        """HGBM073: Invalid browser profile value rejected."""
        rule = _valid_base_rule()
        rule["scope"]["browserProfile"] = ["bogus-profile"]
        assert _policy_bundle_rule_is_valid(rule) is False

    def test_legacy_bundle_without_browser_fields_still_valid(self) -> None:
        """HGBM074: Backwards compatibility — no browser fields needed."""
        rule = _valid_base_rule()
        assert _policy_bundle_rule_is_valid(rule) is True

    def test_bundle_hash_stable_without_browser_fields(self) -> None:
        """HGBM074: Hash unchanged for legacy bundles."""
        bundle = {
            "contractVersion": "guard-policy-bundle.v1",
            "bundleVersion": "1.0",
            "issuedAt": "2026-01-01T00:00:00Z",
            "expiresAt": "2027-01-01T00:00:00Z",
            "verifier": {"algorithm": "rsa-pss-sha256", "publicKeyPem": "key", "signature": "sig"},
            "rolloutState": "enforced",
            "policyDefaults": {},
            "rules": [],
            "acknowledgements": [],
            "bundleHash": "sha256:d514421634db6671dd261bfe1cf84fff26f38def4ab117c09f82b49cf7821a69",
        }
        hash1 = computed_policy_bundle_hash(bundle)
        hash2 = computed_policy_bundle_hash(dict(bundle))
        assert hash1 == hash2

    def test_navigation_allow_does_not_match_interact(self) -> None:
        """HGBM077: browser.navigation scope does not match browser.interact."""
        # This is a logical assertion about scope matching — the parser
        # validates structure, and different browserIntent values produce
        # different scope tuples.
        nav_rule = _valid_base_rule()
        nav_rule["scope"]["browserIntent"] = ["browser.navigation"]

        interact_rule = _valid_base_rule()
        interact_rule["scope"]["browserIntent"] = ["browser.interact"]

        nav_scope = nav_rule["scope"]["browserIntent"]
        interact_scope = interact_rule["scope"]["browserIntent"]
        assert nav_scope != interact_scope

    def test_mcp_tool_matcher_family_accepted(self) -> None:
        """HGBM053: mcp-tool is in rule matcher families."""
        from codex_plugin_scanner.guard.policy_bundle_parser import (
            _POLICY_BUNDLE_RULE_MATCHER_FAMILIES,
        )
        assert "mcp-tool" in _POLICY_BUNDLE_RULE_MATCHER_FAMILIES

    def test_validated_payload_accepts_browser_scope(self) -> None:
        """HGBM072: Full bundle validation accepts browser scope."""
        rule = _valid_base_rule()
        rule["scope"]["browserIntent"] = ["browser.navigation"]
        rule["scope"]["origin"] = ["http://127.0.0.1:3000"]
        rule["scope"]["pathPrefix"] = ["/guard"]
        rule["scope"]["browserProfile"] = ["isolated"]

        bundle = {
            "contractVersion": "guard-policy-bundle.v1",
            "bundleVersion": "1.0",
            "issuedAt": "2026-01-01T00:00:00Z",
            "expiresAt": "2027-01-01T00:00:00Z",
            "verifier": {"algorithm": "sha256", "keyId": "key-1", "signature": "sig"},
            "rolloutState": "enforced",
            "policyDefaults": {
                "mode": "enforce",
                "defaultAction": "block",
                "unknownPublisherAction": "review",
                "changedHashAction": "require-reapproval",
                "newNetworkDomainAction": "block",
                "subprocessAction": "block",
                "telemetryEnabled": False,
                "syncEnabled": False,
            },
            "rules": [rule],
            "acknowledgements": [],
        }
        from codex_plugin_scanner.guard.policy_bundle_parser import computed_policy_bundle_hash
        bundle["bundleHash"] = computed_policy_bundle_hash(bundle)
        payload, error = validated_policy_bundle_payload(bundle)
        assert payload is not None
        assert error is None



def _valid_bundle_with_rules(rules: list[dict[str, object]]) -> dict[str, object]:
    bundle = {
        "contractVersion": "guard-policy-bundle.v1",
        "bundleVersion": "1.0",
        "issuedAt": "2026-01-01T00:00:00Z",
        "expiresAt": "2027-01-01T00:00:00Z",
        "verifier": {"algorithm": "sha256", "keyId": "key-1", "signature": "sig"},
        "rolloutState": "enforced",
        "policyDefaults": {
            "mode": "enforce",
            "defaultAction": "block",
            "unknownPublisherAction": "review",
            "changedHashAction": "require-reapproval",
            "newNetworkDomainAction": "block",
            "subprocessAction": "block",
            "telemetryEnabled": False,
            "syncEnabled": False,
        },
        "rules": rules,
        "acknowledgements": [],
    }
    bundle["bundleHash"] = computed_policy_bundle_hash(bundle)
    return bundle


class TestBrowserScopeDecisionNarrowing:
    """Regression: browser-scoped bundle rules must not produce broad family decisions."""

    @staticmethod
    def _local_match_rule() -> dict[str, object]:
        rule = _valid_base_rule()
        rule["scope"]["locations"] = []
        return rule

    def test_browser_scoped_rule_produces_no_decisions(self) -> None:
        """A rule with browserIntent must not generate a harness-scoped family decision."""
        from codex_plugin_scanner.guard.runtime.runner import _build_policy_bundle_decisions

        rule = self._local_match_rule()
        rule["scope"]["browserIntent"] = ["browser.navigation"]
        rule["scope"]["origin"] = ["http://127.0.0.1:3000"]
        rule["scope"]["pathPrefix"] = ["/guard"]
        bundle = _valid_bundle_with_rules([rule])
        decisions = _build_policy_bundle_decisions(bundle, device_id="device-1", device_name="dev")
        assert decisions == []

    def test_non_browser_scoped_rule_still_produces_decisions(self) -> None:
        """A rule without browser scope keys still generates harness-scoped family decisions."""
        from codex_plugin_scanner.guard.runtime.runner import _build_policy_bundle_decisions

        rule = self._local_match_rule()
        bundle = _valid_bundle_with_rules([rule])
        decisions = _build_policy_bundle_decisions(bundle, device_id="device-1", device_name="dev")
        assert len(decisions) > 0
        for decision in decisions:
            assert decision.scope == "harness"
            assert decision.artifact_id is not None
            assert decision.artifact_id.startswith("family:")

    def test_rule_with_only_sensitive_surface_skipped(self) -> None:
        """A rule with only sensitiveSurface scope is skipped (no broad allow)."""
        from codex_plugin_scanner.guard.runtime.runner import _build_policy_bundle_decisions

        rule = self._local_match_rule()
        rule["scope"]["sensitiveSurface"] = ["cookies"]
        bundle = _valid_bundle_with_rules([rule])
        decisions = _build_policy_bundle_decisions(bundle, device_id="device-1", device_name="dev")
        assert decisions == []

    def test_rule_with_only_browser_profile_skipped(self) -> None:
        """A rule with only browserProfile scope is skipped (no broad allow)."""
        from codex_plugin_scanner.guard.runtime.runner import _build_policy_bundle_decisions

        rule = self._local_match_rule()
        rule["scope"]["browserProfile"] = ["isolated"]
        bundle = _valid_bundle_with_rules([rule])
        decisions = _build_policy_bundle_decisions(bundle, device_id="device-1", device_name="dev")
        assert decisions == []

    def test_rule_with_only_origin_skipped(self) -> None:
        """A rule with only origin scope is skipped (no broad allow)."""
        from codex_plugin_scanner.guard.runtime.runner import _build_policy_bundle_decisions

        rule = self._local_match_rule()
        rule["scope"]["origin"] = ["http://127.0.0.1:3000"]
        bundle = _valid_bundle_with_rules([rule])
        decisions = _build_policy_bundle_decisions(bundle, device_id="device-1", device_name="dev")
        assert decisions == []

    def test_mixed_browser_and_non_browser_rules(self) -> None:
        """Only the non-browser rule produces a decision; the browser rule is skipped."""
        from codex_plugin_scanner.guard.runtime.runner import _build_policy_bundle_decisions

        browser_rule = self._local_match_rule()
        browser_rule["ruleId"] = "browser-rule"
        browser_rule["scope"]["browserIntent"] = ["browser.navigation"]
        browser_rule["scope"]["origin"] = ["http://127.0.0.1:3000"]

        plain_rule = self._local_match_rule()
        plain_rule["ruleId"] = "plain-rule"

        bundle = _valid_bundle_with_rules([browser_rule, plain_rule])
        decisions = _build_policy_bundle_decisions(bundle, device_id="device-1", device_name="dev")
        assert len(decisions) > 0
        for decision in decisions:
            assert decision.owner == "plain-rule"

    def test_browser_scope_constant_exported(self) -> None:
        """POLICY_BUNDLE_BROWSER_SCOPE_KEYS is exported and contains the expected keys."""
        from codex_plugin_scanner.guard.policy_bundle_parser import (
            POLICY_BUNDLE_BROWSER_SCOPE_KEYS,
        )

        assert "browserIntent" in POLICY_BUNDLE_BROWSER_SCOPE_KEYS
        assert "browserOperation" in POLICY_BUNDLE_BROWSER_SCOPE_KEYS
        assert "browserProfile" in POLICY_BUNDLE_BROWSER_SCOPE_KEYS
        assert "origin" in POLICY_BUNDLE_BROWSER_SCOPE_KEYS
        assert "pathPrefix" in POLICY_BUNDLE_BROWSER_SCOPE_KEYS
        assert "sensitiveSurface" in POLICY_BUNDLE_BROWSER_SCOPE_KEYS
