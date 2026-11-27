use super::*;

#[test]
fn browser_protection_is_current_unless_legacy_is_named() {
    for value in [
        None,
        Some(""),
        Some("on"),
        Some("off"),
        Some("0"),
        Some("legacyy"),
        Some("legacy-mode"),
    ] {
        assert_eq!(
            browser_protection_mode_from(value),
            BrowserProtectionMode::Current,
            "{value:?} must not select the legacy path"
        );
    }
}

#[test]
fn browser_protection_legacy_is_trimmed_and_case_insensitive() {
    for value in ["legacy", "LEGACY", " Legacy\n", "\tlegacy "] {
        assert_eq!(
            browser_protection_mode_from(Some(value)),
            BrowserProtectionMode::Legacy,
            "{value:?}"
        );
    }
}

#[test]
fn provider_integrations_are_on_unless_disabled() {
    for value in [
        None,
        Some(""),
        Some("1"),
        Some("on"),
        Some("true"),
        Some("enabled"),
        Some("legacy"),
    ] {
        assert!(
            provider_integrations_enabled_from(value),
            "{value:?} must leave integrations on"
        );
    }
}

#[test]
fn provider_integrations_disabled_values_match_discovery() {
    for value in [
        "0",
        "off",
        "false",
        "disabled",
        " OFF ",
        "False",
        "\tDisabled\n",
    ] {
        assert!(
            !provider_integrations_enabled_from(Some(value)),
            "{value:?} must turn integrations off"
        );
    }
}

#[test]
fn provider_routes_answer_capability_unavailable_when_off() {
    assert_eq!(provider_route_gate_from(None), Ok(()));
    let refused = provider_route_gate_from(Some("off")).expect_err("off must refuse the route");
    assert_eq!(
        refused,
        ProviderIntegrationErrorV1::ProviderCapabilityUnavailable
    );
    assert_eq!(refused.code(), "provider_capability_unavailable");
}

#[test]
fn provider_decide_step_is_a_no_op_when_off() {
    let mut ran = false;
    let evidence: Vec<&str> = provider_decide_step_from(Some("off"), || {
        ran = true;
        vec!["caution"]
    });
    assert!(
        !ran,
        "the decide step must not run when integrations are off"
    );
    assert!(evidence.is_empty());

    let evidence = provider_decide_step_from(None, || vec!["caution"]);
    assert_eq!(evidence, vec!["caution"]);
}

#[test]
fn switches_read_the_contract_variable_names() {
    assert_eq!(BROWSER_PROTECTION_ENV, "HOL_GUARD_BROWSER_PROTECTION");
    assert_eq!(PROVIDER_INTEGRATIONS_ENV, "HOL_GUARD_PROVIDER_INTEGRATIONS");
}
