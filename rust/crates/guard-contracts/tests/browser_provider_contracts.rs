use guard_contracts::*;
use serde_json::{json, Value};

fn browser_action() -> Value {
    json!({
        "version": 2,
        "driver": {
            "id": "driver.example-browser",
            "kind": "mcp",
            "identity_hash": "a".repeat(64),
            "trust_class": "first-party"
        },
        "session": {
            "harness": "example-harness",
            "session_ref_digest": "b".repeat(64),
            "profile_mode": "isolated"
        },
        "intent": "browser.interact",
        "operation": "browser_type",
        "verb": "type",
        "target": {
            "origin": "https://shop.example.test",
            "site_group": "example.test",
            "path_prefix": "/checkout",
            "is_loopback": false,
            "is_guard_origin": false,
            "url_redacted": "https://shop.example.test/checkout?step=[redacted]&lang="
        },
        "element": {
            "role": "textbox",
            "name_digest": "c".repeat(64),
            "name_preview": "Card number",
            "is_password": false,
            "is_payment": true,
            "is_file_input": false
        },
        "input": {
            "kind": "text",
            "length": 16,
            "digest": "d".repeat(64),
            "preview_class": "looks_like_payment"
        },
        "sensitive_surface_flags": ["password_field"],
        "cdp": null,
        "volatile_fields_dropped": ["ref"]
    })
}

fn provider_signal() -> Value {
    json!({
        "version": 1,
        "provider_id": "provider.exampleshield",
        "capability": "browser.origin-reputation",
        "subject": {"kind": "origin", "digest": "e".repeat(64)},
        "verdict": "caution",
        "reason_codes": ["new_domain"],
        "observed_at_ms": 1_000,
        "expires_at_ms": 61_000,
        "inventory": "provider-side",
        "state": "fresh"
    })
}

#[test]
fn browser_action_round_trips_and_keeps_shape() {
    let value = browser_action();
    let action: BrowserActionV2 = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(action.verb, BrowserVerbV1::Type);
    assert_eq!(action.driver.kind, BrowserDriverKindV1::Mcp);
    assert_eq!(action.validate_shape(), Ok(()));
    assert_eq!(serde_json::to_value(&action).unwrap(), value);
}

#[test]
fn browser_action_rejects_unknown_fields_at_every_level() {
    let mut top = browser_action();
    top["extra"] = json!(true);
    assert!(serde_json::from_value::<BrowserActionV2>(top).is_err());

    let mut target = browser_action();
    target["target"]["query"] = json!("token=1");
    assert!(serde_json::from_value::<BrowserActionV2>(target).is_err());

    let mut input = browser_action();
    input["input"]["text"] = json!("4111111111111111");
    assert!(serde_json::from_value::<BrowserActionV2>(input).is_err());
}

#[test]
fn browser_action_rejects_unknown_verb() {
    let mut value = browser_action();
    value["verb"] = json!("approve");
    assert!(serde_json::from_value::<BrowserActionV2>(value).is_err());
}

#[test]
fn browser_action_shape_bounds() {
    let mut action: BrowserActionV2 = serde_json::from_value(browser_action()).unwrap();
    action.operation = "x".repeat(BROWSER_ACTION_OPERATION_MAX_BYTES + 1);
    assert_eq!(
        action.validate_shape(),
        Err(BrowserActionShapeErrorV1::OperationTooLong)
    );

    let mut action: BrowserActionV2 = serde_json::from_value(browser_action()).unwrap();
    action.element.as_mut().unwrap().name_preview =
        Some("é".repeat(BROWSER_ELEMENT_NAME_PREVIEW_MAX_CHARS + 1));
    assert_eq!(
        action.validate_shape(),
        Err(BrowserActionShapeErrorV1::ElementPreviewTooLong)
    );

    let mut action: BrowserActionV2 = serde_json::from_value(browser_action()).unwrap();
    action.driver.kind = BrowserDriverKindV1::Cdp;
    assert_eq!(
        action.validate_shape(),
        Err(BrowserActionShapeErrorV1::CdpMissingForCdpDriver)
    );
    action.cdp = Some(BrowserCdpCommandV1 {
        domain: "Network".into(),
        method: "Network.getCookies".into(),
        classified: true,
    });
    assert_eq!(action.validate_shape(), Ok(()));

    action.version = 1;
    assert_eq!(
        action.validate_shape(),
        Err(BrowserActionShapeErrorV1::WrongVersion)
    );
}

#[test]
fn browser_action_url_must_be_redacted() {
    for url in [
        "https://shop.example.test/checkout",
        "https://shop.example.test/checkout?",
        "https://shop.example.test/checkout?step=[redacted]",
        "https://shop.example.test/checkout?step=%5Bredacted%5D&flag",
    ] {
        assert!(browser_url_is_redacted(url), "{url}");
    }
    let raw_value = format!(
        "https://shop.example.test/checkout?session={}",
        "z".repeat(24)
    );
    for url in [
        raw_value.as_str(),
        "https://shop.example.test/checkout?step=[redacted]&page=2",
        "https://shop.example.test/checkout#fragment",
    ] {
        assert!(!browser_url_is_redacted(url), "{url}");
    }
    let long = format!(
        "https://shop.example.test/{}",
        "a".repeat(BROWSER_URL_REDACTED_MAX_CHARS)
    );
    assert!(!browser_url_is_redacted(&long));

    let mut action: BrowserActionV2 = serde_json::from_value(browser_action()).unwrap();
    action.target.url_redacted = Some(raw_value);
    assert_eq!(
        action.validate_shape(),
        Err(BrowserActionShapeErrorV1::UrlNotRedacted)
    );
}

#[test]
fn browser_action_digests_are_sha256_hex() {
    assert!(sha256_hex_is_valid(&"0123456789abcdef".repeat(4)));
    for bad in [
        String::new(),
        "A".repeat(64),
        "a".repeat(63),
        "a".repeat(65),
        "https://shop.example.test/".into(),
    ] {
        assert!(!sha256_hex_is_valid(&bad), "{bad}");
    }
    let edits: [fn(&mut BrowserActionV2); 3] = [
        |action| action.session.session_ref_digest = Some("raw-session".into()),
        |action| action.element.as_mut().unwrap().name_digest = Some("Card number".into()),
        |action| action.input.as_mut().unwrap().digest = Some(String::new()),
    ];
    for edit in edits {
        let mut action: BrowserActionV2 = serde_json::from_value(browser_action()).unwrap();
        edit(&mut action);
        assert_eq!(
            action.validate_shape(),
            Err(BrowserActionShapeErrorV1::DigestInvalid)
        );
    }
}

#[test]
fn legacy_v1_intent_stays_readable() {
    let value = json!({
        "version": 1,
        "intent": "browser.navigation",
        "operation": "navigate",
        "target_url": "https://example.test/",
        "target_origin": "https://example.test",
        "target_domain": "example.test",
        "target_path_prefix": "/",
        "method": "navigate",
        "profile_mode": "isolated",
        "mcp_server_name": "browser",
        "mcp_server_identity_hash": null,
        "mcp_tool_name": "navigate",
        "mcp_tool_identity_hash": null,
        "mcp_schema_hash": null,
        "sensitive_surface_flags": [],
        "volatile_fields_dropped": []
    });
    let intent: BrowserAutomationIntentV1 = serde_json::from_value(value).unwrap();
    assert_eq!(intent.intent, BrowserIntentV1::Navigation);
}

#[test]
fn card_round_trips_and_checks_invariant() {
    let card = BrowserCardV1 {
        headline: "Example Agent wants to type into a form on shop.example.test".into(),
        verb: BrowserVerbV1::Type,
        site: BrowserCardSiteV1 {
            origin: Some("https://shop.example.test".into()),
            first_visit_in_task: true,
            left_granted_site: false,
        },
        profile_line: BrowserProfileModeV1::Shared.into(),
        detail: BrowserCardDetailV1 {
            element_preview: Some("Card number".into()),
            input_kind: Some(BrowserInputKindV1::Text),
            input_length: Some(16),
            input_masked: true,
        },
        risk_chips: vec![BrowserSensitiveSurfaceV1::PasswordField],
        provider_findings: vec![],
        choices: vec![
            BrowserCardChoiceV1::AllowOnce,
            BrowserCardChoiceV1::AlwaysAllow,
            BrowserCardChoiceV1::Deny,
            BrowserCardChoiceV1::SiteGrant,
        ],
        steps: vec![],
    };
    assert_eq!(card.profile_line, BrowserCardProfileLineV1::Shared);
    assert!(card.keeps_approval_invariant());
    let value = serde_json::to_value(&card).unwrap();
    assert_eq!(value["profile_line"], json!("shared"));
    let back: BrowserCardV1 = serde_json::from_value(value).unwrap();
    assert_eq!(back, card);

    let mut once_only = card;
    once_only
        .choices
        .retain(|choice| *choice != BrowserCardChoiceV1::AlwaysAllow);
    assert!(!once_only.keeps_approval_invariant());
}

#[test]
fn provider_signal_round_trips_and_validates() {
    let value = provider_signal();
    let signal: ProviderSignalV1 = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(signal.capability, ProviderCapabilityV1::OriginReputation);
    assert_eq!(signal.validate_shape(), Ok(()));
    assert!(signal.is_live_at(60_999));
    assert!(!signal.is_live_at(61_000));
    assert_eq!(serde_json::to_value(&signal).unwrap(), value);
}

#[test]
fn provider_signal_has_no_allow_verdict_or_unknown_capability() {
    let mut allow = provider_signal();
    allow["verdict"] = json!("allow");
    assert!(serde_json::from_value::<ProviderSignalV1>(allow).is_err());

    let mut capability = provider_signal();
    capability["capability"] = json!("browser.auto-approve");
    assert!(serde_json::from_value::<ProviderSignalV1>(capability).is_err());

    let mut extra = provider_signal();
    extra["message"] = json!("free text from the provider");
    assert!(serde_json::from_value::<ProviderSignalV1>(extra).is_err());
}

#[test]
fn provider_signal_shape_errors() {
    let base: ProviderSignalV1 = serde_json::from_value(provider_signal()).unwrap();

    let mut signal = base.clone();
    signal.reason_codes = (0..=PROVIDER_SIGNAL_MAX_REASON_CODES)
        .map(|index| format!("code_{index}"))
        .collect();
    assert_eq!(
        signal.validate_shape(),
        Err(ProviderSignalShapeErrorV1::TooManyReasonCodes)
    );

    let mut signal = base.clone();
    signal.reason_codes = vec!["Visit evil dot example".into()];
    assert_eq!(
        signal.validate_shape(),
        Err(ProviderSignalShapeErrorV1::ReasonCodeInvalid)
    );

    let mut signal = base.clone();
    signal.expires_at_ms = 0;
    assert_eq!(
        signal.validate_shape(),
        Err(ProviderSignalShapeErrorV1::ExpiresBeforeObserved)
    );

    let mut signal = base.clone();
    signal.provider_id = "exampleshield".into();
    assert_eq!(
        signal.validate_shape(),
        Err(ProviderSignalShapeErrorV1::ProviderIdInvalid)
    );

    for digest in [
        "https://shop.example.test/checkout".to_owned(),
        String::new(),
        "e".repeat(65),
    ] {
        let mut signal = base.clone();
        signal.subject.digest = digest;
        assert_eq!(
            signal.validate_shape(),
            Err(ProviderSignalShapeErrorV1::SubjectDigestInvalid)
        );
    }

    let mut signal = base;
    signal.state = ProviderSignalStateV1::Stale;
    assert!(!signal.is_live_at(2_000));
}

#[test]
fn provider_ids_and_reason_codes() {
    assert!(provider_id_is_valid("provider.exampleshield"));
    assert!(provider_id_is_valid("provider.fixture-quiet"));
    assert!("provider.fixture-quiet".starts_with(PROVIDER_FIXTURE_ID_PREFIX));
    for bad in [
        "provider.",
        "provider.Example",
        "provider.-x",
        "provider.x-",
        "provider.a/b",
        "other.example",
    ] {
        assert!(!provider_id_is_valid(bad), "{bad}");
    }
    assert!(provider_reason_code_is_valid("typosquat"));
    for bad in ["", "Phishing", "1st", "a-b", "a b"] {
        assert!(!provider_reason_code_is_valid(bad), "{bad}");
    }
}

#[test]
fn strongest_verdict_ordering() {
    let mut verdicts = [
        ProviderVerdictV1::Ok,
        ProviderVerdictV1::Danger,
        ProviderVerdictV1::Unknown,
        ProviderVerdictV1::Caution,
    ];
    verdicts.sort_by_key(|verdict| std::cmp::Reverse(verdict.strength()));
    assert_eq!(verdicts[0], ProviderVerdictV1::Danger);
    assert_eq!(verdicts[3], ProviderVerdictV1::Unknown);
}

#[test]
fn capability_and_fact_names_are_closed() {
    for capability in ProviderCapabilityV1::ALL {
        let value = serde_json::to_value(capability).unwrap();
        assert_eq!(value, json!(capability.as_str()));
    }
    let fact: ProviderShareableFactV1 =
        serde_json::from_value(json!("target.path_prefix")).unwrap();
    assert!(fact.opt_in_only());
    assert!(serde_json::from_value::<ProviderShareableFactV1>(json!("page.text")).is_err());
    assert_eq!(
        ProviderEffectLevelV1::default(),
        ProviderEffectLevelV1::Tighten
    );
}

#[test]
fn connect_request_never_prints_the_key() {
    let key_marker = "m".repeat(40);
    let proof_marker = "n".repeat(40);
    let request: ProviderConnectRequestV1 = serde_json::from_value(json!({
        "key": key_marker.clone(),
        "proof": proof_marker.clone(),
        "enabled_opt_in_facts": ["target.path_prefix"]
    }))
    .unwrap();
    let printed = format!("{request:?}");
    assert!(!printed.contains(&key_marker));
    assert!(!printed.contains(&proof_marker));
    assert!(request.key_is_plausible());

    let control: ProviderConnectRequestV1 =
        serde_json::from_value(json!({"key": "abc\u{0007}", "proof": "p"})).unwrap();
    assert!(!control.key_is_plausible());
    let long: ProviderConnectRequestV1 = serde_json::from_value(
        json!({"key": "k".repeat(PROVIDER_KEY_MAX_BYTES + 1), "proof": "p"}),
    )
    .unwrap();
    assert!(!long.key_is_plausible());
}

#[test]
fn proof_bearing_messages_never_print_the_proof() {
    let proof_marker = "n".repeat(40);
    let settings: ProviderSettingsRequestV1 = serde_json::from_value(json!({
        "proof": proof_marker.clone(),
        "settings": [],
        "enabled_opt_in_facts": []
    }))
    .unwrap();
    let disconnect: ProviderDisconnectRequestV1 =
        serde_json::from_value(json!({"proof": proof_marker.clone()})).unwrap();
    let preview: ProviderConnectPreviewV1 = serde_json::from_value(json!({
        "provider_id": "provider.exampleshield",
        "shares": ["target.origin"],
        "opt_in_facts": ["target.path_prefix"],
        "hosts": ["api.exampleshield.example"],
        "challenge": proof_marker.clone(),
        "expires_at_ms": 5_000
    }))
    .unwrap();
    for printed in [
        format!("{settings:?}"),
        format!("{disconnect:?}"),
        format!("{preview:?}"),
    ] {
        assert!(!printed.contains(&proof_marker), "{printed}");
    }
    // The preview is a response, so it still serializes the challenge for the client.
    assert_eq!(
        serde_json::to_value(&preview).unwrap()["challenge"],
        json!(proof_marker)
    );
}

#[test]
fn integration_error_codes_match_wire_names() {
    for error in [
        ProviderIntegrationErrorV1::ProviderIntegrationUnavailable,
        ProviderIntegrationErrorV1::ProviderKeyInvalid,
        ProviderIntegrationErrorV1::ProviderHostRefused,
        ProviderIntegrationErrorV1::ProviderRateLimited,
        ProviderIntegrationErrorV1::ProviderResponseTooLarge,
        ProviderIntegrationErrorV1::ProviderCapabilityUnavailable,
    ] {
        assert_eq!(serde_json::to_value(error).unwrap(), json!(error.code()));
    }
}
