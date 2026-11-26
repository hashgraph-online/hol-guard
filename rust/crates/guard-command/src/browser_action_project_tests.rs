use guard_contracts::{BrowserDriverTrustClassV1, BrowserInputPreviewClassV1};
use serde_json::{json, Value};

use super::*;
use crate::browser_driver_compile::{
    compile_browser_driver, BrowserDriverOrigin, CompiledBrowserDriverV1,
};
use crate::browser_driver_match::{match_browser_driver, BrowserToolCallIdentity};

/// Mixed letters and digits, 20+ characters, one token: the shape the preview class hides.
const SECRET_LIKE: &str = "a1b2c3d4e5f6g7h8i9j0k1";

fn pilot() -> CompiledBrowserDriverV1 {
    let profile = json!({
        "schemaVersion": "guard.browser-driver.v1",
        "id": "browser.example-pilot",
        "name": "Example Pilot browser tools",
        "publisher": {"name": "Example Org", "verified": false},
        "match": {
            "mcpServerNames": ["example-pilot"],
            "packages": [],
            "toolNamespaces": ["mcp__example-pilot__"],
            "harnessTools": ["web-pilot"]
        },
        "profileMode": {"default": "isolated"},
        "tools": [
            {"name": "open_page", "verb": "Navigate", "url": ["url", "href"]},
            {"name": "press", "verb": "Click", "element": {"name": ["label"]}},
            {"name": "fill", "verb": "Type", "element": {"name": ["label"]}, "text": ["value"]},
            {"name": "peek", "verb": "Read", "script": ["code"]},
            {"name": "inspect", "verb": "Read"},
            {"name": "run_js", "verb": "Evaluate", "script": ["code"]},
            {"name": "attach_file", "verb": "Upload", "file": ["path"]},
            {"name": "web-pilot", "discriminator": "action", "cases": {
                "left_click": {"verb": "Click"},
                "key": {"verb": "Key", "text": ["text"]}
            }},
            {"name": "send_protocol", "cdpPassthrough": {"method": ["method"]}}
        ],
        "volatileFields": ["tabId", "timeout"]
    });
    let bytes = serde_json::to_vec(&profile).unwrap();
    compile_browser_driver(&bytes, BrowserDriverOrigin::Contributed, &[]).unwrap()
}

fn project(tool: &str, arguments: Value) -> BrowserProjection {
    project_with(tool, arguments, &BrowserProjectionContext::default())
}

fn project_with(
    tool: &str,
    arguments: Value,
    context: &BrowserProjectionContext<'_>,
) -> BrowserProjection {
    let drivers = [pilot()];
    let call = BrowserToolCallIdentity {
        harness_tool_name: tool,
        ..Default::default()
    };
    let matched = match_browser_driver(&drivers, &call).expect("fixture driver matches");
    let Value::Object(arguments) = arguments else {
        panic!("arguments are an object");
    };
    project_browser_action(&matched, &arguments, context)
}

fn action(projection: BrowserProjection) -> BrowserActionV2 {
    match projection {
        BrowserProjection::Classified(action) => {
            action
                .validate_shape()
                .expect("projection keeps the contract shape");
            *action
        }
        other => panic!("expected an action, got {other:?}"),
    }
}

#[test]
fn navigate_redacts_the_url_and_keeps_query_keys() {
    let action = action(project(
        "mcp__example-pilot__open_page",
        json!({"url": "https://user:pw@Docs.Example.org:8443/guide/intro?token=abc&page=2&empty=#frag", "tabId": 3}),
    ));
    assert_eq!(action.verb, BrowserVerbV1::Navigate);
    assert_eq!(action.intent, BrowserIntentV1::Navigation);
    assert_eq!(action.operation, "open_page");
    assert_eq!(
        action.driver.trust_class,
        BrowserDriverTrustClassV1::Contributed
    );
    assert_eq!(action.driver.kind, BrowserDriverKindV1::Mcp);
    assert_eq!(action.session.profile_mode, BrowserProfileModeV1::Isolated);
    let target = &action.target;
    assert_eq!(
        target.origin.as_deref(),
        Some("https://docs.example.org:8443")
    );
    assert_eq!(target.site_group.as_deref(), Some("example.org"));
    assert_eq!(target.path_prefix.as_deref(), Some("/guide"));
    assert_eq!(
        target.url_redacted.as_deref(),
        Some("https://docs.example.org:8443/guide/intro?token=[redacted]&page=[redacted]&empty=")
    );
    assert!(!target.is_loopback);
    assert_eq!(action.volatile_fields_dropped, vec!["tabId"]);
    assert!(action.sensitive_surface_flags.is_empty());
}

#[test]
fn second_url_pointer_and_loopback_and_guard_origin() {
    let guard = ["http://127.0.0.1:4781"];
    let context = BrowserProjectionContext {
        guard_origins: &guard,
        ..Default::default()
    };
    let action = action(project_with(
        "mcp__example-pilot__open_page",
        json!({"href": "http://127.0.0.1:4781/approvals"}),
        &context,
    ));
    assert!(action.target.is_loopback);
    assert!(action.target.is_guard_origin);
    let dev = action_of(
        "mcp__example-pilot__open_page",
        json!({"url": "http://localhost:3000/"}),
    );
    assert!(dev.target.is_loopback);
    assert!(!dev.target.is_guard_origin);
    assert_eq!(dev.target.site_group.as_deref(), Some("localhost"));
}

#[test]
fn the_target_origin_is_the_host_a_browser_would_load() {
    // A backslash ends the authority in http(s) URLs, so the text after `@` is path, not host.
    let spoofed = action_of(
        "mcp__example-pilot__open_page",
        json!({"url": "https://other.example\\@trusted.example/"}),
    );
    assert_eq!(
        spoofed.target.origin.as_deref(),
        Some("https://other.example")
    );
    let guard = ["http://127.0.0.1:4781"];
    let context = BrowserProjectionContext {
        guard_origins: &guard,
        ..Default::default()
    };
    for url in [
        "http://127.0.0.1:4781\\@elsewhere.example/",
        "http://127.1:4781/",
        "http://2130706433:4781/",
        "http://127.0.0.1:4781\t/approvals",
    ] {
        let action = action(project_with(
            "mcp__example-pilot__open_page",
            json!({"url": url}),
            &context,
        ));
        assert!(action.target.is_guard_origin, "{url}");
        assert!(action.target.is_loopback, "{url}");
    }
    let default_port = action_of(
        "mcp__example-pilot__open_page",
        json!({"url": "https://docs.example.org:443/a"}),
    );
    assert_eq!(
        default_port.target.origin.as_deref(),
        Some("https://docs.example.org")
    );
}

fn action_of(tool: &str, arguments: Value) -> BrowserActionV2 {
    action(project(tool, arguments))
}

#[test]
fn non_http_urls_have_no_origin_and_javascript_urls_flag_script_eval() {
    let file = action_of(
        "mcp__example-pilot__open_page",
        json!({"url": "file:///etc/hosts"}),
    );
    assert_eq!(file.target.origin, None);
    assert_eq!(file.target.url_redacted, None);
    let script = action_of(
        "mcp__example-pilot__open_page",
        json!({"url": " JavaScript:alert(1)"}),
    );
    assert_eq!(
        script.sensitive_surface_flags,
        vec![BrowserSensitiveSurfaceV1::ScriptEval]
    );
    assert_eq!(script.intent, BrowserIntentV1::Privileged);
}

#[test]
fn element_and_input_keep_digests_never_content() {
    let action = action_of(
        "mcp__example-pilot__fill",
        json!({"label": "Password", "value": SECRET_LIKE}),
    );
    let element = action.element.expect("element");
    assert!(element.is_password);
    assert_eq!(element.name_preview.as_deref(), Some("Password"));
    assert_eq!(element.name_digest.as_ref().map(String::len), Some(64));
    let input = action.input.expect("input");
    assert_eq!(input.kind, BrowserInputKindV1::Text);
    assert_eq!(input.length, SECRET_LIKE.len() as u64);
    assert_eq!(
        input.preview_class,
        BrowserInputPreviewClassV1::LooksLikeSecret
    );
    let serialized = serde_json::to_string(&input).unwrap();
    assert!(!serialized.contains(SECRET_LIKE));
    assert_eq!(
        action.sensitive_surface_flags,
        vec![BrowserSensitiveSurfaceV1::PasswordField]
    );
    assert_eq!(action.intent, BrowserIntentV1::Interact);

    let card = action_of(
        "mcp__example-pilot__fill",
        json!({"label": "Card number", "value": "4242 4242 4242 4242"}),
    );
    assert!(card.element.unwrap().is_payment);
    assert_eq!(
        card.input.unwrap().preview_class,
        BrowserInputPreviewClassV1::LooksLikePayment
    );
    let plain = action_of(
        "mcp__example-pilot__fill",
        json!({"label": "Search", "value": "red shoes"}),
    );
    assert_eq!(
        plain.input.unwrap().preview_class,
        BrowserInputPreviewClassV1::Plain
    );
    let empty = action_of(
        "mcp__example-pilot__fill",
        json!({"label": "Search", "value": " "}),
    );
    assert_eq!(
        empty.input.unwrap().preview_class,
        BrowserInputPreviewClassV1::Empty
    );
}

#[test]
fn a_profile_cannot_lower_a_script_tool_to_inspect() {
    let action = action_of(
        "mcp__example-pilot__peek",
        json!({"code": "document.cookie"}),
    );
    assert_eq!(action.verb, BrowserVerbV1::Read);
    assert_eq!(action.intent, BrowserIntentV1::Privileged);
    assert_eq!(action.input.unwrap().kind, BrowserInputKindV1::Script);
    assert!(action
        .sensitive_surface_flags
        .contains(&BrowserSensitiveSurfaceV1::ScriptEval));
}

#[test]
fn native_screen_flags_are_kept_and_raise_the_intent() {
    let screened = [
        BrowserSensitiveSurfaceV1::Cookies,
        BrowserSensitiveSurfaceV1::Cookies,
    ];
    let context = BrowserProjectionContext {
        screened_surfaces: &screened,
        ..Default::default()
    };
    let action = action(project_with(
        "mcp__example-pilot__press",
        json!({"label": "Accept"}),
        &context,
    ));
    assert_eq!(
        action.sensitive_surface_flags,
        vec![BrowserSensitiveSurfaceV1::Cookies]
    );
    assert_eq!(action.intent, BrowserIntentV1::Privileged);
}

#[test]
fn verbs_carry_their_surfaces() {
    let run = action_of("mcp__example-pilot__run_js", json!({"code": "1"}));
    assert_eq!(
        run.sensitive_surface_flags,
        vec![BrowserSensitiveSurfaceV1::ScriptEval]
    );
    let upload = action_of(
        "mcp__example-pilot__attach_file",
        json!({"path": "/tmp/a.txt"}),
    );
    assert_eq!(upload.intent, BrowserIntentV1::Transfer);
    assert_eq!(
        upload.sensitive_surface_flags,
        vec![BrowserSensitiveSurfaceV1::Upload]
    );
    assert_eq!(upload.input.unwrap().kind, BrowserInputKindV1::File);
}

#[test]
fn discriminated_tools_pick_a_case_or_stay_unclassified() {
    let click = action_of("web-pilot", json!({"action": "left_click"}));
    assert_eq!(click.operation, "web-pilot.left_click");
    assert_eq!(click.verb, BrowserVerbV1::Click);
    assert_eq!(click.driver.kind, BrowserDriverKindV1::HarnessTool);
    let key = action_of("web-pilot", json!({"action": "key", "text": "Enter"}));
    assert_eq!(key.input.unwrap().kind, BrowserInputKindV1::Key);
    for arguments in [json!({"action": "drag"}), json!({"action": 3}), json!({})] {
        assert_eq!(
            project("web-pilot", arguments),
            BrowserProjection::Unclassified {
                driver_id: "browser.example-pilot".into(),
                tool_name: "web-pilot".into(),
                reason: BrowserUnclassifiedReason::CaseNotListed,
            }
        );
    }
}

#[test]
fn unlisted_tools_are_unclassified() {
    assert_eq!(
        project("mcp__example-pilot__evaluate", json!({})),
        BrowserProjection::Unclassified {
            driver_id: "browser.example-pilot".into(),
            tool_name: "evaluate".into(),
            reason: BrowserUnclassifiedReason::ToolNotListed,
        }
    );
}

#[test]
fn cdp_passthrough_is_privileged_other_until_classified() {
    let action = action_of(
        "mcp__example-pilot__send_protocol",
        json!({"method": "Network.getCookies"}),
    );
    assert_eq!(action.verb, BrowserVerbV1::Other);
    assert_eq!(action.intent, BrowserIntentV1::Privileged);
    let cdp = action.cdp.expect("cdp detail");
    assert_eq!(
        (cdp.domain.as_str(), cdp.method.as_str()),
        ("Network", "getCookies")
    );
    assert!(!cdp.classified);
    assert_eq!(
        action.sensitive_surface_flags,
        vec![BrowserSensitiveSurfaceV1::Cdp]
    );
}

#[test]
fn the_observed_profile_mode_overrides_the_default() {
    let context = BrowserProjectionContext {
        harness: "claude-code",
        profile_mode: Some(BrowserProfileModeV1::Shared),
        ..Default::default()
    };
    let action = action(project_with(
        "mcp__example-pilot__press",
        json!({"label": "Next"}),
        &context,
    ));
    assert_eq!(action.session.profile_mode, BrowserProfileModeV1::Shared);
    assert_eq!(action.session.harness, "claude-code");
}

#[test]
fn long_case_operations_fall_back_to_the_case() {
    let tool = "t".repeat(64);
    let case = "c".repeat(64);
    assert_eq!(case_operation(&tool, &case), case);
    assert_eq!(case_operation("act", "click"), "act.click");
}

fn screened(tool: &str, arguments: Value, metadata: Value) -> BrowserProjection {
    let drivers = [pilot()];
    let call = BrowserToolCallIdentity {
        harness_tool_name: tool,
        ..Default::default()
    };
    let matched = match_browser_driver(&drivers, &call).expect("fixture driver matches");
    let (Value::Object(arguments), Value::Object(metadata)) = (arguments, metadata) else {
        panic!("objects");
    };
    project_screened_browser_action(
        &matched,
        &arguments,
        &metadata,
        &BrowserProjectionContext::default(),
    )
}

#[test]
fn native_screens_see_script_eval_a_profile_labels_read() {
    let action = action(screened(
        "mcp__example-pilot__inspect",
        json!({"expression": "document.title"}),
        json!({}),
    ));
    assert_eq!(action.verb, BrowserVerbV1::Read);
    assert_eq!(
        action.sensitive_surface_flags,
        vec![BrowserSensitiveSurfaceV1::ScriptEval]
    );
    assert_eq!(action.intent, BrowserIntentV1::Privileged);
}

#[test]
fn native_screens_read_the_tool_description_and_schema() {
    let action = action(screened(
        "mcp__example-pilot__press",
        json!({"label": "Save"}),
        json!({
            "tool_description": "Clicks and returns the page cookies",
            "tool_schema": {"properties": {"storage_key": {"type": "string"}}}
        }),
    ));
    assert!(action
        .sensitive_surface_flags
        .contains(&BrowserSensitiveSurfaceV1::Cookies));
    assert!(action
        .sensitive_surface_flags
        .contains(&BrowserSensitiveSurfaceV1::Storage));
    assert_eq!(action.intent, BrowserIntentV1::Privileged);
}

#[test]
fn a_plain_call_gains_no_screen_flags() {
    let action = action(screened(
        "mcp__example-pilot__press",
        json!({"label": "Next"}),
        json!({"tool_description": "Clicks an element"}),
    ));
    assert!(action.sensitive_surface_flags.is_empty());
    assert_eq!(action.intent, BrowserIntentV1::Interact);
}

#[test]
fn screens_do_not_classify_an_unlisted_tool() {
    assert!(matches!(
        screened(
            "mcp__example-pilot__evaluate",
            json!({"script": "1"}),
            json!({})
        ),
        BrowserProjection::Unclassified {
            reason: BrowserUnclassifiedReason::ToolNotListed,
            ..
        }
    ));
}
