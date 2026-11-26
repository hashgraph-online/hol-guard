use guard_contracts::{
    BrowserDriverTrustClassV1, BrowserIntentV1, BrowserProfileModeV1, BrowserSensitiveSurfaceV1,
};

use serde_json::{json, Value};

use super::*;
use crate::browser_action_project::{
    project_browser_action, BrowserProjection, BrowserProjectionContext,
};
use crate::browser_driver_match::{match_browser_driver, BrowserToolCallIdentity};

// The operation tables these profiles replaced. Every name keeps its intent.
const CHROME_DEVTOOLS_ORACLE: &[(BrowserIntentV1, &[&str])] = &[
    (
        BrowserIntentV1::Navigation,
        &[
            "close_page",
            "go_back",
            "go_forward",
            "list_pages",
            "navigate_page",
            "new_page",
            "reload_page",
            "select_page",
            "wait_for",
        ],
    ),
    (
        BrowserIntentV1::Inspect,
        &[
            "accessibility_snapshot",
            "get_console",
            "get_console_message",
            "get_dom",
            "get_html",
            "get_network",
            "get_performance",
            "get_snapshot",
            "lighthouse_audit",
            "list_console_messages",
            "list_network_requests",
            "list_resources",
            "performance_analyze_insight",
            "performance_start_trace",
            "performance_stop_trace",
            "performance_trace",
            "read_console",
            "read_network",
            "take_screenshot",
            "take_snapshot",
        ],
    ),
    (
        BrowserIntentV1::Interact,
        &[
            "accept_dialog",
            "click",
            "dismiss_dialog",
            "drag",
            "emulate",
            "fill_form",
            "fill_input",
            "focus_element",
            "handle_dialog",
            "hover",
            "press_key",
            "resize_page",
            "scroll",
            "select_dropdown",
            "submit_form",
            "type_text",
        ],
    ),
    (
        BrowserIntentV1::Transfer,
        &[
            "download_file",
            "drag_drop_file",
            "read_clipboard",
            "save_file",
            "upload_file",
            "write_clipboard",
        ],
    ),
    (
        BrowserIntentV1::Privileged,
        &[
            "clear_storage",
            "evaluate_script",
            "get_auth_headers",
            "get_cookies",
            "get_network_request",
            "get_storage",
            "manage_extension",
            "manage_profile",
            "manage_session",
            "mock_network",
            "network_intercept",
            "raw_cdp",
            "read_cookies",
            "read_storage",
            "set_cookies",
            "set_network_intercept",
            "set_storage",
        ],
    ),
];

const PLAYWRIGHT_ORACLE: &[(BrowserIntentV1, &[&str])] = &[
    (
        BrowserIntentV1::Navigation,
        &[
            "browser_close",
            "browser_close_context",
            "browser_close_page",
            "browser_list_pages",
            "browser_navigate",
            "browser_navigate_back",
            "browser_navigate_forward",
            "browser_new_context",
            "browser_new_page",
            "browser_reload",
            "browser_select_page",
            "browser_wait_for_load_state",
            "browser_wait_for_url",
        ],
    ),
    (
        BrowserIntentV1::Inspect,
        &[
            "browser_accessibility_snapshot",
            "browser_console_messages",
            "browser_get_dom",
            "browser_get_html",
            "browser_network_requests",
            "browser_performance",
            "browser_screenshot",
            "browser_snapshot",
        ],
    ),
    (
        BrowserIntentV1::Interact,
        &[
            "browser_click",
            "browser_dialog_accept",
            "browser_dialog_dismiss",
            "browser_drag",
            "browser_fill",
            "browser_focus",
            "browser_hover",
            "browser_press_key",
            "browser_scroll",
            "browser_select_option",
            "browser_select_text",
            "browser_submit_form",
            "browser_type",
        ],
    ),
    (
        BrowserIntentV1::Transfer,
        &[
            "browser_clipboard_read",
            "browser_clipboard_write",
            "browser_download",
            "browser_drag_and_drop_file",
            "browser_file_upload",
            "browser_pdf_save",
        ],
    ),
    (
        BrowserIntentV1::Privileged,
        &[
            "browser_auth_headers",
            "browser_context_manage",
            "browser_cookies_clear",
            "browser_cookies_get",
            "browser_cookies_set",
            "browser_evaluate",
            "browser_execute_script",
            "browser_network_intercept",
            "browser_profile_manage",
            "browser_raw_cdp",
            "browser_route_intercept",
            "browser_session_manage",
            "browser_storage_clear",
            "browser_storage_get",
            "browser_storage_set",
        ],
    ),
];

fn oracle_names(oracle: &[(BrowserIntentV1, &[&str])]) -> Vec<String> {
    let mut names: Vec<String> = oracle
        .iter()
        .flat_map(|(_, names)| names.iter().map(|name| (*name).to_owned()))
        .collect();
    names.sort();
    names
}

#[test]
fn first_party_profiles_compile_as_first_party() {
    let drivers = compile_first_party().expect("first-party profiles compile");
    assert_eq!(drivers.len(), 5);
    for driver in &drivers {
        assert_eq!(driver.trust_class, BrowserDriverTrustClassV1::FirstParty);
        assert!(driver.publisher_verified);
    }
    assert_eq!(first_party_browser_drivers().len(), 5);
}

#[test]
fn every_replaced_table_entry_keeps_its_intent() {
    for (driver_id, oracle) in [
        (CHROME_DEVTOOLS_DRIVER_ID, CHROME_DEVTOOLS_ORACLE),
        (PLAYWRIGHT_DRIVER_ID, PLAYWRIGHT_ORACLE),
    ] {
        for (intent, names) in oracle {
            for name in *names {
                assert_eq!(
                    first_party_operation_intent(driver_id, name),
                    Some(*intent),
                    "{driver_id} {name}"
                );
            }
        }
        let driver = first_party_browser_drivers()
            .iter()
            .find(|driver| driver.id == driver_id)
            .unwrap();
        let listed: Vec<String> = driver.tools.keys().cloned().collect();
        assert_eq!(
            listed,
            oracle_names(oracle),
            "{driver_id} lists exactly the old tools"
        );
    }
}

#[test]
fn the_puppeteer_profile_lists_the_reference_server_tools() {
    use BrowserIntentV1::*;
    for (name, intent) in [
        ("puppeteer_click", Interact),
        ("puppeteer_connect_active_tab", Privileged),
        ("puppeteer_evaluate", Privileged),
        ("puppeteer_fill", Interact),
        ("puppeteer_hover", Interact),
        ("puppeteer_navigate", Navigation),
        ("puppeteer_screenshot", Inspect),
        ("puppeteer_select", Interact),
    ] {
        assert_eq!(
            first_party_operation_intent(PUPPETEER_DRIVER_ID, name),
            Some(intent),
            "{name}"
        );
    }
    assert_eq!(
        first_party_operation_intent(PUPPETEER_DRIVER_ID, "browser_navigate"),
        None
    );
}

#[test]
fn the_browsermcp_profile_lists_the_script_tool_and_the_legacy_tools() {
    use BrowserIntentV1::*;
    for (name, intent) in [
        ("browser", Privileged),
        ("browser_click", Interact),
        ("browser_drag", Interact),
        ("browser_get_console_logs", Inspect),
        ("browser_go_back", Navigation),
        ("browser_go_forward", Navigation),
        ("browser_hover", Interact),
        ("browser_navigate", Navigation),
        ("browser_press_key", Interact),
        ("browser_screenshot", Inspect),
        ("browser_select_option", Interact),
        ("browser_snapshot", Inspect),
        ("browser_type", Interact),
        ("browser_wait", Inspect),
    ] {
        assert_eq!(
            first_party_operation_intent(BROWSERMCP_DRIVER_ID, name),
            Some(intent),
            "{name}"
        );
    }
}

#[test]
fn unlisted_operations_and_unknown_drivers_have_no_intent() {
    assert_eq!(
        first_party_operation_intent(PLAYWRIGHT_DRIVER_ID, "navigate_page"),
        None
    );
    assert_eq!(
        first_party_operation_intent(CHROME_DEVTOOLS_DRIVER_ID, "browser_navigate"),
        None
    );
    assert_eq!(
        first_party_operation_intent("browser.example-pilot", "click"),
        None
    );
}

#[test]
fn profile_mode_reads_the_profile_flag_lists_in_priority_order() {
    let mode = |args: &[&str]| first_party_profile_mode(args.iter().copied());
    assert_eq!(mode(&[]), BrowserProfileModeV1::Unknown);
    assert_eq!(mode(&["--headless"]), BrowserProfileModeV1::Unknown);
    assert_eq!(mode(&["--isolated"]), BrowserProfileModeV1::Isolated);
    assert_eq!(
        mode(&["--user-data-dir=/tmp/p", "--isolated-context"]),
        BrowserProfileModeV1::Isolated
    );
    assert_eq!(
        mode(&["--user-data-dir=/tmp/p", "--remote-debugging-port=9222"]),
        BrowserProfileModeV1::RemoteDebugging
    );
    assert_eq!(
        mode(&["--ws-endpoint", "ws://x"]),
        BrowserProfileModeV1::RemoteDebugging
    );
    assert_eq!(
        mode(&["--storage-state=s.json"]),
        BrowserProfileModeV1::Dedicated
    );
    assert_eq!(mode(&["--persistent"]), BrowserProfileModeV1::Dedicated);
    assert_eq!(mode(&["--no-isolated"]), BrowserProfileModeV1::Shared);
    assert_eq!(mode(&["--shared"]), BrowserProfileModeV1::Shared);
}

fn computer_use(harness_tool_name: &str, arguments: Value) -> BrowserProjection {
    let call = BrowserToolCallIdentity {
        harness_tool_name,
        ..Default::default()
    };
    let matched = match_browser_driver(first_party_browser_drivers(), &call).expect("matched");
    assert_eq!(matched.driver.id, COMPUTER_USE_DRIVER_ID);
    let Value::Object(arguments) = arguments else {
        panic!("arguments are an object");
    };
    project_browser_action(&matched, &arguments, &BrowserProjectionContext::default())
}

#[test]
fn computer_use_maps_each_action_and_acts_in_the_shared_session() {
    use guard_contracts::BrowserVerbV1::*;
    for (tool, action, verb) in [
        ("computer", "get_screenshot", Screenshot),
        ("computer", "screenshot", Screenshot),
        ("computer", "left_click", Click),
        ("computer", "mouse_move", Click),
        ("computer", "type", Type),
        ("computer", "key", Key),
        ("computer", "scroll", Scroll),
        ("mcp__computer-use__computer", "double_click", Click),
    ] {
        let BrowserProjection::Classified(projected) =
            computer_use(tool, json!({"action": action, "text": "x"}))
        else {
            panic!("{action} is classified");
        };
        assert_eq!(projected.verb, verb, "{action}");
        assert_eq!(
            projected.session.profile_mode,
            BrowserProfileModeV1::Shared,
            "{action}"
        );
    }
}

#[test]
fn an_unlisted_computer_use_action_stays_unclassified() {
    for arguments in [json!({"action": "open_application"}), json!({})] {
        assert!(matches!(
            computer_use("computer", arguments),
            BrowserProjection::Unclassified { .. }
        ));
    }
}

#[test]
fn a_drag_screens_its_destination_as_well_as_its_source() {
    let call = BrowserToolCallIdentity {
        harness_tool_name: "mcp__browsermcp__browser_drag",
        ..Default::default()
    };
    let matched = match_browser_driver(first_party_browser_drivers(), &call).expect("matched");
    assert_eq!(matched.driver.id, BROWSERMCP_DRIVER_ID);
    let project = |arguments: Value| {
        let Value::Object(arguments) = arguments else {
            panic!("arguments are an object");
        };
        let BrowserProjection::Classified(projected) =
            project_browser_action(&matched, &arguments, &BrowserProjectionContext::default())
        else {
            panic!("drag is classified");
        };
        projected
    };
    let password = project(json!({"startElement": "Account name", "endElement": "Password"}));
    assert!(password
        .sensitive_surface_flags
        .contains(&BrowserSensitiveSurfaceV1::PasswordField));
    let plain = project(json!({"startElement": "Card one", "endElement": "Done column"}));
    assert!(!plain
        .sensitive_surface_flags
        .contains(&BrowserSensitiveSurfaceV1::PasswordField));
}
