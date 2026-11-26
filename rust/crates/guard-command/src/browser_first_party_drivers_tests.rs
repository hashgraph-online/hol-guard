use guard_contracts::{BrowserDriverTrustClassV1, BrowserIntentV1, BrowserProfileModeV1};

use super::*;

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
    assert_eq!(drivers.len(), 2);
    for driver in &drivers {
        assert_eq!(driver.trust_class, BrowserDriverTrustClassV1::FirstParty);
        assert!(driver.publisher_verified);
    }
    assert_eq!(first_party_browser_drivers().len(), 2);
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
