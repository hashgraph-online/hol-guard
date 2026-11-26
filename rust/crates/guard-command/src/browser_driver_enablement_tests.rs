use serde_json::json;

use super::*;
use crate::browser_driver_compile::{compile_browser_driver, BrowserDriverOrigin};
use crate::browser_driver_match::{match_browser_driver, BrowserToolCallIdentity};

const PILOT: &str = "browser.example-pilot";
const FIRST: &str = "browser.example-first";

fn driver(id: &str, origin: BrowserDriverOrigin) -> CompiledBrowserDriverV1 {
    let profile = json!({
        "schemaVersion": "guard.browser-driver.v1",
        "id": id,
        "name": "Example browser tools",
        "publisher": {"name": "Example Org", "verified": false},
        "match": {
            "mcpServerNames": [],
            "packages": [],
            "toolNamespaces": [format!("mcp__{}__", id.trim_start_matches("browser."))],
            "harnessTools": []
        },
        "profileMode": {"default": "unknown"},
        "tools": [{"name": "open_page", "verb": "Navigate", "url": ["url"]}]
    });
    compile_browser_driver(&serde_json::to_vec(&profile).unwrap(), origin, &[]).unwrap()
}

fn control(layer: ControlLayerKind, id: &str, state: ControlState) -> BrowserDriverControl {
    BrowserDriverControl {
        layer,
        driver_id: id.to_owned(),
        state,
    }
}

#[test]
fn a_contributed_profile_is_inert_until_a_local_admin_enable() {
    let pilot = driver(PILOT, BrowserDriverOrigin::Contributed);
    assert!(!browser_driver_enabled(&pilot, &[]));
    let cloud = [control(
        ControlLayerKind::SignedCloud,
        PILOT,
        ControlState::Enabled,
    )];
    assert!(!browser_driver_enabled(&pilot, &cloud));
    let other = [control(
        ControlLayerKind::LocalAdmin,
        FIRST,
        ControlState::Enabled,
    )];
    assert!(!browser_driver_enabled(&pilot, &other));
    let local = [control(
        ControlLayerKind::LocalAdmin,
        PILOT,
        ControlState::Enabled,
    )];
    assert!(browser_driver_enabled(&pilot, &local));
}

#[test]
fn any_disable_wins() {
    let pilot = driver(PILOT, BrowserDriverOrigin::Contributed);
    let controls = [
        control(ControlLayerKind::LocalAdmin, PILOT, ControlState::Enabled),
        control(ControlLayerKind::SignedCloud, PILOT, ControlState::Disabled),
    ];
    assert!(!browser_driver_enabled(&pilot, &controls));
    let first = driver(FIRST, BrowserDriverOrigin::FirstParty);
    assert!(browser_driver_enabled(&first, &[]));
    let off = [control(
        ControlLayerKind::LocalAdmin,
        FIRST,
        ControlState::Disabled,
    )];
    assert!(!browser_driver_enabled(&first, &off));
}

#[test]
fn matching_only_sees_enabled_profiles() {
    let table = [
        driver(PILOT, BrowserDriverOrigin::Contributed),
        driver(FIRST, BrowserDriverOrigin::FirstParty),
    ];
    let call = BrowserToolCallIdentity {
        harness_tool_name: "mcp__example-pilot__open_page",
        ..Default::default()
    };
    let inert = enabled_browser_drivers(&table, &[]);
    assert_eq!(inert.len(), 1);
    assert!(match_browser_driver(&inert, &call).is_none());
    let enabled = enabled_browser_drivers(
        &table,
        &[control(
            ControlLayerKind::LocalAdmin,
            PILOT,
            ControlState::Enabled,
        )],
    );
    assert_eq!(
        match_browser_driver(&enabled, &call).map(|found| found.driver.id.as_str()),
        Some(PILOT)
    );
}

#[test]
fn a_device_custom_grant_decides_before_any_profile() {
    assert_eq!(
        browser_decision_source(true),
        BrowserDecisionSource::DeviceCustomGrant
    );
    assert_eq!(
        browser_decision_source(false),
        BrowserDecisionSource::DriverProfile
    );
}
