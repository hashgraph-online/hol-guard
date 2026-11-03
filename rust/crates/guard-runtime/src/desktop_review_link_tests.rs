//! The Desktop link a paused review offers when HOL Guard Desktop opens it.

use super::*;

const REQUEST_ID: &str = "2c79d707370b453886adf5b2e7e622ec";

fn approval_url() -> String {
    format!("http://127.0.0.1:5474/requests/{REQUEST_ID}")
}

fn signed_reason() -> String {
    format!(
        "Guard paused this command. {OPEN_GUARD} {}#guard-token=gld1.payload.signature.",
        approval_url()
    )
}

#[cfg(unix)]
mod with_marker {
    use super::*;

    use serde_json::json;

    use crate::claude_hook_bridge_fixture::{write_private, GuardHome};

    fn home_with_marker(label: &str, marker: serde_json::Value) -> GuardHome {
        let home = GuardHome::new(label);
        write_private(&home.home.join(MARKER_FILE), &marker.to_string());
        home
    }

    fn installed_marker(home: &GuardHome) -> serde_json::Value {
        json!({
            "version": 1,
            "scheme": "hol-guard-desktop",
            "routes": ["requests"],
            "app_path": home.home.to_string_lossy(),
        })
    }

    #[test]
    fn a_desktop_user_gets_the_desktop_link_first_and_keeps_the_browser_link() {
        let home = GuardHome::new("desktop-link-installed");
        write_private(
            &home.home.join(MARKER_FILE),
            &installed_marker(&home).to_string(),
        );
        let linked = with_desktop_link(signed_reason(), &home.home, &approval_url());
        assert_eq!(
            linked,
            format!(
                "Guard paused this command. {OPEN_GUARD} hol-guard-desktop://requests/{REQUEST_ID} \
                 (HOL Guard Desktop), or in a browser: {}#guard-token=gld1.payload.signature.",
                approval_url()
            )
        );
        assert_eq!(
            with_desktop_link(linked.clone(), &home.home, &approval_url()),
            linked,
            "a reason that already names the Desktop link is not linked twice"
        );
    }

    #[test]
    fn a_marker_whose_app_is_gone_offers_no_desktop_link() {
        let home = home_with_marker(
            "desktop-link-uninstalled",
            json!({
                "version": 1,
                "scheme": "hol-guard-desktop",
                "routes": ["requests"],
                "app_path": "/nonexistent/HOL Guard.app",
            }),
        );
        assert_eq!(
            with_desktop_link(signed_reason(), &home.home, &approval_url()),
            signed_reason()
        );
    }

    #[test]
    fn a_marker_without_the_requests_route_or_scheme_offers_nothing() {
        for (label, change) in [
            ("routes", json!({"routes": ["claim"]})),
            ("scheme", json!({"scheme": "https"})),
            ("version", json!({"version": 2})),
        ] {
            let home = GuardHome::new(&format!("desktop-link-{label}"));
            let mut marker = installed_marker(&home);
            for (key, value) in change.as_object().unwrap() {
                marker[key] = value.clone();
            }
            write_private(&home.home.join(MARKER_FILE), &marker.to_string());
            assert!(!desktop_opens_requests(&home.home), "{label}");
        }
    }

    #[test]
    fn a_reason_with_no_open_step_is_left_alone() {
        let home = GuardHome::new("desktop-link-unlinked");
        write_private(
            &home.home.join(MARKER_FILE),
            &installed_marker(&home).to_string(),
        );
        let reason = "Set up the connector in the HOL Guard inbox.".to_owned();
        assert_eq!(
            with_desktop_link(reason.clone(), &home.home, &approval_url()),
            reason
        );
    }
}

#[test]
fn no_marker_leaves_the_reason_unchanged() {
    let home = std::env::temp_dir().join("hol-guard-desktop-link-absent-home");
    assert!(!desktop_opens_requests(&home));
    assert_eq!(
        with_desktop_link(signed_reason(), &home, &approval_url()),
        signed_reason()
    );
}

#[test]
fn only_a_queue_shaped_request_id_becomes_a_desktop_link() {
    assert_eq!(approval_request_id(&approval_url()), Some(REQUEST_ID));
    assert_eq!(
        approval_request_id(&format!("{}#guard-token=gld1.x.y", approval_url())),
        Some(REQUEST_ID)
    );
    for url in [
        "http://127.0.0.1:5474/approvals",
        "http://127.0.0.1:5474/requests/",
        "http://127.0.0.1:5474/requests/2C79D707370B453886ADF5B2E7E622EC",
        "http://127.0.0.1:5474/requests/2c79d707370b453886adf5b2e7e622ec/../x",
        "http://127.0.0.1:5474/requests/not-a-request-id",
    ] {
        assert_eq!(approval_request_id(url), None, "{url}");
    }
    assert_eq!(
        desktop_request_url(REQUEST_ID),
        format!("hol-guard-desktop://requests/{REQUEST_ID}")
    );
}
