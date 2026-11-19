//! Exit counting at the edge of the report window.

use serde_json::json;

use super::tests::{event, private_home, report, NOW};

#[test]
fn a_run_retired_before_the_window_is_not_an_exit_inside_it() {
    let home = private_home();
    let home = home.path();
    let since = NOW - 7 * 86_400 * 1_000_000_000;
    // Retired just before the window opens; its own exit lands just inside.
    event(home, since - 20, 301, "published", None);
    event(
        home,
        since - 10,
        301,
        "retirement_requested",
        Some("requested_retire"),
    );
    event(home, since + 10, 301, "exiting", Some("signal_term"));
    // A run that ends inside the window still counts.
    event(home, since + 20, 302, "published", None);
    event(home, since + 30, 302, "exiting", Some("signal_term"));

    assert_eq!(
        report(home, json!({"days": 7}))["daemon_exits"],
        json!({"total": 1, "by_cause": {"exiting:signal_term": 1}})
    );
}
