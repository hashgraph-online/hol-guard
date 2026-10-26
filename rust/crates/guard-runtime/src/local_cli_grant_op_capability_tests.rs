//! Grant capabilities in the `LocalCliGrantDecide` answer.

use super::*;

const CAPABILITY_TABLE: &str = "
create table local_cli_grant_capability (
    cli_id text not null,
    capability text not null,
    state text not null,
    revision integer not null,
    updated_at text not null,
    primary key (cli_id, capability)
);
";

impl Fixture {
    fn capability(&self, identity: &Identity, name: &str, state: &str) {
        self.connection
            .execute(
                "insert into local_cli_grant_capability values \
                 (?1, ?2, ?3, 1, '2026-01-01T00:00:00Z')",
                params![identity.cli_id, name, state],
            )
            .unwrap();
    }

    fn with_capabilities(identity: &Identity) -> Self {
        let fixture = Self::new();
        fixture.connection.execute_batch(CAPABILITY_TABLE).unwrap();
        fixture.observe(identity, "cli");
        fixture.capability(identity, "state-dir-read", "on");
        fixture.capability(identity, "loopback-network", "on");
        fixture.capability(identity, "state-dir-write", "off");
        fixture.capability(identity, "raw-network", "on");
        fixture
    }
}

fn capabilities(fixture: &Fixture, identity: &Identity) -> Value {
    payload(fixture, identity, "review", None)["capabilities"].clone()
}

#[test]
fn allowed_cli_reports_sorted_enabled_capabilities() {
    let identity = script();
    let fixture = Fixture::with_capabilities(&identity);
    fixture.grant(&identity, "allowed", None);
    let found = payload(&fixture, &identity, "review", None);
    assert_eq!(found["state"], "allowed");
    assert_eq!(
        found["capabilities"],
        serde_json::json!(["loopback-network", "state-dir-read"])
    );
    let keys: Vec<&str> = found
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys.len(), 4, "{found}");
}

#[test]
fn every_answer_carries_an_empty_list_without_enabled_capabilities() {
    let identity = script();
    let fixture = Fixture::new();
    assert_eq!(capabilities(&fixture, &identity), serde_json::json!([]));
    fixture.grant(&identity, "allowed", None);
    // No capability table yet: an older store reads as all off.
    assert_eq!(capabilities(&fixture, &identity), serde_json::json!([]));
}

#[test]
fn only_an_allowed_cli_grant_reports_capabilities() {
    let identity = script();
    let blocked = Fixture::with_capabilities(&identity);
    blocked.grant(&identity, "blocked", None);
    assert_eq!(capabilities(&blocked, &identity), serde_json::json!([]));

    let stale = Fixture::with_capabilities(&identity);
    stale.grant(&identity, "allowed", Some(&"0".repeat(64)));
    assert_eq!(state(&stale, &identity, "review", None), "none");
    assert_eq!(capabilities(&stale, &identity), serde_json::json!([]));

    let unrefined = Fixture::with_capabilities(&identity);
    unrefined.grant(&identity, "allowed", None);
    let found = payload(&unrefined, &identity, "block", None);
    assert_eq!(found["state"], "none");
    assert_eq!(found["capabilities"], serde_json::json!([]));
}

#[test]
fn other_surfaces_never_report_capabilities() {
    let identity = package_json();
    let fixture = Fixture::new();
    fixture.connection.execute_batch(CAPABILITY_TABLE).unwrap();
    fixture.observe(&identity, "package-scripts");
    fixture.capability(&identity, "loopback-network", "on");
    fixture.grant(&identity, "allowed", None);
    let found = payload(&fixture, &identity, "review", None);
    assert_eq!(found["state"], "allowed");
    assert_eq!(found["capabilities"], serde_json::json!([]));
}

#[test]
fn a_capability_without_a_cli_observation_reports_nothing() {
    // A partial salvage can restore the grant and capability rows but not the
    // observation they were written against; without it nothing is widened.
    let identity = script();
    let fixture = Fixture::new();
    fixture.connection.execute_batch(CAPABILITY_TABLE).unwrap();
    fixture.capability(&identity, "loopback-network", "on");
    fixture.grant(&identity, "allowed", None);
    let found = payload(&fixture, &identity, "review", None);
    assert_eq!(found["state"], "allowed");
    assert_eq!(found["capabilities"], serde_json::json!([]));
}

#[test]
fn allowed_launch_answer_carries_capabilities() {
    let identity = script();
    let fixture = Fixture::with_capabilities(&identity);
    fixture.grant(&identity, "allowed", None);
    let answer = crate::local_cli_grant_op::decide_allowed_launch(
        &fixture.home.to_string_lossy(),
        &identity.source,
        None,
    )
    .unwrap();
    assert_eq!(answer["state"], "allowed");
    assert_eq!(
        answer["capabilities"],
        serde_json::json!(["loopback-network", "state-dir-read"])
    );
}
