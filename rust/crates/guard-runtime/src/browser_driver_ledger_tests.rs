use rusqlite::Connection;

use super::*;
use crate::browser_session_schema::ensure_browser_session_schema;

fn digest(seed: char) -> String {
    seed.to_string().repeat(64)
}

fn store() -> Connection {
    let connection = Connection::open_in_memory().expect("memory store");
    ensure_browser_session_schema(&connection).expect("schema");
    connection
}

struct Driver {
    profile_id: String,
    profile_digest: String,
    server_name: String,
    server_identity_hash: String,
}

fn driver() -> Driver {
    Driver {
        profile_id: "browser.example-driver".to_owned(),
        profile_digest: digest('a'),
        server_name: "example-browser".to_owned(),
        server_identity_hash: digest('b'),
    }
}

impl Driver {
    fn identity(&self) -> DriverIdentity<'_> {
        DriverIdentity {
            profile_id: &self.profile_id,
            profile_digest: &self.profile_digest,
            mcp_server_name: &self.server_name,
            server_identity_hash: &self.server_identity_hash,
        }
    }
}

fn call<'a>(tool: &'a str, schema: Option<&'a str>) -> DriverToolCall<'a> {
    DriverToolCall {
        tool_name: tool,
        profiled: true,
        schema_hash: schema,
    }
}

fn observe(connection: &Connection, driver: &Driver, call: DriverToolCall<'_>) -> DriverGrantScope {
    observe_driver_tool(connection, &driver.identity(), &call).expect("observe")
}

fn covered(scope: &DriverGrantScope) -> (&str, Option<&str>) {
    match scope {
        DriverGrantScope::Covered {
            driver_identity_hash,
            ended,
        } => (driver_identity_hash.as_str(), ended.as_deref()),
        other => panic!("expected a covered call, got {other:?}"),
    }
}

#[test]
fn a_second_profiled_tool_joins_without_ending_the_grant() {
    let connection = store();
    let driver = driver();
    let schema = digest('1');
    let first = observe(&connection, &driver, call("navigate", Some(&schema)));
    let second = observe(&connection, &driver, call("click", Some(&digest('2'))));
    let (first_hash, first_ended) = covered(&first);
    let (second_hash, second_ended) = covered(&second);
    assert_eq!(
        first_hash, second_hash,
        "one grant covers every profiled tool"
    );
    assert_eq!((first_ended, second_ended), (None, None));
    let again = observe(&connection, &driver, call("navigate", Some(&schema)));
    assert_eq!(covered(&again), (first_hash, None));
}

#[test]
fn a_changed_schema_for_a_seen_tool_ends_every_grant_of_the_driver() {
    let connection = store();
    let driver = driver();
    observe(&connection, &driver, call("navigate", Some(&digest('1'))));
    let before = observe(&connection, &driver, call("click", Some(&digest('2'))));
    let (old_hash, _) = covered(&before);
    let old_hash = old_hash.to_owned();
    let changed = observe(&connection, &driver, call("navigate", Some(&digest('3'))));
    let (new_hash, ended) = covered(&changed);
    assert_ne!(
        new_hash, old_hash,
        "the grants under the old hash no longer match"
    );
    assert_eq!(ended, Some(old_hash.as_str()));
    // The other tool is covered only under the new hash from now on.
    let other = observe(&connection, &driver, call("click", Some(&digest('2'))));
    assert_eq!(covered(&other), (new_hash, None));
}

#[test]
fn an_unprofiled_tool_is_never_covered_and_never_recorded() {
    let connection = store();
    let driver = driver();
    let unprofiled = DriverToolCall {
        tool_name: "evaluate_script",
        profiled: false,
        schema_hash: Some(&digest('1')),
    };
    let scope = observe(&connection, &driver, unprofiled);
    assert_eq!(scope, DriverGrantScope::Unprofiled);
    let tools: i64 = connection
        .query_row(
            "select count(*) from guard_browser_driver_tools",
            [],
            |row| row.get(0),
        )
        .expect("count");
    assert_eq!(tools, 0);
}

#[test]
fn a_call_without_a_schema_hash_matches_by_identity_only_and_writes_nothing() {
    let connection = store();
    let driver = driver();
    let blind = observe(&connection, &driver, call("navigate", None));
    let seen = observe(&connection, &driver, call("navigate", Some(&digest('1'))));
    let (hash, ended) = covered(&seen);
    assert_eq!(
        blind,
        DriverGrantScope::IdentityOnly {
            driver_identity_hash: hash.to_owned()
        }
    );
    assert_eq!(ended, None, "the blind call did not count as seen");
    // A later blind call cannot hide a schema change from the ledger.
    observe(&connection, &driver, call("navigate", None));
    let changed = observe(&connection, &driver, call("navigate", Some(&digest('2'))));
    assert_eq!(covered(&changed).1, Some(hash));
}

#[test]
fn a_changed_driver_identity_starts_a_fresh_ledger() {
    let connection = store();
    let base = driver();
    let base_scope = observe(&connection, &base, call("navigate", Some(&digest('1'))));
    let (base_hash, _) = covered(&base_scope);
    let variants = [
        Driver {
            profile_id: "browser.other-driver".to_owned(),
            ..driver()
        },
        Driver {
            profile_digest: digest('c'),
            ..driver()
        },
        Driver {
            server_name: "other-browser".to_owned(),
            ..driver()
        },
        Driver {
            server_identity_hash: digest('d'),
            ..driver()
        },
    ];
    for variant in &variants {
        // A schema the base ledger never saw is new here, not a change.
        let scope = observe(&connection, variant, call("navigate", Some(&digest('9'))));
        let (hash, ended) = covered(&scope);
        assert_ne!(
            hash, base_hash,
            "a base grant does not cover another identity"
        );
        assert_eq!(ended, None);
    }
    let unchanged = observe(&connection, &base, call("navigate", Some(&digest('1'))));
    assert_eq!(covered(&unchanged), (base_hash, None));
}

#[test]
fn a_full_ledger_ends_the_grants_instead_of_evicting_a_tool() {
    let connection = store();
    let driver = driver();
    let schema = digest('1');
    let names: Vec<String> = (0..MAX_TOOLS_PER_DRIVER)
        .map(|n| format!("tool_{n}"))
        .collect();
    let mut hash = String::new();
    for name in &names {
        let scope = observe(&connection, &driver, call(name, Some(&schema)));
        let (current, ended) = covered(&scope);
        assert_eq!(ended, None);
        hash = current.to_owned();
    }
    let overflow = observe(&connection, &driver, call("one_more", Some(&schema)));
    let (new_hash, ended) = covered(&overflow);
    assert_eq!(ended, Some(hash.as_str()));
    assert_ne!(new_hash, hash);
    let tools: i64 = connection
        .query_row(
            "select count(*) from guard_browser_driver_tools",
            [],
            |row| row.get(0),
        )
        .expect("count");
    assert_eq!(tools, 1, "the ledger starts again with the new tool");
}

#[test]
fn malformed_identities_and_calls_are_rejected_before_any_write() {
    let connection = store();
    let bad_digest = Driver {
        profile_digest: "not-a-digest".to_owned(),
        ..driver()
    };
    let error = observe_driver_tool(&connection, &bad_digest.identity(), &call("navigate", None))
        .expect_err("bad digest");
    assert_eq!(error.to_string(), "invalid_browser_session:profile_digest");
    let driver = driver();
    for bad in [call("", Some(&digest('1'))), call("navigate", Some("ABC"))] {
        observe_driver_tool(&connection, &driver.identity(), &bad).expect_err("bad call");
    }
    let ledgers: i64 = connection
        .query_row(
            "select count(*) from guard_browser_driver_ledgers",
            [],
            |row| row.get(0),
        )
        .expect("count");
    assert_eq!(ledgers, 0);
}

#[test]
fn the_identity_hash_separates_its_parts_and_its_epoch() {
    let base = driver();
    let key = driver_key(&base.identity()).expect("key");
    assert_ne!(driver_identity_hash(&key, 0), driver_identity_hash(&key, 1));
    let shifted = Driver {
        profile_id: "browser.example-driverexample".to_owned(),
        server_name: "-browser".to_owned(),
        ..driver()
    };
    assert_ne!(driver_key(&shifted.identity()).expect("key"), key);
}
