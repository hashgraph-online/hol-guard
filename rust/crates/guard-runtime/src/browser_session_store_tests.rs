use guard_contracts::BrowserProfileModeV1;
use rusqlite::Connection;

use super::*;

const NOW: i64 = 1_800_000_000;

fn digest(seed: char) -> String {
    seed.to_string().repeat(64)
}

fn store() -> Connection {
    let connection = Connection::open_in_memory().expect("memory store");
    ensure_browser_session_schema(&connection).expect("schema");
    connection
}

struct Sighting {
    session: String,
    harness_session: String,
    driver: String,
    mode: BrowserProfileModeV1,
    origin: Option<&'static str>,
    port: Option<u16>,
    now: i64,
}

fn sighting(session: char) -> Sighting {
    Sighting {
        session: digest(session),
        harness_session: digest('1'),
        driver: digest('d'),
        mode: BrowserProfileModeV1::Isolated,
        origin: None,
        port: None,
        now: NOW,
    }
}

fn record(connection: &Connection, sighting: &Sighting) -> BrowserSessionResult<()> {
    record_browser_session(
        connection,
        &BrowserSessionObservation {
            session_digest: &sighting.session,
            harness: "claude-code",
            harness_session_digest: &sighting.harness_session,
            driver_identity_hash: &sighting.driver,
            profile_mode: sighting.mode,
            origin: sighting.origin,
            debugging_port: sighting.port,
            now_unix: sighting.now,
        },
    )
}

#[test]
fn the_schema_is_idempotent_and_rejects_a_drifted_table() {
    let connection = store();
    ensure_browser_session_schema(&connection).expect("second pass");

    let drifted = Connection::open_in_memory().expect("memory store");
    drifted
        .execute_batch("create table guard_browser_sessions (session_digest text primary key)")
        .expect("drifted table");
    ensure_browser_session_schema(&drifted).expect_err("drift is rejected");
    let ports_table: i64 = drifted
        .query_row(
            "select count(*) from sqlite_master where name = 'guard_browser_session_ports'",
            [],
            |row| row.get(0),
        )
        .expect("count");
    assert_eq!(ports_table, 0, "a rejected pass leaves the store as it was");
}

#[test]
fn a_new_session_records_every_field() {
    let connection = store();
    let mut first = sighting('a');
    first.mode = BrowserProfileModeV1::RemoteDebugging;
    first.origin = Some("http://localhost:4173");
    first.port = Some(9222);
    record(&connection, &first).expect("recorded");

    let session = browser_session(&connection, &first.session, NOW)
        .expect("read")
        .expect("live");
    assert_eq!(session.harness, "claude-code");
    assert_eq!(session.harness_session_digest, digest('1'));
    assert_eq!(session.driver_identity_hash, digest('d'));
    assert_eq!(session.profile_mode, BrowserProfileModeV1::RemoteDebugging);
    assert_eq!(session.first_seen_unix, NOW);
    assert_eq!(session.last_seen_unix, NOW);
    assert_eq!(
        session.current_origin.as_deref(),
        Some("http://localhost:4173")
    );
    assert_eq!(session.debugging_ports, vec![9222]);
}

#[test]
fn a_later_sighting_only_tightens_the_profile_mode_and_adds_ports() {
    let connection = store();
    let mut first = sighting('a');
    first.mode = BrowserProfileModeV1::Shared;
    first.origin = Some("https://example.test");
    first.port = Some(9222);
    record(&connection, &first).expect("first");

    let mut second = sighting('a');
    second.mode = BrowserProfileModeV1::Isolated;
    second.port = Some(9333);
    second.now = NOW + 30;
    record(&connection, &second).expect("second");

    let session = browser_session(&connection, &first.session, NOW + 30)
        .expect("read")
        .expect("live");
    assert_eq!(session.profile_mode, BrowserProfileModeV1::Shared);
    assert_eq!(session.first_seen_unix, NOW);
    assert_eq!(session.last_seen_unix, NOW + 30);
    assert_eq!(
        session.current_origin.as_deref(),
        Some("https://example.test")
    );
    assert_eq!(session.debugging_ports, vec![9222, 9333]);

    let mut third = sighting('a');
    third.mode = BrowserProfileModeV1::RemoteDebugging;
    third.origin = Some("https://other.example.test");
    third.now = NOW + 60;
    record(&connection, &third).expect("third");
    let session = browser_session(&connection, &first.session, NOW + 60)
        .expect("read")
        .expect("live");
    assert_eq!(session.profile_mode, BrowserProfileModeV1::RemoteDebugging);
    assert_eq!(
        session.current_origin.as_deref(),
        Some("https://other.example.test")
    );
}

#[test]
fn a_session_digest_cannot_move_to_another_harness_session_or_driver() {
    let connection = store();
    record(&connection, &sighting('a')).expect("first");

    let mut moved = sighting('a');
    moved.harness_session = digest('2');
    assert!(matches!(
        record(&connection, &moved),
        Err(BrowserSessionStoreError::Invalid("session_identity"))
    ));

    let mut redriven = sighting('a');
    redriven.driver = digest('e');
    assert!(matches!(
        record(&connection, &redriven),
        Err(BrowserSessionStoreError::Invalid("session_identity"))
    ));
}

/// One change to a sighting, named for the field it breaks.
type Mutation = fn(&mut Sighting);

#[test]
fn malformed_observations_are_rejected_before_any_write() {
    let connection = store();
    let cases: [(&str, Mutation); 6] = [
        ("session_digest", |s| s.session = "ABC".to_owned()),
        ("harness_session_digest", |s| {
            s.harness_session = digest('g')
        }),
        ("driver_identity_hash", |s| s.driver = String::new()),
        ("origin", |s| s.origin = Some("https://example.test/path")),
        ("debugging_port", |s| s.port = Some(0)),
        ("now_unix", |s| s.now = 0),
    ];
    for (reason, mutate) in cases {
        let mut bad = sighting('a');
        mutate(&mut bad);
        match record(&connection, &bad) {
            Err(BrowserSessionStoreError::Invalid(actual)) => assert_eq!(actual, reason),
            other => panic!("{reason}: {other:?}"),
        }
    }
    let rows: i64 = connection
        .query_row("select count(*) from guard_browser_sessions", [], |row| {
            row.get(0)
        })
        .expect("count");
    assert_eq!(rows, 0);
}

#[test]
fn known_ports_come_only_from_live_sessions_of_the_same_harness_session() {
    let connection = store();
    let mut launch = sighting('a');
    launch.port = Some(9222);
    record(&connection, &launch).expect("launch");

    let mut other_session = sighting('b');
    other_session.harness_session = digest('2');
    other_session.port = Some(9333);
    record(&connection, &other_session).expect("other harness session");

    let mut stale = sighting('c');
    stale.port = Some(9444);
    stale.now = NOW - BROWSER_SESSION_IDLE_SECONDS - 1;
    record(&connection, &stale).expect("stale");

    assert_eq!(
        known_debugging_ports(&connection, "claude-code", &digest('1'), NOW).expect("ports"),
        vec![9222]
    );
    assert_eq!(
        known_debugging_ports(&connection, "codex", &digest('1'), NOW).expect("ports"),
        Vec::<u16>::new()
    );
    assert!(browser_session(&connection, &digest('c'), NOW)
        .expect("read")
        .is_none());
}

#[test]
fn ports_per_session_are_bounded() {
    let connection = store();
    for offset in 0..(MAX_DEBUGGING_PORTS_PER_SESSION as u16 + 4) {
        let mut launch = sighting('a');
        launch.port = Some(9000 + offset);
        record(&connection, &launch).expect("launch");
    }
    let session = browser_session(&connection, &digest('a'), NOW)
        .expect("read")
        .expect("live");
    assert_eq!(
        session.debugging_ports.len(),
        MAX_DEBUGGING_PORTS_PER_SESSION
    );
}

#[test]
fn sessions_expire_with_the_harness_session_or_when_idle() {
    let connection = store();
    let mut first = sighting('a');
    first.port = Some(9222);
    record(&connection, &first).expect("first");
    let mut other = sighting('b');
    other.harness_session = digest('2');
    other.now = NOW - BROWSER_SESSION_IDLE_SECONDS - 10;
    record(&connection, &other).expect("other");

    assert_eq!(
        expire_harness_session(&connection, "claude-code", &digest('1')).expect("expired"),
        1
    );
    assert!(browser_session(&connection, &digest('a'), NOW)
        .expect("read")
        .is_none());
    let orphan_ports: i64 = connection
        .query_row(
            "select count(*) from guard_browser_session_ports",
            [],
            |row| row.get(0),
        )
        .expect("count");
    assert_eq!(orphan_ports, 0);

    assert_eq!(
        prune_idle_browser_sessions(&connection, NOW).expect("pruned"),
        1
    );
    let rows: i64 = connection
        .query_row("select count(*) from guard_browser_sessions", [], |row| {
            row.get(0)
        })
        .expect("count");
    assert_eq!(rows, 0);
}

#[test]
fn a_harness_session_keeps_only_its_most_recent_sessions() {
    let connection = store();
    for index in 0..(MAX_SESSIONS_PER_HARNESS_SESSION + 2) {
        let mut launch = sighting('a');
        launch.session = format!("{index:064x}");
        launch.now = NOW + index;
        record(&connection, &launch).expect("launch");
    }
    let rows: i64 = connection
        .query_row("select count(*) from guard_browser_sessions", [], |row| {
            row.get(0)
        })
        .expect("count");
    assert_eq!(rows, MAX_SESSIONS_PER_HARNESS_SESSION);
    assert!(
        browser_session(&connection, &format!("{:064x}", 0), NOW + 100)
            .expect("read")
            .is_none()
    );
}
