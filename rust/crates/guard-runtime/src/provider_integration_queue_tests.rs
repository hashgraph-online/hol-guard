use guard_contracts::ProviderCapabilityV1 as Cap;

use super::*;

const SHIELD: &str = "provider.exampleshield";
const OTHER: &str = "provider.otherwatch";
const NOW: u64 = 10_000_000;

fn queue() -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    ensure_lookup_queue_schema(&connection).unwrap();
    connection
}

fn ask(connection: &Connection, provider_id: &str, origin: &str, now_ms: u64) -> bool {
    request_lookup(
        connection,
        provider_id,
        Cap::OriginReputation,
        origin,
        now_ms,
    )
    .unwrap()
}

fn count(connection: &Connection) -> i64 {
    connection
        .query_row("select count(*) from pending_provider_lookups", [], |row| {
            row.get(0)
        })
        .unwrap()
}

#[test]
fn a_public_origin_is_queued_once_in_its_canonical_spelling() {
    let connection = queue();
    assert!(ask(
        &connection,
        SHIELD,
        "HTTPS://Shop.Example.com:443/",
        NOW
    ));
    assert!(!ask(
        &connection,
        SHIELD,
        "https://shop.example.com",
        NOW + 1
    ));
    assert!(ask(&connection, OTHER, "https://shop.example.com", NOW + 2));
    let taken = take_lookups(&connection, NOW + 3, 8).unwrap();
    assert_eq!(taken.len(), 2);
    assert_eq!(taken[0].provider_id, SHIELD);
    assert_eq!(taken[0].origin, "https://shop.example.com");
    assert_eq!(
        taken[0].subject,
        origin_subject("https://shop.example.com").unwrap().1
    );
    assert_eq!(count(&connection), 0, "taking removes the request");
}

#[test]
fn an_origin_that_may_not_be_shared_is_never_written() {
    let connection = queue();
    for origin in [
        "http://localhost:3000",
        "http://127.0.0.1",
        "https://intranet",
        "https://printer.local",
        "https://app.internal",
        "https://10.1.2.3",
    ] {
        assert!(!ask(&connection, SHIELD, origin, NOW), "{origin}");
    }
    assert_eq!(count(&connection), 0);
    assert!(request_lookup(
        &connection,
        "not a provider",
        Cap::OriginReputation,
        "https://shop.example.com",
        NOW
    )
    .is_err());
}

#[test]
fn old_requests_expire_and_the_queue_is_bounded() {
    let connection = queue();
    assert!(ask(&connection, SHIELD, "https://old.example.com", NOW));
    let later = NOW + QUEUED_LOOKUP_TTL_MS + 1;
    assert!(ask(&connection, SHIELD, "https://new.example.com", later));
    let taken = take_lookups(&connection, later, 8).unwrap();
    assert_eq!(taken.len(), 1);
    assert_eq!(taken[0].origin, "https://new.example.com");

    for index in 0..(MAX_QUEUED_LOOKUPS + 10) {
        let origin = format!("https://site{index}.example.com");
        ask(&connection, SHIELD, &origin, NOW + index as u64);
    }
    assert_eq!(count(&connection), MAX_QUEUED_LOOKUPS);
    let first = take_lookups(&connection, NOW + 400, 1).unwrap();
    assert_eq!(
        first[0].origin, "https://site10.example.com",
        "oldest go first"
    );
}

#[test]
fn a_tampered_row_is_dropped_not_returned() {
    let connection = queue();
    assert!(ask(&connection, SHIELD, "https://shop.example.com", NOW));
    connection
        .execute(
            "update pending_provider_lookups set origin = 'http://127.0.0.1'",
            [],
        )
        .unwrap();
    assert!(ask(&connection, SHIELD, "https://other.example.com", NOW));
    connection
        .execute(
            "update pending_provider_lookups set origin = 'https://elsewhere.example.com' \
             where origin = 'https://other.example.com'",
            [],
        )
        .unwrap();
    assert!(take_lookups(&connection, NOW, 8).unwrap().is_empty());
    assert_eq!(count(&connection), 0);
}

#[test]
fn disconnect_and_purge_drop_queued_requests() {
    let connection = queue();
    ask(&connection, SHIELD, "https://a.example.com", NOW);
    ask(&connection, OTHER, "https://a.example.com", NOW);
    assert_eq!(forget_queued_lookups(&connection, Some(SHIELD)).unwrap(), 1);
    assert_eq!(forget_queued_lookups(&connection, None).unwrap(), 1);
    let bare = Connection::open_in_memory().unwrap();
    assert_eq!(forget_queued_lookups(&bare, None).unwrap(), 0);
}
