//! A kept read-write connection sees and writes what a fresh one would, and
//! never outlives the file it was opened on or carries a transaction over.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use rusqlite::Connection;

use super::{file_key, keep, open, open_read_write_cached, take, Idle, MAX_IDLE};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn home() -> PathBuf {
    let home = std::env::temp_dir().join(format!(
        "hol-guard-store-write-cache-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&home).unwrap();
    home.canonicalize().unwrap()
}

/// A store at `path` holding the single `value`.
fn write(path: &Path, value: i64) {
    let store = Connection::open(path).unwrap();
    store
        .execute_batch("create table if not exists marker (value integer)")
        .unwrap();
    store
        .execute("insert into marker values (?1)", [value])
        .unwrap();
}

fn values(connection: &Connection) -> Vec<i64> {
    let mut statement = connection
        .prepare_cached("select value from marker order by value")
        .unwrap();
    let rows = statement.query_map([], |row| row.get(0)).unwrap();
    rows.collect::<Result<Vec<i64>, _>>().unwrap()
}

#[test]
fn a_kept_connection_sees_other_writers_and_its_writes_are_durable() {
    let path = home().join("guard.db");
    write(&path, 1);
    {
        let connection = open_read_write_cached(&path).unwrap();
        connection
            .execute("insert into marker values (2)", [])
            .unwrap();
    }
    write(&path, 3);
    let connection = open_read_write_cached(&path).unwrap();
    assert_eq!(values(&connection), [1, 2, 3]);
    assert_eq!(values(&Connection::open(&path).unwrap()), [1, 2, 3]);
}

#[test]
fn a_replaced_store_is_opened_afresh() {
    let home = home();
    let path = home.join("guard.db");
    write(&path, 1);
    drop(open_read_write_cached(&path).unwrap());
    let next = home.join("next.db");
    write(&next, 7);
    std::fs::rename(&next, &path).unwrap();
    assert_eq!(values(&open_read_write_cached(&path).unwrap()), [7]);
}

#[test]
fn only_a_connection_for_the_same_file_is_reused() {
    let home = home();
    let path = home.join("guard.db");
    write(&path, 1);
    let key = file_key(&path).expect("key");
    let mut idle = Vec::new();
    keep(&mut idle, key.clone(), open(&path).unwrap());
    assert!(take(&mut idle, &key).is_some());
    assert!(take(&mut idle, &key).is_none());
    keep(&mut idle, key.clone(), open(&path).unwrap());
    let next = home.join("next.db");
    write(&next, 2);
    std::fs::rename(&next, &path).unwrap();
    let replaced = file_key(&path).expect("key");
    assert_ne!(replaced, key);
    assert!(take(&mut idle, &replaced).is_none());
    assert!(idle.is_empty());
}

#[test]
fn an_open_transaction_is_never_kept() {
    let path = home().join("guard.db");
    write(&path, 1);
    let key = file_key(&path).expect("key");
    let connection = open(&path).unwrap();
    connection.execute_batch("begin immediate").unwrap();
    let mut idle = Vec::new();
    keep(&mut idle, key, connection);
    assert!(idle.is_empty());
}

#[test]
fn the_oldest_kept_connection_makes_room() {
    let homes: Vec<PathBuf> = (0..=MAX_IDLE).map(|_| home().join("guard.db")).collect();
    let mut idle: Vec<Idle> = Vec::new();
    for path in &homes {
        write(path, 1);
        keep(&mut idle, file_key(path).expect("key"), open(path).unwrap());
    }
    assert_eq!(idle.len(), MAX_IDLE);
    assert!(take(&mut idle, &file_key(&homes[0]).expect("key")).is_none());
    assert!(take(&mut idle, &file_key(&homes[MAX_IDLE]).expect("key")).is_some());
}
