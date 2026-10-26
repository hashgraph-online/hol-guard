//! A kept connection reads what a fresh one would, and never outlives the
//! file it was opened on.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use rusqlite::Connection;

use super::{file_key, keep, open_read_only, open_read_only_cached, take, Idle, MAX_IDLE};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn home() -> PathBuf {
    let home = std::env::temp_dir().join(format!(
        "hol-guard-store-cache-{}-{}",
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

/// Every value the store holds, read on a fresh snapshot.
fn values(path: &Path) -> Vec<i64> {
    let connection = open_read_only_cached(path).unwrap().expect("store");
    let snapshot = connection.unchecked_transaction().unwrap();
    let mut statement = snapshot
        .prepare_cached("select value from marker order by value")
        .unwrap();
    let rows = statement.query_map([], |row| row.get(0)).unwrap();
    rows.collect::<Result<Vec<i64>, _>>().unwrap()
}

fn opened(path: &Path) -> Connection {
    open_read_only(path).unwrap().expect("store")
}

#[test]
fn a_kept_connection_sees_every_later_commit() {
    let path = home().join("guard.db");
    write(&path, 1);
    assert_eq!(values(&path), [1]);
    write(&path, 2);
    assert_eq!(values(&path), [1, 2]);
    assert_eq!(values(&path), [1, 2]);
}

#[test]
fn a_replaced_store_is_read_afresh() {
    let home = home();
    let path = home.join("guard.db");
    write(&path, 1);
    assert_eq!(values(&path), [1]);
    let next = home.join("next.db");
    write(&next, 7);
    std::fs::rename(&next, &path).unwrap();
    assert_eq!(values(&path), [7]);
    std::fs::remove_file(&path).unwrap();
    assert!(open_read_only_cached(&path).unwrap().is_none());
}

#[test]
fn only_a_connection_for_the_same_file_is_reused() {
    let home = home();
    let path = home.join("guard.db");
    write(&path, 1);
    let key = file_key(&path).expect("key");
    let mut idle = Vec::new();
    keep(&mut idle, key.clone(), opened(&path));
    assert!(take(&mut idle, &key).is_some());
    assert!(take(&mut idle, &key).is_none());
    // A connection to the file the path named before is closed, not reused.
    keep(&mut idle, key.clone(), opened(&path));
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
    let connection = opened(&path);
    connection.execute_batch("begin").unwrap();
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
        keep(&mut idle, file_key(path).expect("key"), opened(path));
    }
    assert_eq!(idle.len(), MAX_IDLE);
    assert!(take(&mut idle, &file_key(&homes[0]).expect("key")).is_none());
    assert!(take(&mut idle, &file_key(&homes[MAX_IDLE]).expect("key")).is_some());
}
