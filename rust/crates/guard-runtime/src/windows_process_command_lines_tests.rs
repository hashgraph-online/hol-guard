use std::cell::RefCell;
use std::collections::BTreeMap;

use serde_json::json;

use super::*;

#[derive(Clone, Default)]
struct Entry {
    image: Option<String>,
    command_line: Option<String>,
    liveness: Option<bool>,
}

#[derive(Default)]
struct FakeTable {
    ids: Option<Vec<u32>>,
    entries: BTreeMap<u32, Entry>,
    /// Every bound a command-line read was asked for, by process.
    bounds: RefCell<Vec<(u32, usize)>>,
}

impl FakeTable {
    fn with(entries: &[(u32, &str, Option<&str>, Option<bool>)]) -> Self {
        let mut table = Self::default();
        for (pid, image, command_line, liveness) in entries {
            table.entries.insert(
                *pid,
                Entry {
                    image: Some((*image).to_owned()),
                    command_line: command_line.map(str::to_owned),
                    liveness: *liveness,
                },
            );
        }
        let mut ids: Vec<u32> = table.entries.keys().copied().collect();
        ids.push(0);
        table.ids = Some(ids);
        table
    }
}

impl ProcessTable for FakeTable {
    type Process = u32;

    fn process_ids(&self) -> Option<Vec<u32>> {
        self.ids.clone()
    }

    fn open(&self, process_id: u32) -> Option<u32> {
        self.entries.contains_key(&process_id).then_some(process_id)
    }

    fn image_path(&self, process: &u32) -> Option<String> {
        self.entries[process].image.clone()
    }

    fn command_line(&self, process: &u32, max_command_line_bytes: usize) -> Option<String> {
        self.bounds
            .borrow_mut()
            .push((*process, max_command_line_bytes));
        self.entries[process].command_line.clone()
    }

    fn liveness(&self, process_id: u32) -> Option<bool> {
        self.entries
            .get(&process_id)
            .and_then(|entry| entry.liveness)
    }
}

fn request(value: Value) -> Request {
    serde_json::from_value(value).unwrap()
}

fn read(table: &FakeTable, pids: Value, max: i64) -> Value {
    answer(
        &request(json!({
            "schema": SCHEMA,
            "op": "read",
            "pids": pids,
            "max_command_line_bytes": max,
        })),
        table,
    )
    .unwrap()
}

fn inventory_of(table: &FakeTable, candidates: Value, max_processes: i64, max: i64) -> Value {
    answer(
        &request(json!({
            "schema": SCHEMA,
            "op": "inventory",
            "candidate_executable_names": candidates,
            "max_processes": max_processes,
            "max_command_line_bytes": max,
        })),
        table,
    )
    .unwrap()["entries"]
        .clone()
}

const PYTHON: &str = r"C:\Python\python.exe";

#[test]
fn read_strips_and_bounds_each_command_line() {
    let table = FakeTable::with(&[
        (10, PYTHON, Some("  python.exe -m guard \r\n"), Some(true)),
        (20, PYTHON, Some(" \t "), Some(true)),
        (30, PYTHON, Some("\u{1c}python.exe x\u{1f}"), Some(true)),
        (40, PYTHON, Some("pythön.exe"), Some(true)),
    ]);
    assert_eq!(
        read(
            &table,
            json!([10, 20, 30, 0, -1, 99, 4_294_967_296_i64]),
            1024
        )["command_lines"],
        json!([
            "python.exe -m guard",
            null,
            "python.exe x",
            null,
            null,
            null,
            null
        ])
    );
    // UTF-8 bytes, not characters, count against the bound.
    assert_eq!(
        read(&table, json!([40]), 10)["command_lines"],
        json!([null])
    );
    assert_eq!(
        read(&table, json!([40]), 11)["command_lines"],
        json!(["pythön.exe"])
    );
    assert_eq!(table.bounds.borrow().last(), Some(&(40, 11)));
}

#[test]
fn read_refuses_out_of_range_limits() {
    let table = FakeTable::with(&[(10, PYTHON, Some("python.exe"), Some(true))]);
    for max in [0, -1, COMMAND_LINE_TOTAL_LIMIT_BYTES + 1] {
        assert_eq!(
            read(&table, json!([10]), max)["command_lines"],
            json!([null])
        );
    }
    assert_eq!(
        read(&table, json!([10]), COMMAND_LINE_TOTAL_LIMIT_BYTES)["command_lines"],
        json!(["python.exe"])
    );
}

#[test]
fn requests_are_checked() {
    let table = FakeTable::default();
    let wrong_schema =
        request(json!({"schema": "other", "op": "read", "max_command_line_bytes": 1}));
    assert!(answer(&wrong_schema, &table).is_err());
    let wrong_op = request(json!({"schema": SCHEMA, "op": "kill", "max_command_line_bytes": 1}));
    assert!(answer(&wrong_op, &table).is_err());
    let too_many = request(json!({
        "schema": SCHEMA,
        "op": "read",
        "pids": vec![1; MAX_READ_PIDS + 1],
        "max_command_line_bytes": 1,
    }));
    assert!(answer(&too_many, &table).is_err());
    assert!(serde_json::from_value::<Request>(json!({
        "schema": SCHEMA,
        "op": "read",
        "max_command_line_bytes": 1,
        "extra": true,
    }))
    .is_err());
    assert!(run_command(&b"{"[..]).is_err());
    let oversized = vec![b' '; MAX_REQUEST_BYTES as usize + 1];
    assert_eq!(
        run_command(&oversized[..]),
        Err("windows_process_request_too_large".to_owned())
    );
}

#[test]
fn inventory_lists_live_candidates_sorted_by_process_id() {
    let table = FakeTable::with(&[
        (
            30,
            r"C:\Guard\HOL-GUARD.EXE",
            Some("hol-guard.exe daemon"),
            Some(true),
        ),
        (10, PYTHON, Some(" python.exe -m guard "), None),
        (
            20,
            r"C:\Windows\explorer.exe",
            Some("explorer.exe"),
            Some(true),
        ),
        (40, PYTHON, Some("python.exe gone"), Some(false)),
        (50, PYTHON, None, Some(false)),
    ]);
    assert_eq!(
        inventory_of(
            &table,
            json!([" Python.exe ", r"D:\bin\hol-guard.exe", ""]),
            100,
            1024
        ),
        json!([[10, "python.exe -m guard"], [30, "hol-guard.exe daemon"]])
    );
    // A non-candidate image is never asked for its command line.
    assert!(table.bounds.borrow().iter().all(|(pid, _)| *pid != 20));
}

#[test]
fn inventory_refuses_an_unreadable_process_that_may_still_run() {
    for liveness in [Some(true), None] {
        let table = FakeTable::with(&[
            (10, PYTHON, Some("python.exe ok"), Some(true)),
            (20, PYTHON, None, liveness),
        ]);
        assert_eq!(
            inventory_of(&table, json!(["python.exe"]), 100, 1024),
            Value::Null
        );
    }
}

#[test]
fn inventory_skips_processes_it_cannot_open_or_name() {
    let mut table = FakeTable::with(&[(10, PYTHON, Some("python.exe ok"), Some(true))]);
    table.entries.insert(20, Entry::default());
    table.entries.insert(
        30,
        Entry {
            image: Some("  ".to_owned()),
            ..Entry::default()
        },
    );
    table.ids.as_mut().unwrap().extend([20, 30, 99]);
    assert_eq!(
        inventory_of(&table, json!(["python.exe"]), 100, 1024),
        json!([[10, "python.exe ok"]])
    );
}

#[test]
fn inventory_spends_one_command_line_budget() {
    let table = FakeTable::with(&[
        (10, PYTHON, Some("aaaa"), Some(true)),
        (20, PYTHON, Some("bbbb"), Some(true)),
        (30, PYTHON, Some("cc"), Some(true)),
    ]);
    assert_eq!(
        inventory_of(&table, json!(["python.exe"]), 100, 10),
        json!([[10, "aaaa"], [20, "bbbb"], [30, "cc"]])
    );
    assert_eq!(
        table.bounds.borrow().as_slice(),
        &[(10, 10), (20, 6), (30, 2)]
    );
    assert_eq!(
        inventory_of(&table, json!(["python.exe"]), 100, 9),
        Value::Null
    );
    // The budget is spent before the last candidate is reached.
    assert_eq!(
        inventory_of(&table, json!(["python.exe"]), 100, 8),
        Value::Null
    );
}

#[test]
fn inventory_refuses_a_table_it_may_not_have_read_whole() {
    let table = FakeTable::with(&[(10, PYTHON, Some("python.exe"), Some(true))]);
    // Two ids, the idle process's 0 included, fill a two-slot table.
    assert_eq!(
        inventory_of(&table, json!(["python.exe"]), 2, 1024),
        Value::Null
    );
    assert_eq!(
        inventory_of(&table, json!(["python.exe"]), 3, 1024),
        json!([[10, "python.exe"]])
    );
    let unreadable = FakeTable::default();
    assert_eq!(
        inventory_of(&unreadable, json!(["python.exe"]), 3, 1024),
        Value::Null
    );
    let empty = FakeTable {
        ids: Some(Vec::new()),
        ..FakeTable::default()
    };
    assert_eq!(
        inventory_of(&empty, json!(["python.exe"]), 3, 1024),
        Value::Null
    );
}

#[test]
fn inventory_limits_and_empty_candidates() {
    let table = FakeTable::with(&[(10, PYTHON, Some("python.exe"), Some(true))]);
    for (max_processes, max) in [
        (0, 1024),
        (-1, 1024),
        (PROCESS_ENUMERATION_LIMIT + 1, 1024),
        (100, 0),
        (100, COMMAND_LINE_TOTAL_LIMIT_BYTES + 1),
    ] {
        assert_eq!(
            inventory_of(&table, json!(["python.exe"]), max_processes, max),
            Value::Null
        );
    }
    assert_eq!(
        inventory_of(&table, json!([" ", r"C:\"]), 100, 1024),
        json!([])
    );
}

#[test]
fn executable_name_matches_ntpath_basename() {
    for (path, name) in [
        (r"C:\Python\Python.EXE", "python.exe"),
        ("C:python.exe", "python.exe"),
        ("C:", ""),
        ("python.exe", "python.exe"),
        ("dir/sub/py.exe", "py.exe"),
        (r"\\server\share", ""),
        (r"\\server", ""),
        (r"\\server\share\py.exe", "py.exe"),
        (r"\\server\share\dir\py.exe", "py.exe"),
        (r"C:\dir\", ""),
    ] {
        assert_eq!(executable_name(path), name, "{path}");
    }
}
