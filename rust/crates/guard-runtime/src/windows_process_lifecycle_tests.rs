use std::cell::RefCell;
use std::collections::BTreeMap;

use serde_json::json;

use super::*;

#[derive(Default)]
struct FakeProcesses {
    liveness: BTreeMap<u32, Option<bool>>,
    creation_times: BTreeMap<u32, u64>,
    owner_sids: BTreeMap<u32, String>,
    /// Every termination asked for: process, creation time and timeout.
    terminations: RefCell<Vec<(u32, u64, Option<Duration>)>>,
}

impl Processes for FakeProcesses {
    fn liveness(&self, process_id: u32) -> Option<bool> {
        self.liveness.get(&process_id).copied().flatten()
    }

    fn creation_time(&self, process_id: u32) -> Option<u64> {
        self.creation_times.get(&process_id).copied()
    }

    fn owner_sid(&self, process_id: u32) -> Option<String> {
        self.owner_sids.get(&process_id).cloned()
    }

    fn terminate_if_creation_time(
        &self,
        process_id: u32,
        expected_creation_time: u64,
        timeout: Option<Duration>,
    ) -> bool {
        self.terminations
            .borrow_mut()
            .push((process_id, expected_creation_time, timeout));
        self.creation_times.get(&process_id) == Some(&expected_creation_time)
    }

    fn command_line_to_argv(&self, command: &str) -> Option<Vec<String>> {
        match command {
            "unsplittable" => None,
            "nothing" => Some(Vec::new()),
            _ => Some(command.split(' ').map(str::to_owned).collect()),
        }
    }
}

fn ask(processes: &FakeProcesses, request: Value) -> Result<Value, String> {
    let mut request = request;
    request["schema"] = json!(SCHEMA);
    answer(&serde_json::from_value(request).unwrap(), processes)
}

#[test]
fn liveness_is_false_only_when_proven() {
    let processes = FakeProcesses {
        liveness: BTreeMap::from([(10, Some(true)), (20, Some(false)), (30, None)]),
        ..FakeProcesses::default()
    };
    assert_eq!(
        ask(
            &processes,
            json!({"op": "liveness", "pids": [10, 20, 30, 40, 0, -5, 4_294_967_296_i64]})
        )
        .unwrap(),
        json!({"liveness": [true, false, null, null, false, false, null]})
    );
}

#[test]
fn creation_times_and_owner_sids_answer_per_process() {
    let processes = FakeProcesses {
        creation_times: BTreeMap::from([(10, 133_000_000_000_000_000)]),
        owner_sids: BTreeMap::from([(10, "sid:S-1-5-21-1".to_owned())]),
        ..FakeProcesses::default()
    };
    assert_eq!(
        ask(
            &processes,
            json!({"op": "creation_time", "pids": [10, 20, 0, -1]})
        )
        .unwrap(),
        json!({"creation_times": [133_000_000_000_000_000_u64, null, null, null]})
    );
    assert_eq!(
        ask(&processes, json!({"op": "owner_sid", "pids": [10, 20, 0]})).unwrap(),
        json!({"owner_sids": ["sid:S-1-5-21-1", null, null]})
    );
}

#[test]
fn termination_needs_a_process_and_its_creation_time() {
    let processes = FakeProcesses {
        creation_times: BTreeMap::from([(10, 77)]),
        ..FakeProcesses::default()
    };
    let terminate = |request: Value| {
        let mut request = request;
        request["op"] = json!("terminate_if_creation_time");
        ask(&processes, request).unwrap()["terminated"].clone()
    };
    assert_eq!(
        terminate(json!({"pid": 10, "expected_creation_time": 77})),
        json!(true)
    );
    assert_eq!(
        terminate(json!({"pid": 10, "expected_creation_time": 78, "timeout_ms": 250})),
        json!(false)
    );
    for refused in [
        json!({"pid": 0, "expected_creation_time": 77}),
        json!({"pid": 10, "expected_creation_time": 0}),
        json!({"pid": 10, "expected_creation_time": -77}),
        json!({"pid": 10}),
        json!({"expected_creation_time": 77}),
    ] {
        assert_eq!(terminate(refused), json!(false));
    }
    assert_eq!(
        processes.terminations.borrow().as_slice(),
        &[(10, 77, None), (10, 78, Some(Duration::from_millis(250)))]
    );
    for timeout_ms in [-1, MAX_TIMEOUT_MS + 1] {
        let request = json!({
            "op": "terminate_if_creation_time",
            "pid": 10,
            "expected_creation_time": 77,
            "timeout_ms": timeout_ms,
        });
        assert!(ask(&processes, request).is_err());
    }
}

#[test]
fn command_lines_split_or_answer_null() {
    let processes = FakeProcesses::default();
    let split = |command: Value| {
        ask(
            &processes,
            json!({"op": "command_line_to_argv", "command": command}),
        )
        .unwrap()["argv"]
            .clone()
    };
    assert_eq!(
        split(json!("guard.exe --status")),
        json!(["guard.exe", "--status"])
    );
    assert_eq!(split(json!("")), Value::Null);
    assert_eq!(split(Value::Null), Value::Null);
    assert_eq!(split(json!("unsplittable")), Value::Null);
    assert_eq!(split(json!("nothing")), Value::Null);
}

#[test]
fn requests_are_checked() {
    let processes = FakeProcesses::default();
    assert!(ask(&processes, json!({"op": "kill"})).is_err());
    assert!(ask(
        &processes,
        json!({"op": "liveness", "pids": vec![1; MAX_PIDS + 1]})
    )
    .is_err());
    let wrong_schema = json!({"schema": "other", "op": "liveness"});
    assert!(answer(&serde_json::from_value(wrong_schema).unwrap(), &processes).is_err());
    assert!(serde_json::from_value::<Request>(json!({
        "schema": SCHEMA,
        "op": "liveness",
        "extra": true,
    }))
    .is_err());
    assert!(run_command(&b"{"[..]).is_err());
    let oversized = vec![b' '; MAX_REQUEST_BYTES as usize + 1];
    assert_eq!(
        run_command(&oversized[..]),
        Err("windows_process_lifecycle_request_too_large".to_owned())
    );
}

#[test]
fn off_windows_nothing_is_read() {
    if cfg!(windows) {
        return;
    }
    let request: Request = serde_json::from_value(json!({
        "schema": SCHEMA,
        "op": "liveness",
        "pids": [std::process::id()],
    }))
    .unwrap();
    assert_eq!(
        answer(&request, &SystemProcesses).unwrap(),
        json!({"liveness": [null]})
    );
}
