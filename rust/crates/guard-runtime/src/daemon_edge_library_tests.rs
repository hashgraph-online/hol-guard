use serde_json::json;

use super::*;

#[test]
fn answers_decode_to_values_and_raised_errors() {
    assert_eq!(decode(br#"{"ok":{"a":1}}"#), Ok(json!({"a": 1})));
    assert_eq!(decode(br#"{"ok":null}"#), Ok(Value::Null));
    let raised = decode(br#"{"error":{"kind":"not_found","type":"X","message":"m"}}"#);
    assert_eq!(
        raised.as_ref().err().and_then(CallError::kind),
        Some("not_found")
    );
    for answer in [&b""[..], b"[]", b"{}", b"{\"error\":1}", b"not json"] {
        assert_eq!(decode(answer), Err(CallError::NoAnswer));
    }
}

#[test]
fn worker_host_arguments_name_the_guard_home() {
    assert_eq!(
        host_args("/h"),
        ["desktop", "daemon-workers", "--guard-home", "/h"].map(str::to_owned)
    );
}

fn journaled(home: &std::path::Path) -> Vec<String> {
    let (events, _) = super::super::lifecycle::load_events(home, 64, false);
    events
        .iter()
        .filter_map(|event| {
            event
                .get("event")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .collect()
}

#[test]
fn worker_host_start_steps_are_journaled_before_ready() {
    let home = tempfile::tempdir().unwrap();
    let (sender, receiver) = mpsc::channel();
    let mut lines = &b"phase launched\nphase admitted\nready\nphase late\n"[..];
    read_host_start(&mut lines, home.path(), Some(sender));
    assert!(receiver.try_recv().is_ok());
    assert_eq!(journaled(home.path()), ["host_launched", "host_admitted"]);
}

#[test]
fn a_host_that_says_anything_else_is_not_ready() {
    let home = tempfile::tempdir().unwrap();
    for output in [
        &b"phase launched\nnot ready\nready\n"[..],
        b"phase launched\n",
        b"",
    ] {
        let (sender, receiver) = mpsc::channel();
        let mut lines = output;
        read_host_start(&mut lines, home.path(), Some(sender));
        assert!(receiver.try_recv().is_err());
    }
    let (sender, receiver) = mpsc::channel();
    let flood = "phase step\n".repeat(MAX_HOST_PHASES + 1) + "ready\n";
    read_host_start(&mut flood.as_bytes(), home.path(), Some(sender));
    assert!(receiver.try_recv().is_err());
}

/// A resident that died since the last call must not cost the next hook its
/// answer: the call starts the replacement and is served by it.
#[test]
fn a_call_that_finds_its_resident_gone_is_served_by_a_replacement() {
    let home = tempfile::tempdir().unwrap();
    let marker = home.path().join("started");
    // The first launch exits at once; any later launch answers one call.
    let script = format!(
        "if [ -e '{marker}' ]; then read line; printf '%s\\n' '{{\"id\":1,\"ok\":\"served\"}}'; read line; else : > '{marker}'; fi",
        marker = marker.display()
    );
    let guard_home = home.path().join("guard-home").display().to_string();
    let handshake = json!({
        "schema": crate::daemon_edge::reads::HANDSHAKE_SCHEMA,
        "auth_token": "library-test-value",
        "guard_home": guard_home,
        "store_path": home.path().join("guard.db").display().to_string(),
        "source": "default",
        "busy_timeout_ms": 2000,
        "cli_command": ["/bin/sh", "-c", script, "sh"],
    });
    let config = ReadConfig::from_line(&serde_json::to_vec(&handshake).unwrap()).unwrap();

    let dead = Arc::new(start_resident(&config).unwrap());
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while dead.pending.lock().unwrap().is_some() {
        assert!(
            std::time::Instant::now() < deadline,
            "first child never exited"
        );
        thread::sleep(Duration::from_millis(10));
    }
    residents()
        .lock()
        .unwrap()
        .insert(guard_home.clone(), Arc::clone(&dead));

    let answer = call_resident_within(&config, "hook.warm", json!({}), Duration::from_secs(10));
    assert_eq!(answer, Ok(json!("served")));

    if let Some(resident) = residents().lock().unwrap().remove(&guard_home) {
        resident.stop();
    }
}

/// A resident that has stopped reading its input must not hold callers past
/// their own deadline. A burst of large calls fills the pipe; each caller
/// still gives up on time instead of waiting in a write that never ends.
#[test]
fn callers_keep_their_deadline_when_the_resident_stops_reading() {
    let home = tempfile::tempdir().unwrap();
    let guard_home = home.path().join("guard-home").display().to_string();
    let handshake = json!({
        "schema": crate::daemon_edge::reads::HANDSHAKE_SCHEMA,
        "auth_token": "library-test-value",
        "guard_home": guard_home,
        "store_path": home.path().join("guard.db").display().to_string(),
        "source": "default",
        "busy_timeout_ms": 2000,
        "cli_command": ["/bin/sh", "-c", "sleep 30", "sh"],
    });
    let config = Arc::new(ReadConfig::from_line(&serde_json::to_vec(&handshake).unwrap()).unwrap());
    let filler = "x".repeat(256 * 1024);
    let started = std::time::Instant::now();
    let callers: Vec<_> = (0..16)
        .map(|_| {
            let config = Arc::clone(&config);
            let filler = filler.clone();
            thread::spawn(move || {
                call_resident_within(
                    &config,
                    "hook.review",
                    json!({ "payload": filler }),
                    Duration::from_millis(500),
                )
            })
        })
        .collect();
    let (finished, done) = mpsc::channel();
    thread::spawn(move || {
        let answers: Vec<_> = callers
            .into_iter()
            .map(|caller| caller.join().unwrap())
            .collect();
        let _ = finished.send(answers);
    });
    let answers = done
        .recv_timeout(Duration::from_secs(10))
        .expect("callers stayed blocked writing to a resident that never reads");
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(answers
        .iter()
        .all(|answer| answer == &Err(CallError::NoAnswer)));

    if let Some(resident) = residents().lock().unwrap().remove(&guard_home) {
        resident.stop();
    }
}

#[test]
fn a_call_line_names_its_deadline_before_its_arguments() {
    let line = request_line(
        7,
        Duration::from_millis(1500),
        "hook.review",
        &json!({"a": 1}),
    )
    .unwrap();
    assert_eq!(
        line,
        b"{\"id\":7,\"expires_in_ms\":1500,\"call\":\"hook.review\",\"args\":{\"a\":1}}\n"
    );
    let decoded: Value = serde_json::from_slice(&line).unwrap();
    assert_eq!(decoded["call"], "hook.review");
}
