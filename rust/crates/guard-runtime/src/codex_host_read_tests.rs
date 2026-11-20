use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::fake_host::{default_handler, host, Host};
use super::*;

fn code(code: &'static str) -> Option<Stop> {
    Some(Stop::Code(code))
}

#[test]
fn existing_host_is_kernel_authenticated_and_summaries_cannot_grant() {
    let host = host(default_handler);
    let snapshot = host.read().unwrap();
    assert_eq!(
        host.methods(),
        ["initialize", "initialized", "app/installed", "app/read"]
    );
    let requests = host.requests();
    assert_eq!(requests[2]["params"], json!({ "forceRefresh": false }));
    assert_eq!(
        requests[3]["params"],
        json!({ "appIds": ["example"], "includeTools": true })
    );
    let ids: std::collections::HashSet<&str> = requests
        .iter()
        .filter_map(|request| request["id"].as_str())
        .collect();
    assert_eq!(ids.len(), 3);
    assert_eq!(snapshot.apps[0]["name"], "Example connector");
    assert_eq!(
        snapshot.apps[0]["tools"],
        json!([{
            "name": "send_message",
            "title": "Send a message",
            "description": "Change external content",
        }])
    );
    assert!(snapshot.complete);
    assert_eq!(snapshot.host_pid, std::process::id());
    assert_eq!(snapshot.managed_pid, Some(std::process::id()));
    let answered = answer(Ok(snapshot));
    assert_eq!(
        answered["snapshot"]["connection_id"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    assert_eq!(answered["snapshot"]["metadata_complete"], true);
}

#[test]
fn wrong_host_or_process_is_rejected_before_handshake() {
    let host = host(default_handler);
    host.set_marker(std::process::id() + 1);
    assert_eq!(host.read_error(), code(UNTRUSTED));
    host.set_marker(std::process::id());
    let outcome = read_snapshot(&host.request(), Duration::from_secs(5), &|_| Ok(false));
    assert_eq!(outcome.err(), code(UNTRUSTED));
    assert!(host.requests().is_empty());
}

#[test]
fn a_peer_that_is_not_codex_is_rejected_by_the_real_process_check() {
    let host = host(default_handler);
    let request = json!({ "codex_home": host.home(), "timeout_ms": 5000 });
    let answered = read_op(request.as_object().unwrap());
    assert_eq!(answered, json!({ "error": UNTRUSTED }));
    assert!(host.requests().is_empty());
}

#[test]
fn replay_and_malformed_pages_fail_atomically() {
    for fault in [
        "replay",
        "foreign_app",
        "missing_app",
        "duplicate_app",
        "duplicate_tool",
        "error",
        "no_result",
    ] {
        let previous: Mutex<Vec<Value>> = Mutex::new(Vec::new());
        let host = host(move |request| {
            let mut response = default_handler(request);
            if request["method"] == "app/read" {
                match fault {
                    "replay" => response["id"] = previous.lock().unwrap()[0].clone(),
                    "foreign_app" => {
                        response["result"]["apps"][0]["id"] = json!("another-account");
                    }
                    "missing_app" => response["result"]["apps"] = json!([]),
                    "duplicate_app" => {
                        let app = response["result"]["apps"][0].clone();
                        response["result"]["apps"] = json!([app.clone(), app]);
                    }
                    "duplicate_tool" => {
                        let tool = response["result"]["apps"][0]["tools"][0].clone();
                        response["result"]["apps"][0]["tools"] = json!([tool.clone(), tool]);
                    }
                    "error" => {
                        response = json!({
                            "id": request["id"],
                            "error": { "message": "private host details" },
                        });
                    }
                    _ => response = json!({ "id": request["id"] }),
                }
            }
            previous.lock().unwrap().push(request["id"].clone());
            response
        });
        let stop = host.read_error();
        assert!(
            matches!(stop, Some(Stop::Code(INVALID | UNAVAILABLE))),
            "{fault}: {stop:?}"
        );
    }
}

#[test]
fn a_host_with_no_installed_apps_is_complete_and_asks_for_no_metadata() {
    let host = host(|request| {
        if request["method"] == "app/installed" {
            return json!({ "id": request["id"], "result": { "apps": [] } });
        }
        default_handler(request)
    });
    let snapshot = host.read().unwrap();
    assert!(snapshot.apps.is_empty());
    assert!(snapshot.complete);
    assert_eq!(
        host.methods(),
        ["initialize", "initialized", "app/installed"]
    );
}

#[test]
fn missing_metadata_is_explicit_without_losing_host_runtime_state() {
    let host = host(|request| {
        let mut response = default_handler(request);
        if request["method"] == "app/read" {
            response["result"] = json!({ "apps": [], "missingAppIds": ["example"] });
        }
        response
    });
    let snapshot = host.read().unwrap();
    assert!(!snapshot.complete);
    assert_eq!(snapshot.apps[0]["callable"], true);
    assert_eq!(snapshot.apps[0]["metadata_available"], false);
    assert_eq!(snapshot.apps[0]["tools"], json!([]));
}

#[test]
fn tool_summaries_take_the_place_of_tools() {
    let host = host(|request| {
        let mut response = default_handler(request);
        if request["method"] == "app/read" {
            let app = &mut response["result"]["apps"][0];
            app["toolSummaries"] = json!([{ "name": "summary_tool" }]);
        }
        response
    });
    let snapshot = host.read().unwrap();
    assert_eq!(snapshot.apps[0]["tools"][0]["name"], "summary_tool");
}

#[test]
fn reconnect_during_metadata_read_invalidates_snapshot() {
    let marker = Arc::new(Mutex::new(None::<PathBuf>));
    let seen = marker.clone();
    let host = host(move |request| {
        if request["method"] == "app/read" {
            let path = seen.lock().unwrap().clone().unwrap();
            std::fs::write(path, (std::process::id() + 1).to_string()).unwrap();
        }
        default_handler(request)
    });
    *marker.lock().unwrap() = Some(host.marker());
    assert_eq!(host.read_error(), code(CHANGED));
}

#[test]
fn missing_host_is_absent_and_never_launches_one() {
    let directory = tempfile::Builder::new()
        .prefix("hgr")
        .tempdir_in("/tmp")
        .unwrap();
    let home = directory.path().to_str().unwrap();
    let request = Request {
        codex_home: home,
        home_dir: None,
        temp_dir: None,
    };
    let outcome = read_snapshot(&request, Duration::from_secs(1), &|_| Ok(true));
    assert_eq!(outcome.err(), Some(Stop::Absent));
    let asked = json!({ "codex_home": home, "timeout_ms": 1000 });
    assert_eq!(
        read_op(asked.as_object().unwrap()),
        json!({ "absent": true })
    );
    let relative = json!({ "codex_home": "codex", "timeout_ms": 1000 });
    assert_eq!(
        read_op(relative.as_object().unwrap()),
        json!({ "error": INVALID })
    );
}

#[test]
fn public_metadata_pages_are_bounded_and_preserve_all_installed_apps() {
    let host = host(|request| {
        let result = match request["method"].as_str().unwrap() {
            "app/installed" => json!({ "apps": (0..101)
                .map(|index| json!({ "id": format!("app_{index}"), "enabled": true, "callable": false }))
                .collect::<Vec<_>>() }),
            "app/read" => {
                let ids = request["params"]["appIds"].as_array().unwrap();
                json!({
                    "apps": ids.iter().map(|id| json!({ "id": id, "name": id, "tools": [] })).collect::<Vec<_>>(),
                    "missingAppIds": [],
                })
            }
            _ => return default_handler(request),
        };
        json!({ "id": request["id"], "result": result })
    });
    let snapshot = host.read().unwrap();
    assert_eq!(snapshot.apps.len(), 101);
    let pages: Vec<usize> = host
        .requests()
        .iter()
        .filter(|request| request["method"] == "app/read")
        .map(|request| request["params"]["appIds"].as_array().unwrap().len())
        .collect();
    assert_eq!(pages, [100, 1]);
    assert_eq!(snapshot.apps[100]["app_id"], "app_100");
    assert!(snapshot.complete);
}

#[test]
fn private_socket_alias_is_pinned_to_authenticated_target() {
    let host = host(default_handler);
    let target = host.control().join("daemon.sock");
    std::fs::rename(host.socket(), &target).unwrap();
    symlink(&target, host.socket()).unwrap();
    let snapshot = host.read().unwrap();
    assert_eq!(snapshot.apps[0]["app_id"], "example");
    assert_eq!(Path::new(&snapshot.pin.target), target);
}

#[test]
fn socket_alias_to_a_shared_directory_is_rejected() {
    let host = host(default_handler);
    let shared = host.home.parent().unwrap().join("shared");
    std::fs::create_dir(&shared).unwrap();
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o755)).unwrap();
    let target = shared.join("daemon.sock");
    std::fs::rename(host.socket(), &target).unwrap();
    symlink(&target, host.socket()).unwrap();
    assert_eq!(host.read_error(), code(UNTRUSTED));
    assert!(host.requests().is_empty());
}

fn check_request(host: &Host, snapshot: &Snapshot) -> Value {
    json!({
        "codex_home": host.home(),
        "target": snapshot.pin.target,
        "identity": snapshot.pin.identity,
        "pid": snapshot.host_pid,
        "managed_pid": snapshot.managed_pid,
    })
}

#[test]
fn check_is_valid_until_the_marker_or_socket_changes() {
    let host = host(default_handler);
    let snapshot = host.read().unwrap();
    let request = check_request(&host, &snapshot);
    let valid = |request: &Value| check_op(request.as_object().unwrap())["valid"].clone();
    assert_eq!(valid(&request), json!(true));

    let mut other_pid = request.clone();
    other_pid["pid"] = json!(snapshot.host_pid + 1);
    assert_eq!(valid(&other_pid), json!(false));

    let mut other_socket = request.clone();
    other_socket["identity"][1] = json!(snapshot.pin.identity[1] + 1);
    assert_eq!(valid(&other_socket), json!(false));

    for malformed in [
        json!({ "codex_home": host.home() }),
        json!({ "codex_home": "relative", "target": "", "identity": [1, 2, 3, 4], "pid": 2, "managed_pid": null }),
        json!({ "codex_home": host.home(), "target": "x", "identity": [1, 2, 3], "pid": 2, "managed_pid": null }),
    ] {
        assert_eq!(valid(&malformed), json!(false), "{malformed}");
    }

    host.set_marker(std::process::id() + 1);
    assert_eq!(valid(&request), json!(false));
}

#[test]
fn check_without_a_marker_only_needs_a_real_pid() {
    let host = host(default_handler);
    std::fs::remove_file(host.marker()).unwrap();
    let snapshot = host.read().unwrap();
    assert_eq!(snapshot.managed_pid, None);
    let request = check_request(&host, &snapshot);
    assert_eq!(
        check_op(request.as_object().unwrap()),
        json!({ "valid": true })
    );
    host.set_marker(snapshot.host_pid);
    assert_eq!(
        check_op(request.as_object().unwrap()),
        json!({ "valid": false })
    );
}

#[test]
fn connection_id_hashes_home_user_process_and_socket_identity() {
    let expected = hex::encode(Sha256::digest(br#"["/h",501,42,1,2,3,4]"#));
    assert_eq!(source_id("/h", 501, 42, &[1, 2, 3, 4]), expected);
    assert_ne!(source_id("/h", 501, 42, &[1, 2, 3, 5]), expected);
}

#[test]
fn shared_depth_scanner_keeps_the_limit_and_ignores_string_brackets() {
    let quoted = json!({ "text": format!("{}\\\"{}", "[".repeat(100), "]".repeat(100)) });
    assert_eq!(check_depth(quoted.to_string().as_bytes()), Ok(()));
    let nested = |depth: usize| [vec![b'['; depth], b"0".to_vec(), vec![b']'; depth]].concat();
    assert_eq!(check_depth(&nested(32)), Ok(()));
    let moderate = nested(33);
    assert_eq!(check_depth(&moderate), Err(Stop::Code(LIMIT)));
    let excessive = nested(65);
    for malformed in [
        b"]".to_vec(),
        [vec![b'}'; 64], excessive].concat(),
        [vec![b']'; 32], moderate].concat(),
    ] {
        assert_eq!(check_depth(&malformed), Err(Stop::Code(LIMIT)));
    }
}

#[test]
fn host_text_that_is_not_strict_json_is_refused() {
    assert_eq!(parse_message(br#"{"id":"a"}"#).unwrap()["id"], "a");
    assert_eq!(parse_message(b"not json"), Err(Stop::Code(UNAVAILABLE)));
    assert_eq!(parse_message(&[0xff, 0xfe]), Err(Stop::Code(UNAVAILABLE)));
    assert_eq!(
        parse_message(br#"{"id":"a","id":"b"}"#),
        Err(Stop::Code(INVALID))
    );
    assert_eq!(parse_message(b"[1]"), Err(Stop::Code(INVALID)));
}

#[test]
fn socket_failures_keep_the_python_error_meaning() {
    assert_eq!(
        failure_stop(Failure::Error("FileNotFoundError")),
        Stop::Absent
    );
    assert_eq!(
        failure_stop(Failure::Error("ValueError")),
        Stop::Code(INVALID)
    );
    assert_eq!(
        failure_stop(Failure::Error("OSError")),
        Stop::Code(UNAVAILABLE)
    );
    assert_eq!(failure_stop(Failure::Timeout), Stop::Code(UNAVAILABLE));
}

fn with_app_read(change: impl Fn(&mut Value) + Send + Sync + 'static) -> Host {
    host(move |request| {
        let mut response = default_handler(request);
        if request["method"] == "app/read" {
            change(&mut response["result"]);
        }
        response
    })
}

#[test]
fn protocol_tool_summaries_bound_long_display_text() {
    let host = with_app_read(|result| {
        let app = &mut result["apps"][0];
        app["toolSummaries"] = app["tools"].take();
        app["toolSummaries"][0]["title"] = json!("t".repeat(700));
        app["toolSummaries"][0]["description"] = json!("d".repeat(9030));
    });
    let snapshot = host.read().unwrap();
    assert!(snapshot.complete);
    let tool = &snapshot.apps[0]["tools"][0];
    assert_eq!(tool["title"].as_str().unwrap().len(), 512);
    assert_eq!(tool["description"].as_str().unwrap().len(), 4000);
    assert!(tool.get("inputSchema").is_none());
}

#[test]
fn unavailable_tool_summaries_keep_the_app_but_not_complete() {
    for missing in [false, true] {
        let host = with_app_read(move |result| {
            let app = &mut result["apps"][0];
            if missing {
                app.as_object_mut().unwrap().remove("tools");
            } else {
                app["toolSummaries"] = Value::Null;
            }
        });
        let snapshot = host.read().unwrap();
        assert!(!snapshot.complete);
        assert_eq!(snapshot.apps[0]["tools"], json!([]));
        assert_eq!(snapshot.apps[0]["metadata_available"], false);
    }
}

#[test]
fn wide_host_replies_are_read_whole() {
    let host = with_app_read(|result| {
        let app = &mut result["apps"][0];
        app["toolSummaries"] = (0..5000)
            .map(|index| json!({ "name": format!("tool_{index}"), "inputSchema": { "a": [[[[]]]] } }))
            .collect();
        app["labels"] = (0..5000)
            .map(|index| (format!("label_{index}"), json!(index)))
            .collect::<serde_json::Map<_, _>>()
            .into();
        result["extra"] = (0..5000).collect();
    });
    let snapshot = host.read().unwrap();
    assert!(snapshot.complete);
    let tools = snapshot.apps[0]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 5000);
    assert_eq!(tools[4095]["name"], "tool_4095");
    assert_eq!(tools[4096]["name"], "tool_4096");
}

#[test]
fn more_tools_than_the_limit_are_refused() {
    let host = with_app_read(|result| {
        result["apps"][0]["tools"] = (0..10_001)
            .map(|index| json!({ "name": format!("tool_{index}") }))
            .collect();
    });
    assert_eq!(host.read_error(), code(LIMIT));
}

#[test]
fn app_read_reply_whose_apps_is_not_a_list_is_refused() {
    for apps in [Value::Null, json!(3), json!(true), json!("apps")] {
        let reply = apps.clone();
        let host = with_app_read(move |result| result["apps"] = reply.clone());
        assert!(matches!(host.read_error(), Some(Stop::Code(_))), "{apps:?}");
    }
}

#[test]
fn managed_marker_removal_invalidates_the_snapshot() {
    let host = host(default_handler);
    let snapshot = host.read().unwrap();
    let request = check_request(&host, &snapshot);
    assert_eq!(
        check_op(request.as_object().unwrap()),
        json!({ "valid": true })
    );
    std::fs::remove_file(host.marker()).unwrap();
    assert_eq!(
        check_op(request.as_object().unwrap()),
        json!({ "valid": false })
    );
}

#[test]
fn a_host_without_the_guard_marker_is_still_authenticated() {
    let host = host(default_handler);
    std::fs::remove_file(host.marker()).unwrap();
    let outcome = read_snapshot(&host.request(), Duration::from_secs(5), &|_| Ok(false));
    assert_eq!(outcome.err(), code(UNTRUSTED));
    assert!(host.requests().is_empty());
    let outcome = read_snapshot(&host.request(), Duration::from_secs(5), &|_| {
        Err(Stop::Code(UNAVAILABLE))
    });
    assert_eq!(outcome.err(), code(UNAVAILABLE));
    assert!(host.requests().is_empty());
}
