use std::fs;
use std::path::Path;

use serde_json::{json, Value};

use super::{remember, stored, MAX_STORED, STORE_NAME};
use crate::runtime_identity_probe::run_command;

const MISSING: &str = "/nonexistent/guard-runtime-probe/node";

fn artifact() -> Value {
    json!({
        "artifact_id": "artifact:node", "family": "node", "vendor": null,
        "version": "20.11.1", "build_id": null, "os": "linux", "arch": "x86_64",
        "executable_sha256": "a".repeat(64), "component_identity_sha256": null,
        "identity_assurance": "self_reported",
    })
}

fn known(pid: u32, location_id: &str) -> Value {
    json!({
        "boot_identity": "boot:1", "pid": pid, "start_identity": format!("posix:{pid}"),
        "location_id": location_id, "artifact": artifact(),
    })
}

fn instance(state: &str, pid: u32) -> Value {
    json!({
        "instance_id": format!("instance:{pid}"), "boot_identity": "boot:1", "pid": pid,
        "start_identity": format!("posix:{pid}"), "artifact_id": "artifact:node",
        "location_id": "path:node", "state": state, "coverage": "observed_only",
    })
}

fn reply(instances: &[Value]) -> Value {
    json!({
        "artifacts": [artifact()],
        "locations": [{"location_id": "path:node", "artifact_id": "artifact:node", "state": "present"}],
        "instances": instances,
    })
}

fn store(home: &Path, items: &[Value]) {
    let payload = json!({"schema": "guard.runtime-instances.v1", "instances": items});
    fs::write(home.join(STORE_NAME), payload.to_string()).expect("write");
}

fn probe(request: Value) -> Value {
    let reply = run_command(request.to_string().as_bytes()).expect("parsed");
    assert_eq!(reply["ok"], true, "{reply}");
    reply["result"].clone()
}

#[test]
fn the_store_keeps_running_instances_and_other_scopes() {
    let home = tempfile::tempdir().expect("tempdir");
    let elsewhere = known(9, "path:other");
    store(home.path(), &[known(8, "path:node"), elsewhere.clone()]);

    remember(
        home.path(),
        &reply(&[instance("running", 7), instance("exited", 8)]),
    );

    assert_eq!(stored(home.path()), vec![known(7, "path:node"), elsewhere]);
}

#[test]
fn a_write_keeps_what_another_scan_stored_after_this_one_loaded() {
    let home = tempfile::tempdir().expect("tempdir");
    store(home.path(), &[]);
    let loaded = stored(home.path());
    let other_scan = known(9, "path:other");
    store(home.path(), &[loaded, vec![other_scan.clone()]].concat());

    remember(home.path(), &reply(&[instance("running", 7)]));

    assert_eq!(stored(home.path()), vec![known(7, "path:node"), other_scan]);
}

#[test]
fn a_record_the_probe_would_refuse_costs_only_its_own_process() {
    let damaged: [(&str, Value); 10] = [
        ("pid", json!("7")),
        ("pid", json!(true)),
        ("pid", json!(0)),
        ("boot_identity", json!("")),
        ("location_id", json!(7)),
        ("artifact", {
            let mut a = artifact();
            a["vendor"] = json!(7);
            a
        }),
        ("artifact", {
            let mut a = artifact();
            a["executable_sha256"] = json!("a");
            a
        }),
        ("artifact", {
            let mut a = artifact();
            a["version"] = json!(" ");
            a
        }),
        ("artifact", {
            let mut a = artifact();
            a["identity_assurance"] = json!("vendor_verified");
            a
        }),
        ("artifact", {
            let mut a = artifact();
            a["extra"] = Value::Null;
            a
        }),
    ];
    for (field, value) in damaged {
        let home = tempfile::tempdir().expect("tempdir");
        let mut item = known(8, "path:node");
        item[field] = value;
        store(home.path(), &[item, known(9, "path:node")]);
        assert_eq!(stored(home.path()), vec![known(9, "path:node")], "{field}");
    }
    let home = tempfile::tempdir().expect("tempdir");
    let mut partial = known(8, "path:node");
    partial
        .as_object_mut()
        .expect("object")
        .remove("location_id");
    store(home.path(), &[partial]);
    assert_eq!(stored(home.path()), Vec::<Value>::new());
}

#[test]
fn a_damaged_store_reads_as_empty() {
    let home = tempfile::tempdir().expect("tempdir");
    fs::write(home.path().join(STORE_NAME), "{not json").expect("write");
    assert!(stored(home.path()).is_empty());
    let other = json!({"schema": "other", "instances": [known(7, "path:node")]});
    fs::write(home.path().join(STORE_NAME), other.to_string()).expect("write");
    assert!(stored(home.path()).is_empty());
}

#[test]
fn the_store_holds_a_bounded_number_of_instances() {
    let home = tempfile::tempdir().expect("tempdir");
    let many: Vec<Value> = (1..=u32::try_from(MAX_STORED).expect("fits") + 5)
        .map(|pid| known(pid, "path:other"))
        .collect();
    store(home.path(), &many);
    assert_eq!(stored(home.path()).len(), MAX_STORED);
    remember(home.path(), &reply(&[instance("running", 1)]));
    assert_eq!(stored(home.path()).len(), MAX_STORED);
}

#[test]
fn an_instance_home_needs_instances_and_replaces_known_instances() {
    let home = tempfile::tempdir().expect("tempdir");
    let path = home.path().to_string_lossy().into_owned();
    for request in [
        json!({"paths": [MISSING], "instance_home": path}),
        json!({"paths": [MISSING], "instances": true, "instance_home": path,
               "known_instances": [known(7, "path:node")]}),
        json!({"paths": [MISSING], "instances": true, "instance_home": "guard-home"}),
    ] {
        let reply = run_command(request.to_string().as_bytes()).expect("parsed");
        assert_eq!(
            reply["error"], "runtime_identity_probe_request_invalid",
            "{request}"
        );
    }
    assert!(!home.path().join(STORE_NAME).exists());
}

#[test]
fn a_probe_reads_and_updates_the_record_in_its_home() {
    let home = tempfile::tempdir().expect("tempdir");
    let path = home.path().to_string_lossy().into_owned();
    let location = probe(json!({"paths": [MISSING]}))["locations"][0]["location_id"]
        .as_str()
        .expect("location")
        .to_owned();
    let gone = known(7, &location);
    let elsewhere = known(9, "path:elsewhere");
    store(home.path(), &[gone, elsewhere.clone()]);

    let result = probe(json!({"paths": [MISSING], "instances": true, "instance_home": path}));

    let instance = &result["instances"][0];
    assert_eq!(instance["state"], "exited");
    assert_eq!(instance["artifact_id"], "artifact:node");
    assert_eq!(stored(home.path()), vec![elsewhere]);
}

#[test]
fn a_probe_without_a_record_starts_one() {
    let home = tempfile::tempdir().expect("tempdir");
    let guard_home = home.path().join("guard-home");
    let path = guard_home.to_string_lossy().into_owned();

    let result = probe(json!({"paths": [MISSING], "instances": true, "instance_home": path}));

    assert_eq!(result["instances"], json!([]));
    let written: Value =
        serde_json::from_slice(&fs::read(guard_home.join(STORE_NAME)).expect("read"))
            .expect("decode");
    assert_eq!(
        written,
        json!({"schema": "guard.runtime-instances.v1", "instances": []})
    );
    let leftovers: Vec<_> = fs::read_dir(&guard_home)
        .expect("list")
        .flatten()
        .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
        .collect();
    assert!(leftovers.is_empty());
}
