use serde_json::{json, Value};

use crate::runtime_identity_probe::run_command;

fn reply(request: Value) -> Value {
    run_command(request.to_string().as_bytes()).expect("parsed")
}

fn probe(request: Value) -> Value {
    let reply = reply(request);
    assert_eq!(reply["ok"], true, "{reply}");
    reply["result"].clone()
}

fn known(artifact: &str) -> Value {
    json!({
        "boot_identity": "boot:1", "pid": 7, "start_identity": "posix:1",
        "location_id": "path:elsewhere",
        "artifact": {
            "artifact_id": "artifact:old", "family": "node", "vendor": null,
            "version": "20.11.1", "build_id": null, "os": "linux", "arch": "x86_64",
            "executable_sha256": "a".repeat(64), "component_identity_sha256": null,
            "identity_assurance": artifact,
        },
    })
}

#[test]
fn a_stored_instance_cannot_claim_a_trusted_identity() {
    for assurance in ["vendor_verified", "locally_trusted"] {
        let reply = reply(json!({"instances": true, "known_instances": [known(assurance)]}));
        assert_eq!(
            reply["error"], "runtime_identity_probe_known_instance_invalid",
            "{assurance}"
        );
    }
    let reply = reply(json!({"known_instances": [known("self_reported")]}));
    assert_eq!(reply["error"], "runtime_identity_probe_request_invalid");
}

#[test]
fn a_stored_artifact_the_assessment_would_reject_is_refused() {
    let damaged: [(&str, Value); 3] = [
        ("vendor", json!(7)),
        ("executable_sha256", json!("a")),
        ("version", json!(" ")),
    ];
    for (key, value) in damaged {
        let mut item = known("self_reported");
        item["artifact"][key] = value;
        let reply = reply(json!({"instances": true, "known_instances": [item]}));
        assert_eq!(
            reply["error"], "runtime_identity_probe_known_instance_invalid",
            "{key}"
        );
    }
}

const MISSING: &str = "/nonexistent/guard-runtime-probe/node";

#[test]
fn a_known_instance_from_another_boot_has_exited() {
    let location = probe(json!({"paths": [MISSING]}))["locations"][0]["location_id"].clone();
    let mut item = known("self_reported");
    item["location_id"] = location.clone();
    let result = probe(json!({"paths": [MISSING], "instances": true, "known_instances": [item]}));
    let instance = &result["instances"][0];
    assert_eq!(instance["state"], "exited");
    assert_eq!(instance["artifact_id"], "artifact:old");
    assert_eq!(instance["location_id"], location);
    assert!(result["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .any(|artifact| artifact["artifact_id"] == "artifact:old"));
}

#[test]
fn a_known_instance_outside_the_probed_locations_is_left_out() {
    let mut unplaced = known("self_reported");
    unplaced["location_id"] = Value::Null;
    let result = probe(json!({
        "paths": [MISSING], "instances": true,
        "known_instances": [known("self_reported"), unplaced],
    }));
    assert_eq!(result["instances"], json!([]));
    assert!(!result["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .any(|artifact| artifact["artifact_id"] == "artifact:old"));
}

#[test]
fn a_probe_without_instances_keeps_its_reply_shape() {
    let result = probe(json!({"paths": []}));
    assert!(result.get("instances").is_none());
}

#[cfg(unix)]
mod unix {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command};
    use std::time::Duration;

    use serde_json::{json, Value};

    use super::probe;

    /// A copy of a system sleep binary laid out as a Node install, so the probe
    /// names it Node 20.11.1 and it can be started.
    fn runtime(root: &Path, source: &str) -> PathBuf {
        let path = root.join(".nvm/versions/node/v20.11.1/bin/node");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let staged = root.join("staged");
        fs::copy(source, &staged).unwrap();
        // Renaming over the path replaces the file the way an installer does,
        // leaving any process already running it on the old file.
        fs::rename(&staged, &path).unwrap();
        path
    }

    struct Running(Child);

    impl Drop for Running {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn start(path: &Path) -> Running {
        // A launch in the same second as the install stays unproven.
        // Process start times can read up to a second early, so wait two.
        std::thread::sleep(Duration::from_millis(2_100));
        Running(Command::new(path).arg("30").spawn().unwrap())
    }

    fn instance_of(result: &Value, pid: u32) -> Value {
        result["instances"]
            .as_array()
            .unwrap()
            .iter()
            .find(|instance| instance["pid"] == pid)
            .cloned()
            .unwrap_or_else(|| panic!("no instance for {pid}: {result}"))
    }

    fn artifact(result: &Value, id: &Value) -> Value {
        result["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|artifact| artifact["artifact_id"] == *id)
            .cloned()
            .expect("artifact listed")
    }

    fn carried(result: &Value, instance: &Value) -> Value {
        json!({
            "boot_identity": instance["boot_identity"], "pid": instance["pid"],
            "start_identity": instance["start_identity"], "location_id": instance["location_id"],
            "artifact": artifact(result, &instance["artifact_id"]),
        })
    }

    #[test]
    fn a_replaced_runtime_leaves_its_old_process_on_the_old_build() {
        let dir = tempfile::tempdir().unwrap();
        let path = runtime(dir.path(), "/bin/sleep");
        let text = path.to_string_lossy().into_owned();
        let child = start(&path);
        let pid = child.0.id();

        let before = probe(json!({"paths": [text], "instances": true}));
        let old = instance_of(&before, pid);
        let old_artifact = before["locations"][0]["artifact_id"].clone();
        assert_eq!(old["state"], "running");
        assert_eq!(old["coverage"], "observed_only");
        assert_eq!(old["artifact_id"], old_artifact);
        assert_eq!(old["location_id"], before["locations"][0]["location_id"]);

        let _ = runtime(dir.path(), "/bin/cat");
        let after = probe(json!({
            "paths": [text], "instances": true,
            "known_instances": [carried(&before, &old)],
        }));
        let new_artifact = after["locations"][0]["artifact_id"].clone();
        assert_ne!(new_artifact, old_artifact, "the file on disk changed");
        let kept = instance_of(&after, pid);
        assert_eq!(kept["instance_id"], old["instance_id"]);
        assert_eq!(
            kept["artifact_id"], old_artifact,
            "the process still runs the old build"
        );
        assert_eq!(artifact(&after, &old_artifact)["version"], "20.11.1");

        // Without the earlier binding the old process runs bytes nobody hashed.
        // Where the platform no longer reports a replaced file's path the process
        // is not seen at all, which leaves the scope incomplete.
        let unbound = probe(json!({"paths": [text], "instances": true}));
        for unknown in unbound["instances"].as_array().unwrap() {
            assert_ne!(unknown["artifact_id"], new_artifact);
            let unidentified = artifact(&unbound, &unknown["artifact_id"]);
            assert_eq!(unidentified["family"], "node");
            assert_eq!(unidentified["version"], Value::Null);
            assert_eq!(unidentified["identity_assurance"], "unknown");
        }

        let record = carried(&after, &kept);
        drop(child);
        let stopped = probe(json!({
            "paths": [text], "instances": true, "known_instances": [record],
        }));
        let exited = instance_of(&stopped, pid);
        assert_eq!(exited["state"], "exited");
        assert_eq!(exited["artifact_id"], old_artifact);
    }
}
