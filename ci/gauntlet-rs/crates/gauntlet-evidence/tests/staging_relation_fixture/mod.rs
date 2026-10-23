//! Synthetic Ed25519 and independent product/kernel fixtures for relation tests.

use base64::{engine::general_purpose::STANDARD, Engine};
use gauntlet_contracts::canonicalize;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn key() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap()
}
pub fn public() -> String {
    key()
        .public_key()
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
pub fn signed(record: Value) -> Value {
    let raw = canonicalize(record.to_string().as_bytes()).unwrap();
    json!({"record":record,"signature":STANDARD.encode(key().sign(&raw).as_ref())})
}
pub fn fixture(role: &str) -> (Value, Value) {
    let base = format!("/home/hx-{}/{role}/tasks", "a".repeat(16));
    let mut tasks = Vec::new();
    let mut idmaps = Vec::new();
    let mut observed = Vec::new();
    let mut mounts = String::new();
    for path in [
        "/",
        "/usr",
        "/opt/node",
        "/public",
        "/etc/alternatives",
        "/runtime/installed",
    ] {
        mounts += &format!("1 0 0:1 / {path} ro,nosuid,nodev - ext4 disk rw\n");
    }
    mounts += "1 0 0:1 / /dev ro,nosuid - ext4 disk rw\n";
    for path in ["/product", "/tmp"] {
        mounts += &format!("1 0 0:1 / {path} rw,nosuid,nodev - ext4 disk rw\n");
    }
    for (i, name) in ["checkout", "remote", "home"].iter().enumerate() {
        let source = format!("{base}/{name}");
        let destination = if *name == "checkout" {
            "/runtime/home/project"
        } else {
            &source
        };
        let mode = if *name == "checkout" { 0o755 } else { 0o700 };
        let task =
            json!({"source":source,"destination":destination,"device":9,"inode":i+100,"mode":mode});
        idmaps.push(
            json!({"source":source,"destination":destination,"observer_pid":42,
            "physical":{"device":9,"inode":i+100,"mode":mode,"uid":10001,"gid":10001},
            "product_view":{"device":9,"inode":i+100,"mode":mode,"uid":10004,"gid":10004}}),
        );
        let mut measured = task.clone();
        measured["physical_uid"] = json!(10001);
        measured["physical_gid"] = json!(10001);
        measured["product_uid"] = json!(10004);
        measured["product_gid"] = json!(10004);
        measured["mount_id"] = json!(i + 1);
        observed.push(measured);
        tasks.push(task);
        mounts += &format!("1 0 0:1 / {destination} rw,nosuid,nodev - ext4 disk rw\n");
    }
    let mut signed_namespaces = json!({});
    let mut kernel_namespaces = json!({});
    for (i, name) in ["mnt", "pid", "net", "ipc", "uts", "cgroup"]
        .iter()
        .enumerate()
    {
        signed_namespaces[name] = json!(format!("{name}:[{}]", i + 100));
        kernel_namespaces[name] = json!({"device":4,"inode":i+100});
    }
    let identity = json!({"pid":42,"start_time":"123","namespaces":signed_namespaces,
        "argv":["/usr/bin/python3","-I","-B","/public/actor.py","/public"],
        "mountinfo":mounts,"status":{"Uid":"\t10004\t10004\t10004\t10004",
        "Gid":"\t10004\t10004\t10004\t10004","NSpid":"\t42\t1","NoNewPrivs":"\t1","Seccomp":"\t2"}});
    let sample = json!({"pid":42,"start_ticks":123,"uid":10004,"gid":10004,"namespace_pid":1,
        "no_new_privileges":true,"seccomp_mode":2,"namespaces":kernel_namespaces,
        "argv_sha256":sha(b"/usr/bin/python3\0-I\0-B\0/public/actor.py\0/public\0"),
        "mountinfo_sha256":sha(mounts.as_bytes()),"task_mounts":observed});
    let plane = json!({"source_sha":"b".repeat(40),"workspace_path":"/runtime/home/project",
        "runtime_prefix":"/runtime/installed","task_digest":"c".repeat(64),"task_mounts":tasks,
        "cell_observations":[{"kind":"idmapped-task-mounts","declaration_digest":"c".repeat(64),"mounts":idmaps},
            {"kind":"filtered-cell","identity":identity}]});
    (plane, sample)
}
