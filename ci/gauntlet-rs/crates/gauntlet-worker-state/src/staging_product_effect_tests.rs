use super::*;

fn report() -> Value {
    let run = "a".repeat(16);
    let service = format!("hol-product-cell-{}.service", "b".repeat(32));
    let mut namespaces = serde_json::Map::new();
    for (index, name) in ["mnt", "pid", "net", "ipc", "uts", "cgroup", "user"]
        .iter()
        .enumerate()
    {
        namespaces.insert(name.to_string(), json!({"device":7,"inode":index+1}));
    }
    let rows: Vec<_> = ["checkout", "remote", "home"].iter().enumerate().map(|(i, name)| {
        let source = format!("/home/hx-{run}/success/tasks/{name}");
        let destination = if *name == "checkout" { "/runtime/home/project" } else { &source };
        let mode = if *name == "checkout" { 0o755 } else { 0o700 };
        json!({"source":source,"destination":destination,"mount_id":i+1,"device":8,"inode":i+100,
            "mode":mode,"physical_uid":10001,"physical_gid":10001,"product_uid":10004,"product_gid":10004})
    }).collect();
    json!({"live_product_activity":{
        "schema":"hol-gauntlet-staging-product-kernel.v1","run_id":run,"role":"success",
        "slice_samples":5,"process_attempts":2,"last_unavailable_reason":null,
        "continuously_observed":false,"guard_causality_verified":false,"execution_eligible":false,
        "observation":{"pid":42,"start_ticks":123,"cgroup":format!("/holgauntletrust{run}.slice/{service}"),
            "service":service,"cgroup_device":7,"cgroup_inode":8,"uid":10004,"gid":10004,"namespace_pid":1,
            "no_new_privileges":true,"seccomp_mode":2,"namespaces":namespaces,
            "executable_sha256":"c".repeat(64),"argv_sha256":"d".repeat(64),"mountinfo_sha256":"e".repeat(64),
            "task_mounts":rows}
    }})
}

#[test]
fn retained_sample_rejects_wrong_run_foreign_service_and_forged_idmap() {
    let good = report();
    assert!(matching_sample(&good, &"a".repeat(16), "success").is_ok());
    assert!(matching_sample(&good, &"c".repeat(16), "success").is_err());
    assert!(matching_sample(&good, &"a".repeat(16), "injection").is_err());
    for (path, value) in [
        (
            "/live_product_activity/observation/cgroup",
            json!("/system.slice/foreign.service"),
        ),
        (
            "/live_product_activity/observation/task_mounts/0/product_uid",
            json!(10001),
        ),
        (
            "/live_product_activity/observation/task_mounts/1/source",
            json!("/home/other"),
        ),
        (
            "/live_product_activity/observation/task_mounts/2/mode",
            json!(0o777),
        ),
        ("/live_product_activity/observation/namespace_pid", json!(2)),
        (
            "/live_product_activity/observation/namespaces/mnt/inode",
            json!(0),
        ),
        ("/live_product_activity/observation/seccomp_mode", json!(0)),
        ("/live_product_activity/continuously_observed", json!(true)),
        ("/live_product_activity/observation", Value::Null),
    ] {
        let mut changed = good.clone();
        *changed.pointer_mut(path).unwrap() = value;
        assert!(
            matching_sample(&changed, &"a".repeat(16), "success").is_err(),
            "{path}"
        );
    }
    let mut duplicate = good.clone();
    duplicate["live_product_activity"]["observation"]["task_mounts"][2] =
        duplicate["live_product_activity"]["observation"]["task_mounts"][1].clone();
    assert!(matching_sample(&duplicate, &"a".repeat(16), "success").is_err());
}
