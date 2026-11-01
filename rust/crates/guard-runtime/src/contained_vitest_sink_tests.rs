use super::*;

fn words(command: &[&str]) -> Vec<String> {
    command.iter().map(|word| (*word).to_owned()).collect()
}

fn response(fields: Value) -> Map<String, Value> {
    let Value::Object(response) = fields else {
        unreachable!()
    };
    response
}

#[test]
fn the_tsx_loader_names_the_package_the_image_is_found_from() {
    let loader = "file:///w/node_modules/tsx/dist/loader.mjs";
    assert_eq!(
        tsx_package_dir(&words(&["node", "--import", loader, "x.test.ts"])),
        Some(PathBuf::from("/w/node_modules/tsx"))
    );
    assert_eq!(
        tsx_package_dir(&words(&[
            "node",
            "--import",
            "file:///my%20app/node_modules/tsx/dist/loader.mjs"
        ])),
        Some(PathBuf::from("/my app/node_modules/tsx"))
    );
    assert_eq!(
        tsx_package_dir(&words(&[
            "node",
            "--import",
            "file:/w/node_modules/tsx/dist/loader.mjs?v=1"
        ])),
        Some(PathBuf::from("/w/node_modules/tsx"))
    );
    for command in [
        words(&["node", "--require", loader]),
        words(&["node", "--import", "/w/node_modules/tsx/dist/loader.mjs"]),
        words(&[
            "node",
            "--import",
            "file:///w/node_modules/tsx/dist/esm.mjs",
        ]),
        words(&[
            "node",
            "--import",
            "file:///w/node_modules/tsy/dist/loader.mjs",
        ]),
        words(&["node", "--import"]),
    ] {
        assert_eq!(tsx_package_dir(&command), None, "{command:?}");
    }
}

#[test]
fn the_image_starts_only_when_the_resident_allows_it_or_reads_it_as_this_run() {
    let route = readonly::VITEST_ROUTE;
    let allowed = response(json!({"decision": "allow", "policy_action": "allow"}));
    assert!(capability_allowed(&allowed, route));
    let contained = response(json!({
        "decision": "deny",
        "policy_action": "sandbox-required",
        "reason_code": route.0,
        "required_execution_profile": route.1,
    }));
    assert!(capability_allowed(&contained, route));
    let mut observed = allowed.clone();
    observed.insert("observe_mode".into(), Value::Bool(true));
    for refused in [
        observed,
        response(json!({"decision": "allow", "policy_action": "require-reapproval"})),
        response(json!({"decision": "deny", "policy_action": "allow"})),
        response(json!({
            "decision": "deny",
            "policy_action": "sandbox-required",
            "reason_code": "native_workspace_containment_required",
            "required_execution_profile": route.1,
        })),
        Map::new(),
    ] {
        assert!(!capability_allowed(&refused, route), "{refused:?}");
    }
}

#[test]
fn the_localhost_preload_is_written_once_and_read_only() {
    let private = tempfile::tempdir().expect("private");
    let preload = write_preload(private.path()).expect("preload");
    assert_eq!(preload, private.path().join("localhost-resolution.cjs"));
    assert_eq!(
        std::fs::read_to_string(&preload).expect("source"),
        LOCALHOST_RESOLUTION
    );
    let mode = std::os::unix::fs::MetadataExt::mode(&std::fs::metadata(&preload).expect("mode"));
    assert_eq!(mode & 0o777, 0o400);
    assert!(write_preload(private.path()).is_err());
}

#[test]
fn the_images_directory_goes_with_its_guard() {
    let images = Images::create().expect("images");
    let path = images.path.clone();
    std::fs::write(path.join("esbuild"), b"image").expect("image");
    drop(images);
    assert!(!path.exists());
}
