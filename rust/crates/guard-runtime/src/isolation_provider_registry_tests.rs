use serde_json::{json, Value};

use super::dispatch;
use crate::runner_authority_op::ERR_INVALID;

const ROOT: &str = "/usr/libexec/hol-guard/providers";

fn parts(path: &str) -> Vec<String> {
    let mut parts = vec!["/".to_owned()];
    parts.extend(
        path.split('/')
            .filter(|part| !part.is_empty())
            .map(str::to_owned),
    );
    parts
}

fn plan(raw: &str, resolved: &str) -> Value {
    let name = resolved.rsplit('/').next().unwrap_or_default();
    let path = json!({ "raw": raw, "resolved": resolved, "name": name, "parts": parts(resolved) });
    dispatch(&json!({ "op": "plan_inputs", "paths": [path] })).unwrap()
}

#[test]
fn a_plan_input_on_the_forbidden_host_set_is_refused() {
    for (raw, refusal) in [
        ("/home/user/project/.env", "forbidden_path"),
        ("/root/.ssh/id_rsa", "forbidden_path"),
        ("/repo/.git/config", "forbidden_path"),
        ("/repo/.hg/config", "forbidden_path"),
        ("/repo/.SVN/config", "forbidden_path"),
        ("/home/user/.GnuPG", "forbidden_path"),
        ("/var/run/docker.sock", "control_socket"),
        ("/run/containerd/containerd.sock", "control_socket"),
        ("/home/user/.hol-guard/state.db", "guard_state"),
        ("/srv/guard-state/x", "guard_state"),
    ] {
        assert_eq!(
            plan(raw, raw),
            json!({ "refusal": refusal, "index": 0 }),
            "{raw}"
        );
    }
    // A socket is refused by its spelling or by where it resolves.
    assert_eq!(
        plan("/tmp/docker-link", "/var/run/docker.sock")["refusal"],
        json!("control_socket")
    );
}

#[test]
fn a_benign_plan_input_passes_and_the_first_refusal_names_its_index() {
    for raw in [
        "/home/user/project/src/main.py",
        "/tmp/workspace/output.txt",
        "/work/.envrc",
    ] {
        assert_eq!(plan(raw, raw), json!({ "refusal": null }), "{raw}");
    }
    let path = |raw: &str| {
        let name = raw.rsplit('/').next().unwrap();
        json!({ "raw": raw, "resolved": raw, "name": name, "parts": parts(raw) })
    };
    let request = json!({
        "op": "plan_inputs",
        "paths": [path("/work/a.txt"), path("/app/.env"), path("/root/.ssh/id_rsa")],
    });
    assert_eq!(
        dispatch(&request).unwrap(),
        json!({ "refusal": "forbidden_path", "index": 1 })
    );
}

fn locate(path: &str, lexical: &str) -> Value {
    let request = json!({
        "op": "locate",
        "root": ROOT,
        "root_parts": parts(ROOT),
        "path_parts": parts(path),
        "lexical": lexical,
    });
    dispatch(&request).unwrap()["refusal"].clone()
}

#[test]
fn a_provider_path_must_resolve_inside_the_root() {
    let inside = format!("{ROOT}/seatbelt");
    assert_eq!(locate(&inside, &inside), Value::Null);
    assert_eq!(
        locate(
            "/home/user/project/.guard/provider",
            "/home/user/project/.guard/provider"
        ),
        json!("outside")
    );
    assert_eq!(
        locate(
            "/usr/libexec/hol-guard/evil/bin",
            "/usr/libexec/hol-guard/providers/../evil/bin"
        ),
        json!("outside")
    );
    // A sibling that shares the root's spelling as a prefix is not inside it.
    assert_eq!(
        locate(
            "/usr/libexec/hol-guard/providers-x/bin",
            "/usr/libexec/hol-guard/providers-x/bin"
        ),
        json!("outside")
    );
}

#[cfg(unix)]
#[test]
fn a_symlink_between_the_root_and_the_artifact_is_refused() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().join("providers");
    std::fs::create_dir_all(root.join("real")).expect("mkdir");
    std::os::unix::fs::symlink(root.join("real"), root.join("link")).expect("symlink");
    let request = |lexical: std::path::PathBuf| {
        let root = root.to_str().unwrap();
        let lexical = lexical.to_str().unwrap();
        json!({
            "op": "locate",
            "root": root,
            "root_parts": parts(root),
            "path_parts": parts(lexical),
            "lexical": lexical,
        })
    };
    let linked = dispatch(&request(root.join("link/bin"))).unwrap();
    assert_eq!(linked["refusal"], json!("symlink"));
    let real = dispatch(&request(root.join("real/bin"))).unwrap();
    assert_eq!(real["refusal"], Value::Null);
}

#[cfg(unix)]
#[test]
fn the_artifact_digest_reads_a_regular_file_and_never_a_link() {
    let directory = tempfile::tempdir().expect("tempdir");
    let artifact = directory.path().join("provider");
    std::fs::write(&artifact, b"trusted-provider").expect("write");
    let digest = |path: &std::path::Path| {
        dispatch(&json!({ "op": "digest", "path": path.to_str().unwrap() })).unwrap()
    };
    let expected = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(b"trusted-provider"));
    assert_eq!(digest(&artifact), json!({ "digest": expected }));
    let link = directory.path().join("provider-link");
    std::os::unix::fs::symlink(&artifact, &link).expect("symlink");
    assert_eq!(digest(&link), json!({ "refusal": "unreadable" }));
    assert_eq!(
        digest(directory.path()),
        json!({ "refusal": "not_regular" })
    );
    assert_eq!(
        digest(&directory.path().join("missing")),
        json!({ "refusal": "unreadable" })
    );
}

#[cfg(unix)]
mod registry {
    use std::os::unix::fs::PermissionsExt;

    use serde_json::{json, Value};

    use super::dispatch;

    fn load(config: &std::path::Path) -> Value {
        dispatch(&json!({ "op": "registry", "config": config.to_str().unwrap() })).unwrap()
    }

    fn anchor() -> Value {
        json!({
            "providerKind": "oci-isolation",
            "implementationVersion": "1.0.0",
            "binaryOrImageDigest": "a".repeat(64),
            "signingIdentity": "guard",
            "trustDomain": "guard.local",
        })
    }

    fn write(config: &std::path::Path, payload: &Value, mode: u32) {
        std::fs::write(config, payload.to_string()).expect("write");
        std::fs::set_permissions(config, std::fs::Permissions::from_mode(mode)).expect("chmod");
    }

    #[test]
    fn a_missing_registry_declares_no_provider() {
        let directory = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            load(&directory.path().join("providers.json")),
            json!({ "declarations": [] })
        );
    }

    #[test]
    fn an_admin_owned_registry_lists_its_pinned_providers() {
        let directory = tempfile::tempdir().expect("tempdir");
        let config = directory.path().join("providers.json");
        let declaration =
            json!({ "kind": "oci-isolation", "path": "/usr/libexec/p", "trustAnchor": anchor() });
        write(
            &config,
            &json!({ "schema": "guard.provider-registry.v1", "providers": [declaration] }),
            0o600,
        );
        assert_eq!(
            load(&config),
            json!({ "declarations": [{ "path": "/usr/libexec/p", "trustAnchor": anchor() }] })
        );
    }

    #[test]
    fn a_registry_others_can_write_or_reach_by_link_is_refused() {
        let directory = tempfile::tempdir().expect("tempdir");
        let config = directory.path().join("providers.json");
        let payload = json!({ "schema": "guard.provider-registry.v1", "providers": [] });
        write(&config, &payload, 0o620);
        assert_eq!(
            load(&config),
            json!({ "refusal": "managed provider registry is not admin-owned" })
        );
        write(&config, &payload, 0o602);
        assert_eq!(
            load(&config),
            json!({ "refusal": "managed provider registry is not admin-owned" })
        );
        write(&config, &payload, 0o600);
        let link = directory.path().join("link.json");
        std::os::unix::fs::symlink(&config, &link).expect("symlink");
        assert_eq!(
            load(&link),
            json!({ "refusal": "managed provider registry is unreadable" })
        );
    }

    #[test]
    fn a_malformed_registry_names_what_is_wrong() {
        let directory = tempfile::tempdir().expect("tempdir");
        let config = directory.path().join("providers.json");
        let schema = "guard.provider-registry.v1";
        let mut partial = anchor();
        partial["trustDomain"] = json!("");
        for (payload, refusal) in [
            (json!([]), "managed provider registry is invalid"),
            (
                json!({ "schema": "other", "providers": [] }),
                "managed provider registry schema is invalid",
            ),
            (
                json!({ "schema": schema, "providers": {} }),
                "managed provider registry providers are invalid",
            ),
            (
                json!({ "schema": schema, "providers": [1] }),
                "managed provider declaration is invalid",
            ),
            (
                json!({ "schema": schema, "providers": [{ "kind": "docker", "path": "/usr/p", "trustAnchor": anchor() }] }),
                "managed provider declaration is invalid",
            ),
            (
                json!({ "schema": schema, "providers": [{ "kind": "oci-isolation", "path": "/usr/p", "trustAnchor": partial }] }),
                "managed provider trust anchor is invalid",
            ),
        ] {
            write(&config, &payload, 0o600);
            assert_eq!(load(&config), json!({ "refusal": refusal }), "{payload}");
        }
        std::fs::write(&config, b"{not json").expect("write");
        assert_eq!(
            load(&config),
            json!({ "refusal": "managed provider registry is invalid" })
        );
    }
}

#[test]
fn refuses_malformed_requests() {
    for request in [
        json!([]),
        json!({ "op": "plan_inputs", "paths": "x" }),
        json!({ "op": "plan_inputs", "paths": [{ "raw": "/x" }] }),
        json!({ "op": "locate", "root": ROOT, "root_parts": [], "path_parts": [1], "lexical": "/x" }),
        json!({ "op": "digest", "path": "/x", "extra": 1 }),
        json!({ "op": "registry" }),
        json!({ "op": "register", "config": "/x" }),
    ] {
        assert_eq!(dispatch(&request), Err(ERR_INVALID), "{request}");
    }
}
