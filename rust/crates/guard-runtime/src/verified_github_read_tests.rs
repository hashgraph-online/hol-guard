use super::*;

struct Files {
    _dir: tempfile::TempDir,
    executor: String,
    bundle: String,
}

fn files() -> Files {
    let dir = tempfile::tempdir().expect("dir");
    let executor = dir.path().join("verified_github_reads.py");
    let bundle = dir.path().join("ca.pem");
    fs::write(&executor, b"executor").expect("executor");
    fs::write(&bundle, b"bundle").expect("bundle");
    Files {
        executor: executor.to_str().expect("utf-8").to_owned(),
        bundle: bundle.to_str().expect("utf-8").to_owned(),
        _dir: dir,
    }
}

fn request(files: &Files, op: &str) -> Value {
    json!({
        "op": op,
        "owner": "hashgraph-online",
        "repository": "hol-guard",
        "pull_number": 17,
        "fields": ["number", "state", "mergeable"],
        "network_policy": {
            "proxyMode": "system",
            "proxyConfigured": false,
            "caBundleConfigured": true,
            "allowPublicRegistries": true,
        },
        "ca_bundle_path": files.bundle,
        "executor_path": files.executor,
    })
}

fn plan(files: &Files) -> Value {
    answer(request(files, "plan")).expect("plan")
}

fn repository_reply() -> Value {
    json!({"private": false, "full_name": "HashGraph-Online/hol-guard"})
}

fn pull_reply() -> Value {
    json!({
        "number": 17,
        "state": "open",
        "mergeable": true,
        "base": {"repo": {"full_name": "hashgraph-online/HOL-guard"}},
        "title": "not shown",
    })
}

fn compose(files: &Files, identity: &Value, repository: &[u8], pull: &[u8]) -> Value {
    let mut request = request(files, "compose");
    let members = request.as_object_mut().expect("object");
    members.insert("identity".to_owned(), identity.clone());
    members.insert("tls_runtime".to_owned(), json!("OpenSSL 3.0.13"));
    members.insert(
        "repository_body".to_owned(),
        json!(STANDARD.encode(repository)),
    );
    members.insert("pull_body".to_owned(), json!(STANDARD.encode(pull)));
    answer(request).expect("compose")
}

fn body(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).expect("body")
}

#[test]
fn the_plan_names_the_two_exact_api_urls_and_sorted_fields() {
    let files = files();
    let planned = plan(&files);
    assert_eq!(planned["fields"], json!(["mergeable", "number", "state"]));
    assert_eq!(
        planned["urls"],
        json!([
            "https://api.github.com/repos/hashgraph-online/hol-guard",
            "https://api.github.com/repos/hashgraph-online/hol-guard/pulls/17",
        ])
    );
    assert_eq!(planned["identity"].as_str().map(str::len), Some(64));
}

#[test]
fn a_public_pull_request_composes_its_output_and_a_stable_proof() {
    let files = files();
    let identity = plan(&files)["identity"].clone();
    let composed = compose(
        &files,
        &identity,
        &body(&repository_reply()),
        &body(&pull_reply()),
    );
    assert_eq!(
        composed["stdout"],
        json!("{\"mergeable\":true,\"number\":17,\"state\":\"open\"}\n")
    );
    let binding = composed["binding_digest"].as_str().expect("digest");
    assert_eq!(binding.len(), 64);
    let again = compose(
        &files,
        &identity,
        &body(&repository_reply()),
        &body(&pull_reply()),
    );
    assert_eq!(again["binding_digest"], json!(binding));

    let mut marked = b"\xef\xbb\xbf".to_vec();
    marked.extend_from_slice(&body(&repository_reply()));
    let mut pull = pull_reply();
    pull["mergeable"] = Value::Null;
    let unknown = compose(&files, &identity, &marked, &body(&pull));
    assert_eq!(
        unknown["stdout"],
        json!("{\"mergeable\":null,\"number\":17,\"state\":\"open\"}\n")
    );
    assert_ne!(unknown["binding_digest"], json!(binding));
}

#[test]
fn only_the_requested_fields_are_shown() {
    let files = files();
    let mut request = request(&files, "plan");
    request["fields"] = json!(["state"]);
    let identity = answer(request.clone()).expect("plan")["identity"].clone();
    let members = request.as_object_mut().expect("object");
    members.insert("op".to_owned(), json!("compose"));
    members.insert("identity".to_owned(), identity);
    members.insert("tls_runtime".to_owned(), json!("OpenSSL"));
    members.insert(
        "repository_body".to_owned(),
        json!(STANDARD.encode(body(&repository_reply()))),
    );
    members.insert(
        "pull_body".to_owned(),
        json!(STANDARD.encode(body(&pull_reply()))),
    );
    assert_eq!(
        answer(request).expect("compose")["stdout"],
        json!("{\"state\":\"open\"}\n")
    );
}

#[test]
fn replies_that_do_not_prove_a_public_pull_request_are_unverified() {
    let files = files();
    let identity = plan(&files)["identity"].clone();
    let unverified = json!({"verified": false});
    let mut repositories = Vec::new();
    for (key, value) in [
        ("private", json!(true)),
        ("private", Value::Null),
        ("full_name", json!("hashgraph-online/other")),
        ("full_name", json!(7)),
    ] {
        let mut repository = repository_reply();
        repository[key] = value;
        repositories.push(body(&repository));
    }
    repositories.push(b"[]".to_vec());
    repositories.push(b"not json".to_vec());
    repositories.push(b"\xff".to_vec());
    let mut oversized = body(&repository_reply());
    oversized.resize(MAX_RESPONSE_BYTES + 1, b' ');
    repositories.push(oversized);
    for repository in repositories {
        assert_eq!(
            compose(&files, &identity, &repository, &body(&pull_reply())),
            unverified
        );
    }

    let mut pulls = Vec::new();
    for (key, value) in [
        ("number", json!(18)),
        ("number", json!("17")),
        ("number", json!(17.0)),
        ("state", json!("merged")),
        ("mergeable", json!("yes")),
        ("base", json!({"repo": {"full_name": "fork/hol-guard"}})),
        ("base", json!({"repo": "hashgraph-online/hol-guard"})),
    ] {
        let mut pull = pull_reply();
        pull[key] = value;
        pulls.push(body(&pull));
    }
    for pull in pulls {
        assert_eq!(
            compose(&files, &identity, &body(&repository_reply()), &pull),
            unverified
        );
    }
}

#[test]
fn a_ca_bundle_or_executor_change_during_the_read_is_unverified() {
    let files = files();
    let identity = plan(&files)["identity"].clone();
    fs::write(&files.bundle, b"another bundle").expect("bundle");
    let unverified = json!({"verified": false});
    assert_eq!(
        compose(
            &files,
            &identity,
            &body(&repository_reply()),
            &body(&pull_reply())
        ),
        unverified
    );

    let files = self::files();
    let identity = plan(&files)["identity"].clone();
    fs::write(&files.executor, b"edited").expect("executor");
    assert_eq!(
        compose(
            &files,
            &identity,
            &body(&repository_reply()),
            &body(&pull_reply())
        ),
        unverified
    );

    let files = self::files();
    fs::remove_file(&files.bundle).expect("remove");
    // Without an identity Python never sends the requests.
    assert_eq!(plan(&files)["identity"], Value::Null);
    let identity = plan(&self::files())["identity"].clone();
    assert_eq!(
        compose(
            &files,
            &identity,
            &body(&repository_reply()),
            &body(&pull_reply())
        ),
        unverified
    );
}

#[test]
fn the_network_policy_is_part_of_the_identity() {
    let files = files();
    let planned = plan(&files)["identity"].clone();
    let mut request = request(&files, "plan");
    request["network_policy"]["proxyMode"] = json!("managed");
    assert_ne!(answer(request).expect("plan")["identity"], planned);
    let mut request = self::request(&files, "plan");
    request["ca_bundle_path"] = Value::Null;
    assert_ne!(answer(request).expect("plan")["identity"], planned);
}

#[cfg(unix)]
#[test]
fn a_linked_identity_file_is_not_read() {
    let files = files();
    let link = Path::new(&files.executor).with_file_name("link.py");
    std::os::unix::fs::symlink(&files.executor, &link).expect("link");
    let mut request = request(&files, "plan");
    request["executor_path"] = json!(link.to_str().expect("utf-8"));
    assert_eq!(answer(request).expect("plan")["identity"], Value::Null);
}

#[test]
fn requests_outside_the_reviewed_shape_are_refused() {
    let files = files();
    let mut refused = Vec::new();
    for (key, value) in [
        ("owner", json!("-leading")),
        ("owner", json!("a/b")),
        ("owner", json!("x".repeat(101))),
        ("repository", json!("")),
        ("repository", json!("é")),
        ("pull_number", json!(0)),
        ("pull_number", json!(2_147_483_648_u64)),
        ("pull_number", json!(-1)),
        ("pull_number", json!(true)),
        ("fields", json!([])),
        ("fields", json!(["state", "state"])),
        ("fields", json!(["title"])),
        ("fields", json!([1])),
        ("op", json!("fetch")),
        ("unknown", json!(1)),
        ("tls_runtime", json!("OpenSSL")),
    ] {
        let mut request = request(&files, "plan");
        request[key] = value;
        refused.push(request);
    }
    let mut incomplete = request(&files, "compose");
    incomplete["identity"] = json!("x");
    refused.push(incomplete);
    let mut undecodable = request(&files, "compose");
    for key in ["identity", "tls_runtime", "repository_body"] {
        undecodable[key] = json!("x");
    }
    undecodable["pull_body"] = json!("%%%");
    refused.push(undecodable);
    for request in refused {
        assert_eq!(answer(request), Err(invalid()));
    }
    assert_eq!(
        run_command(&b"x"[..]),
        Err("verified_github_read_request_invalid".to_owned())
    );
    let oversized = vec![b' '; MAX_REQUEST_BYTES as usize + 1];
    assert_eq!(
        run_command(&oversized[..]),
        Err("verified_github_read_request_too_large".to_owned())
    );
}

#[test]
fn the_command_names_verified_github_read() {
    assert!(is_command("verified-github-read"));
    assert!(!is_command("verified-read"));
}
