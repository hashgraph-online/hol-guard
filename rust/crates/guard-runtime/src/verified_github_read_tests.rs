use std::path::PathBuf;

use super::*;

const REPOSITORY_URL: &str = "https://api.github.com/repos/hashgraph-online/hol-guard";
const PULL_URL: &str = "https://api.github.com/repos/hashgraph-online/hol-guard/pulls/17";

struct Network {
    _dir: tempfile::TempDir,
    bundle: PathBuf,
    policy: ManagedNetworkPolicy,
}

fn network() -> Network {
    let dir = tempfile::tempdir().expect("dir");
    let bundle = dir.path().join("ca.pem");
    fs::write(&bundle, b"bundle").expect("bundle");
    let policy = ManagedNetworkPolicy {
        ca_bundle_path: Some(bundle.clone()),
        ..ManagedNetworkPolicy::unmanaged_default()
    };
    Network {
        _dir: dir,
        bundle,
        policy,
    }
}

fn request() -> Value {
    json!({
        "op": "read",
        "owner": "hashgraph-online",
        "repository": "hol-guard",
        "pull_number": 17,
        "fields": ["number", "state", "mergeable"],
        "timeout_seconds": 15.0,
    })
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

fn body(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).expect("body")
}

/// The answer to `request` when the two URLs reply with `repository` and `pull`.
fn read_with(network: &Network, request: Value, repository: &[u8], pull: &[u8]) -> Value {
    let (read, fields) = checked(request).expect("reviewed shape");
    compose_read(&read, &fields, &network.policy, |url| match url {
        REPOSITORY_URL => Some(repository.to_vec()),
        PULL_URL => Some(pull.to_vec()),
        _ => None,
    })
}

fn read(network: &Network, repository: &[u8], pull: &[u8]) -> Value {
    read_with(network, request(), repository, pull)
}

#[test]
fn a_public_pull_request_composes_its_output_and_a_stable_proof() {
    let network = network();
    let composed = read(&network, &body(&repository_reply()), &body(&pull_reply()));
    assert_eq!(
        composed["stdout"],
        json!("{\"mergeable\":true,\"number\":17,\"state\":\"open\"}\n")
    );
    let binding = composed["binding_digest"].as_str().expect("digest");
    assert_eq!(binding.len(), 64);
    let again = read(&network, &body(&repository_reply()), &body(&pull_reply()));
    assert_eq!(again["binding_digest"], json!(binding));

    let mut marked = b"\xef\xbb\xbf".to_vec();
    marked.extend_from_slice(&body(&repository_reply()));
    let mut pull = pull_reply();
    pull["mergeable"] = Value::Null;
    let unknown = read(&network, &marked, &body(&pull));
    assert_eq!(
        unknown["stdout"],
        json!("{\"mergeable\":null,\"number\":17,\"state\":\"open\"}\n")
    );
    assert_ne!(unknown["binding_digest"], json!(binding));
}

#[test]
fn a_failed_exchange_ends_the_read_and_fields_come_back_sorted() {
    let network = network();
    let (read, fields) = checked(request()).expect("reviewed shape");
    let mut asked = Vec::new();
    let answer = compose_read(&read, &fields, &network.policy, |url| {
        asked.push(url.to_owned());
        None
    });
    assert_eq!(answer, json!({"verified": false}));
    assert_eq!(asked, vec![REPOSITORY_URL.to_owned()]);
    assert_eq!(fields, vec!["mergeable", "number", "state"]);
}

#[test]
fn only_the_requested_fields_are_shown() {
    let network = network();
    let mut request = request();
    request["fields"] = json!(["state"]);
    let answer = read_with(
        &network,
        request,
        &body(&repository_reply()),
        &body(&pull_reply()),
    );
    assert_eq!(answer["stdout"], json!("{\"state\":\"open\"}\n"));
}

#[test]
fn replies_that_do_not_prove_a_public_pull_request_are_unverified() {
    let network = network();
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
            read(&network, &repository, &body(&pull_reply())),
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
            read(&network, &body(&repository_reply()), &pull),
            unverified
        );
    }
}

#[test]
fn a_ca_bundle_change_during_the_read_is_unverified() {
    let network = network();
    let (read, fields) = checked(request()).expect("reviewed shape");
    let answer = compose_read(&read, &fields, &network.policy, |url| {
        if url == PULL_URL {
            fs::write(&network.bundle, b"another bundle").expect("bundle");
            return Some(body(&pull_reply()));
        }
        Some(body(&repository_reply()))
    });
    assert_eq!(answer, json!({"verified": false}));

    let network = self::network();
    fs::remove_file(&network.bundle).expect("remove");
    let (read, fields) = checked(request()).expect("reviewed shape");
    let mut asked = false;
    let answer = compose_read(&read, &fields, &network.policy, |_| {
        asked = true;
        None
    });
    // Without an identity no request is sent.
    assert_eq!(answer, json!({"verified": false}));
    assert!(!asked);
}

#[test]
fn the_network_policy_is_part_of_the_identity() {
    let network = network();
    let planned = identity(&network.policy).expect("identity");
    let mut explicit = network.policy.clone();
    explicit.proxy_mode = ProxyMode::Explicit;
    assert_ne!(identity(&explicit), Some(planned.clone()));
    let mut unbundled = network.policy.clone();
    unbundled.ca_bundle_path = None;
    assert_ne!(identity(&unbundled), Some(planned.clone()));
    fs::write(&network.bundle, b"another bundle").expect("bundle");
    assert_ne!(identity(&network.policy), Some(planned));
}

#[cfg(unix)]
#[test]
fn a_linked_ca_bundle_is_not_read() {
    let network = network();
    let link = network.bundle.with_file_name("link.pem");
    std::os::unix::fs::symlink(&network.bundle, &link).expect("link");
    let mut policy = network.policy.clone();
    policy.ca_bundle_path = Some(link);
    assert_eq!(identity(&policy), None);
}

#[test]
fn requests_outside_the_reviewed_shape_are_refused() {
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
        ("op", json!("plan")),
        ("op", json!("compose")),
        ("unknown", json!(1)),
        ("timeout_seconds", json!(0)),
        ("timeout_seconds", json!(30.5)),
        ("timeout_seconds", json!("15")),
    ] {
        let mut request = request();
        request[key] = value;
        refused.push(request);
    }
    let mut untimed = request();
    untimed
        .as_object_mut()
        .expect("object")
        .remove("timeout_seconds");
    refused.push(untimed);
    for request in refused {
        assert_eq!(checked(request).map(|_| ()), Err(invalid()));
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
