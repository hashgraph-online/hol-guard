//! Parity vectors recorded from the retired Python implementation.
//!
//! Each case carries a file tree, the wire request and the answer the Python
//! proofs gave on the same tree. The two machine-dependent engines (launch
//! identity, package intent) are replaced by the deterministic fakes the
//! recorder used, so only the proofs under test can differ.
//!
//! Where the resident deliberately departs from the retired implementation,
//! the recorded answer is updated with it and the departure is argued in the
//! change that makes it; re-running the recorder would restore the old answer,
//! so it is not the way to resolve a difference. The tool-target family departs
//! in three places: the bytes a write tool puts into the file it names no
//! longer bind the approval, paging and formatting options no longer bind a
//! read, and one file a read tool names outside the workspace is a scope an
//! approval can cover. A directory outside it still is not, neither is any
//! path a search tool is given to walk, and neither is a write out there: the
//! bytes are not part of the identity, so naming only the path would let one
//! allow answer for every later edit of a shell profile or a launch agent.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use flate2::read::GzDecoder;
use guard_contracts::{NativeExactActionPayloadV1, NativeExactActionRequestV1};
use serde_json::{json, Value};

use super::context::{Engines, EvidenceFile, LocalExecution};
use super::{decide_with, token, Fallback};
#[path = "native_exact_action_v2_vectors.rs"]
mod v2_vectors;
#[path = "native_exact_action_v4_vectors.rs"]
mod v4_vectors;

const VECTORS: &[u8] = include_bytes!("../tests/fixtures/native_exact_action_vectors.json.gz");

struct Fake {
    #[cfg_attr(windows, allow(dead_code))]
    root: String,
    intent: Value,
}

fn evidence(value: &Value) -> Option<EvidenceFile> {
    let object = value.as_object()?;
    let text = |key: &str| object.get(key).and_then(Value::as_str).map(str::to_owned);
    Some(EvidenceFile {
        path: text("path")?,
        resolved_path: text("resolved_path"),
        status: text("status")?,
        content_hash: text("content_hash"),
    })
}

fn files(value: &Value) -> Vec<EvidenceFile> {
    value
        .as_array()
        .map(|items| items.iter().filter_map(evidence).collect())
        .unwrap_or_default()
}

impl Engines for Fake {
    fn launch_identity(
        &self,
        executable: &str,
        args: &[String],
        cwd: &str,
        home: Option<&str>,
        _env: &BTreeMap<String, String>,
    ) -> Value {
        json!({"fake_launch": true, "executable": executable, "args": args, "cwd": cwd, "home": home})
    }

    fn launch_reusable(&self, identity: &Value) -> bool {
        !identity["executable"]
            .as_str()
            .unwrap_or("")
            .contains("unreusable")
    }

    fn system_git_config(&self) -> String {
        format!("{}/etc/gitconfig", self.root)
    }

    fn local_executions(
        &self,
        _command: &str,
        _cwd: &str,
        _home: Option<&str>,
        _env: &BTreeMap<String, String>,
    ) -> Option<Vec<LocalExecution>> {
        let executions = self.intent.as_array()?;
        Some(
            executions
                .iter()
                .map(|item| LocalExecution {
                    local_executable: evidence(&item["local_executable"]),
                    manager: evidence(&item["manager"]),
                    manager_is_guard_shim: item["manager_is_guard_shim"].as_bool().unwrap_or(false),
                    package_name: item["package_name"].as_str().map(str::to_owned),
                    executable_name: item["executable_name"].as_str().map(str::to_owned),
                    manifests: files(&item["manifests"]),
                    lockfiles: files(&item["lockfiles"]),
                })
                .collect(),
        )
    }
}

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "eav-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path.canonicalize().unwrap())
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn materialize(root: &Path, tree: &serde_json::Map<String, Value>) {
    let mut entries: Vec<(&String, &Value)> =
        tree.iter().filter(|(_, spec)| !spec.is_null()).collect();
    entries.sort_by_key(|(path, _)| path.matches('/').count());
    let mut links = Vec::new();
    for (relative, spec) in entries {
        let path = root.join(relative);
        if let Some(target) = spec.get("symlink").and_then(Value::as_str) {
            links.push((path, target.to_owned()));
            continue;
        }
        if spec.get("dir").is_some() {
            std::fs::create_dir_all(&path).unwrap();
            continue;
        }
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let bytes = match spec.get("fill").and_then(Value::as_u64) {
            Some(count) => spec["char"]
                .as_str()
                .unwrap_or("x")
                .repeat(count as usize)
                .into_bytes(),
            None => spec.as_str().unwrap().as_bytes().to_vec(),
        };
        std::fs::write(&path, bytes).unwrap();
    }
    for (path, target) in links {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(target, path).unwrap();
        #[cfg(not(unix))]
        let _ = (path, target);
    }
}

fn load() -> Vec<Value> {
    let mut text = String::new();
    GzDecoder::new(VECTORS).read_to_string(&mut text).unwrap();
    let mut document: Value = serde_json::from_str(&text).unwrap();
    match document["cases"].take() {
        Value::Array(cases) => cases,
        _ => panic!("fixture has no cases"),
    }
}

/// A recorded git config digest carries the pairs it hashed, because they hold
/// absolute paths of the machine that recorded it (and config files that name
/// them, kept as text).
fn config_digest(preimage: &str) -> String {
    let mut pairs: Value = serde_json::from_str(preimage).unwrap();
    for pair in pairs.as_array_mut().unwrap() {
        if let Some(text) = pair[1]
            .as_str()
            .and_then(|text| text.strip_prefix("{FILE_SHA}"))
        {
            pair[1] = Value::String(super::fs_path::sha256_hex(text.as_bytes()));
        }
    }
    let mut encoded = Vec::new();
    guard_contracts::write_canonical_json(&pairs, &mut encoded).unwrap();
    super::fs_path::sha256_hex(&encoded)
}

fn resolve_digests(value: &mut Value) {
    match value {
        Value::String(text) => {
            if let Some(preimage) = text.strip_prefix("{GIT_CONFIG_DIGEST}") {
                *text = config_digest(preimage);
            }
        }
        Value::Array(items) => items.iter_mut().for_each(resolve_digests),
        Value::Object(map) => map.values_mut().for_each(resolve_digests),
        _ => {}
    }
}

fn clip(value: &Value) -> String {
    value.to_string().chars().take(140).collect()
}

fn first_difference(got: &Value, want: &Value) -> String {
    if let (Value::Object(left), Value::Object(right)) = (got, want) {
        for key in left.keys().chain(right.keys()) {
            if left.get(key) != right.get(key) {
                return format!(
                    ".{key}{}",
                    first_difference(
                        left.get(key).unwrap_or(&Value::Null),
                        right.get(key).unwrap_or(&Value::Null)
                    )
                );
            }
        }
    }
    format!(": {} != {}", clip(got), clip(want))
}

fn ordinary_review_binding(request: &Value, engines: &Fake) -> Option<String> {
    let mut request = request.clone();
    request["query"]["facts"]["action_type"] = json!("shell");
    let request: NativeExactActionRequestV1 = serde_json::from_value(request).unwrap();
    match decide_with(&request, engines, Fallback::Strict) {
        Ok(NativeExactActionPayloadV1::ReviewBinding { binding }) => binding,
        _ => None,
    }
}

fn run_case(case: &Value) -> Result<(), String> {
    let scratch = Scratch::new();
    let root = scratch.0.to_str().unwrap().to_owned();
    let concrete: Value = serde_json::from_str(
        &case
            .to_string()
            .replace("{ROOT}", &root.replace('\\', "\\\\")),
    )
    .unwrap();
    materialize(&scratch.0, concrete["tree"].as_object().unwrap());
    let request: NativeExactActionRequestV1 =
        serde_json::from_value(concrete["request"].clone()).unwrap();
    let engines = Fake {
        root,
        intent: concrete["intent"].clone(),
    };
    let expected = v2_vectors::expected(&concrete);
    let payload = decide_with(&request, &engines, Fallback::Strict)
        .map_err(|code| format!("error {code}"))?;
    match payload {
        NativeExactActionPayloadV1::BashSubject { .. }
        | NativeExactActionPayloadV1::LaunchEvidence { .. } => {
            Err("legacy identity vector unexpectedly returned a Bash subject".into())
        }
        NativeExactActionPayloadV1::ReviewEvidence { .. } => {
            Err("legacy identity vector unexpectedly returned review evidence".into())
        }
        NativeExactActionPayloadV1::ReviewBinding { binding } => {
            let mut want = expected["binding"].as_str().map(str::to_owned);
            if want.is_none() && concrete["request"]["query"]["facts"]["action_type"] == "package" {
                // Package reviews now get the retry binding of any other
                // review (docs/guard/approval-invariant.md); the recorded
                // Python left them unbound.
                want = ordinary_review_binding(&concrete["request"], &engines);
                if want.is_none() {
                    return Err("an ordinary review has no binding".into());
                }
            }
            (binding == want)
                .then_some(())
                .ok_or(format!("binding {binding:?} != {want:?}"))
        }
        NativeExactActionPayloadV1::ExactAction {
            token: minted,
            once_only_reason,
        } => {
            let migrated = v4_vectors::migrated(&concrete, &expected);
            let want_reason = if migrated {
                Some("script_execution_binding_unavailable".to_owned())
            } else {
                expected["once_only_reason"].as_str().map(str::to_owned)
            };
            let want_token = !migrated && expected["token_present"].as_bool().unwrap();
            if once_only_reason != want_reason || minted.is_some() != want_token {
                return Err(format!(
                    "reason {once_only_reason:?} != {want_reason:?} (token {})",
                    minted.is_some()
                ));
            }
            if minted.is_none() && !migrated {
                return Ok(());
            }
            let deadline = Instant::now() + Duration::from_secs(20);
            let observed = token::exact_action_components(&request.query, deadline, &engines);
            if migrated && !expected["token_present"].as_bool().unwrap() {
                return match observed {
                    Err(reason) if Some(reason) == expected["once_only_reason"].as_str() => Ok(()),
                    Err(reason) => Err(format!("prior inventory refusal changed: {reason}")),
                    Ok(_) => Err("prior incomplete inventory unexpectedly became complete".into()),
                };
            }
            let mut wanted = expected["components"].clone();
            resolve_digests(&mut wanted);
            let components = observed.map_err(|reason| reason.to_owned())?;
            for (name, got) in [
                ("identity", &components.identity),
                ("content", &components.content),
                ("capabilities", &components.capabilities),
                ("policy", &components.policy),
                ("sandbox", &components.sandbox),
            ] {
                if got != &wanted[name] {
                    return Err(format!("{name}{}", first_difference(got, &wanted[name])));
                }
            }
            Ok(())
        }
    }
}

/// The recorded trees and requests are POSIX: `:`-separated `PATH`s, `/`-rooted
/// paths and symlinks. The proofs model POSIX path semantics, so on Windows
/// no launch is proven (`a_windows_launch_falls_back_to_the_command_hash`).
#[cfg_attr(
    not(unix),
    ignore = "POSIX-recorded vectors; Windows launches are never proven"
)]
#[test]
fn matches_vectors_recorded_from_python() {
    let cases = load();
    v2_vectors::validate(&cases);
    v4_vectors::validate(&cases);
    assert!(cases.len() > 600, "fixture shrank to {}", cases.len());
    let failures: Vec<String> = cases
        .iter()
        .filter_map(|case| {
            run_case(case)
                .err()
                .map(|message| format!("{}: {message}", case["name"].as_str().unwrap()))
        })
        .collect();
    assert!(
        failures.is_empty(),
        "{} of {} vectors differ:\n{}",
        failures.len(),
        cases.len(),
        failures
            .iter()
            .take(25)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// The identity proofs bind `/`-rooted spellings, so on Windows a launch is
/// never proven. The approval still persists under the command hash.
#[cfg(windows)]
#[test]
fn a_windows_launch_falls_back_to_the_command_hash() {
    let case = load()
        .into_iter()
        .find(|case| case["name"] == "gate_baseline")
        .unwrap();
    assert_eq!(case["expected"]["token_present"], true);
    let scratch = Scratch::new();
    let root = scratch.0.to_str().unwrap().trim_start_matches(r"\\?\");
    let concrete: Value = serde_json::from_str(
        &case
            .to_string()
            .replace("{ROOT}", &root.replace('\\', "\\\\")),
    )
    .unwrap();
    materialize(&scratch.0, concrete["tree"].as_object().unwrap());
    let request: NativeExactActionRequestV1 =
        serde_json::from_value(concrete["request"].clone()).unwrap();
    let engines = Fake {
        root: root.to_owned(),
        intent: concrete["intent"].clone(),
    };
    let NativeExactActionPayloadV1::ExactAction {
        token,
        once_only_reason,
    } = decide_with(&request, &engines, Fallback::Strict).unwrap()
    else {
        panic!("an exact-action query answers with an exact action");
    };
    assert!(token.is_none());
    assert_eq!(once_only_reason.as_deref(), Some("unproven_launch"));
    let NativeExactActionPayloadV1::ExactAction {
        token,
        once_only_reason,
    } = super::decide(&request, &engines).unwrap()
    else {
        panic!("an exact-action query answers with an exact action");
    };
    assert!(token.is_some());
    assert!(once_only_reason.is_none());
}
