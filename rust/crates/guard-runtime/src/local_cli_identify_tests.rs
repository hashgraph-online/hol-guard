//! Parity vectors recorded from the retired Python identification.
//!
//! Each case carries a file tree, the wire request and the identities the
//! Python gave on the same tree. Launch identity and package intent are the
//! deterministic fakes the recorder installed, so only the identification
//! under test can differ.

use std::collections::BTreeMap;
#[cfg(unix)]
use std::io::Read;
use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;
#[cfg(unix)]
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(unix)]
use flate2::read::GzDecoder;
#[cfg(unix)]
use guard_contracts::LocalCliIdentitySourceV1;
#[cfg(unix)]
use serde_json::Map;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::{identify_with, owned_executables, Request};
#[cfg(unix)]
use crate::context_digest_local_cli::local_cli_identity;
use crate::native_exact_action_op::context::{Engines, EvidenceFile, LocalExecution};

// The recorded vectors materialize symlinked trees, so only unix replays them.
#[cfg(unix)]
const VECTORS: &[u8] = include_bytes!("../tests/fixtures/local_cli_identify_vectors.json.gz");
const SCRIPT_KINDS: [(&str, &str); 8] = [
    ("python3", "python-script"),
    ("python", "python-script"),
    ("node", "node-script"),
    ("bash", "bash-script"),
    ("sh", "sh-script"),
    ("zsh", "zsh-script"),
    ("ruby", "ruby-script"),
    ("tsx", "tsx-script"),
];

/// Mirrors the recorder's `fake_launch` and package-intent fake.
struct Fake {
    root: String,
    intent: Value,
}

impl Fake {
    fn sha(&self, text: &str) -> String {
        hex::encode(Sha256::digest(
            text.replace(&self.root, "{ROOT}").as_bytes(),
        ))
    }
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
        _home: Option<&str>,
        _env: &BTreeMap<String, String>,
    ) -> Value {
        let name = executable
            .replace('\\', "/")
            .rsplit('/')
            .next()
            .unwrap_or("")
            .to_lowercase();
        let first = args.first().map(String::as_str);
        let resolve = |value: &str| {
            if value.starts_with('/') {
                value.to_owned()
            } else {
                format!("{cwd}/{value}")
            }
        };
        let verified = |path: &str| {
            if Path::new(path).is_file() {
                "verified"
            } else {
                "missing"
            }
        };
        let script_kind = SCRIPT_KINDS.iter().find(|(key, _)| *key == name);
        let (path, kind, status) = match (script_kind, first) {
            (Some((_, kind)), Some(first)) if !["-c", "-m", "-e"].contains(&first) => {
                let path = resolve(first);
                let status = verified(&path);
                (Some(path), *kind, status)
            }
            (_, Some(flag @ ("-c" | "-m"))) => {
                let kind = match (name.starts_with("python"), flag) {
                    (true, "-c") => "python-c",
                    (true, _) => "python-m",
                    _ => "inline-script",
                };
                (None, kind, "verified")
            }
            (_, Some("run")) if name == "bun" => (
                Some(format!("{cwd}/package.json")),
                "bun-package-script",
                "verified",
            ),
            _ if executable.contains('/') && (name.ends_with(".sh") || name.ends_with(".py")) => {
                let path = resolve(executable);
                let status = verified(&path);
                (Some(path), "direct-script", status)
            }
            _ => (None, "none", "not-applicable"),
        };
        let mut entrypoint = json!({"kind": kind, "status": status});
        if let Some(path) = path {
            entrypoint["sha256"] = json!(self.sha(&path));
            entrypoint["path"] = json!(path);
        }
        let exe_path = if executable.contains('/') {
            resolve(executable)
        } else {
            format!("/fake/bin/{name}")
        };
        let exe_status = if name.contains("unverifiable") {
            "unverified"
        } else {
            "verified"
        };
        json!({
            "fake_launch": true,
            "executable": {"path": exe_path, "sha256": self.sha(&exe_path), "status": exe_status},
            "entrypoint": entrypoint,
        })
    }

    fn launch_reusable(&self, identity: &Value) -> bool {
        !identity["executable"]["path"]
            .as_str()
            .unwrap_or("")
            .contains("unreusable")
    }

    fn local_executions(
        &self,
        _command: &str,
        _cwd: &str,
        _home: Option<&str>,
        _env: &BTreeMap<String, String>,
    ) -> Option<Vec<LocalExecution>> {
        // A parser failure ("raise") reached the old caller as no intent.
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

#[cfg(unix)]
struct Scratch(PathBuf);

#[cfg(unix)]
impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "lci-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path.canonicalize().unwrap())
    }
}

#[cfg(unix)]
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(unix)]
fn materialize(root: &Path, tree: &Map<String, Value>) {
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
        std::fs::write(&path, spec.as_str().unwrap()).unwrap();
    }
    for (path, target) in links {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(target, path).unwrap();
    }
}

#[cfg(unix)]
fn vectors() -> Vec<Value> {
    let mut text = String::new();
    GzDecoder::new(VECTORS).read_to_string(&mut text).unwrap();
    let document: Value = serde_json::from_str(&text).unwrap();
    document["cases"].as_array().unwrap().clone()
}

#[cfg(unix)]
fn concretize(value: &Value, root: &str) -> Value {
    serde_json::from_str(&value.to_string().replace("{ROOT}", root)).unwrap()
}

#[cfg(unix)]
#[test]
fn identification_matches_the_retired_python() {
    let owned = owned_executables().unwrap();
    let cases = vectors();
    assert_eq!(cases.len(), 100);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let scratch = Scratch::new();
        let root = scratch.0.to_str().unwrap().to_owned();
        let concrete = concretize(&case, &root);
        materialize(&scratch.0, concrete["tree"].as_object().unwrap());
        let request = &concrete["request"];
        let env: BTreeMap<String, String> = serde_json::from_value(request["env"].clone()).unwrap();
        let fake = Fake {
            root: root.clone(),
            intent: concrete["intent"].clone(),
        };
        let identities = identify_with(
            &Request {
                command_text: request["command_text"].as_str().unwrap(),
                cwd: request["cwd"].as_str().unwrap(),
                home_dir: request["home_dir"].as_str(),
                user_home: request["user_home"].as_str().unwrap(),
                compound: request["compound"].as_bool().unwrap(),
                env: &env,
                budget_ms: request["budget_ms"].as_u64().unwrap(),
            },
            &fake,
            owned,
        )
        .unwrap_or_else(|code| panic!("{name}: {code}"));
        let expected = concrete["expected"].as_array().unwrap();
        assert_eq!(identities.len(), expected.len(), "{name}: identity count");
        for (actual, (recorded, raw)) in identities
            .iter()
            .zip(expected.iter().zip(case["expected"].as_array().unwrap()))
        {
            let mut actual_fields = serde_json::to_value(actual).unwrap();
            let mut recorded_fields = recorded.clone();
            for key in ["cli_id", "identity_hash"] {
                actual_fields.as_object_mut().unwrap().remove(key);
                recorded_fields.as_object_mut().unwrap().remove(key);
            }
            assert_eq!(actual_fields, recorded_fields, "{name}");
            // The grant hash binds concrete paths: re-derive it from the
            // recorded source on this tree, and where the source names no
            // path under the tree the recorded value must match verbatim.
            let source: LocalCliIdentitySourceV1 =
                serde_json::from_value(recorded["identity_source"].clone()).unwrap();
            let identity = local_cli_identity(&source).unwrap().unwrap();
            assert_eq!(actual.cli_id, identity.cli_id, "{name}: cli_id");
            assert_eq!(actual.identity_hash, identity.identity_hash, "{name}: hash");
            if !raw["identity_source"].to_string().contains("{ROOT}") {
                assert_eq!(
                    raw["cli_id"],
                    json!(actual.cli_id),
                    "{name}: recorded cli_id"
                );
                assert_eq!(
                    raw["identity_hash"],
                    json!(actual.identity_hash),
                    "{name}: recorded hash"
                );
            }
        }
    }
}

#[test]
fn an_exhausted_budget_fails_closed() {
    let env = BTreeMap::new();
    let fake = Fake {
        root: String::new(),
        intent: Value::Null,
    };
    let result = identify_with(
        &Request {
            command_text: "mytool deploy",
            cwd: "/nonexistent",
            home_dir: None,
            user_home: "/nonexistent",
            compound: true,
            env: &env,
            budget_ms: 0,
        },
        &fake,
        owned_executables().unwrap(),
    );
    assert_eq!(result, Err(super::DEADLINE_EXCEEDED));
}
