//! Parity replay for `guard_command::package_context_build`.
//!
//! The vectors under `fixtures/package_context_vectors.v1.json.gz` were recorded
//! by `scripts/ci/package_context_vector_recorder.py` from the retired Python
//! builder. Each scenario materialises a file tree in a scratch directory, runs
//! the Rust build over it with replay ports, and requires the same digest,
//! components and non-portable reason, plus the same ordered log of native hook
//! calls (digest texts, search-path digest, environment projection and launch
//! identity) with the scratch directory replaced by `{root}`.
#![cfg(unix)]

use std::collections::BTreeMap;
use std::io::Read;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};

use guard_command::package_context_build::{build_with_ports, BuildError, BuildInput, Ports};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

const FIXTURE: &[u8] = include_bytes!("fixtures/package_context_vectors.v1.json.gz");
const TOKEN: &str = "{root}";
const MINIMUM_SCENARIOS: usize = 300;

fn replace(value: &Value, from: &str, to: &str) -> Value {
    match value {
        Value::String(text) => Value::String(text.replace(from, to)),
        Value::Array(items) => {
            Value::Array(items.iter().map(|item| replace(item, from, to)).collect())
        }
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, item)| (key.replace(from, to), replace(item, from, to)))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn sha256_hex(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

struct Replay<'a> {
    root: &'a str,
    hooks: &'a [Value],
    cursor: usize,
}

impl Replay<'_> {
    fn next(&mut self, kind: &str) -> &Value {
        let hook = self
            .hooks
            .get(self.cursor)
            .unwrap_or_else(|| panic!("unexpected extra {kind} hook at {}", self.cursor));
        self.cursor += 1;
        assert_eq!(hook["hook"], kind, "hook {} kind", self.cursor - 1);
        hook
    }

    fn normal(&self, value: &Value) -> Value {
        replace(value, self.root, TOKEN)
    }

    fn expanded(&self, value: &Value) -> Value {
        replace(value, TOKEN, self.root)
    }
}

fn string_map(environment: &BTreeMap<String, String>) -> Value {
    Value::Object(
        environment
            .iter()
            .map(|(key, value)| (key.clone(), Value::String(value.clone())))
            .collect(),
    )
}

impl Ports for Replay<'_> {
    fn digest_material(&mut self, canonical_text: &str) -> String {
        let normal = canonical_text.replace(self.root, TOKEN);
        let hook = self.next("digest");
        assert_eq!(hook["text"], Value::String(normal.clone()), "digest text");
        sha256_hex(&normal)
    }

    fn opaque_digest(&mut self, material: &str) -> String {
        let normal = material.replace(self.root, TOKEN);
        let hook = self.next("opaque");
        assert_eq!(hook["text"], Value::String(normal.clone()), "opaque text");
        sha256_hex(&normal)
    }

    fn environment_values(
        &mut self,
        manager: &str,
        environment: &BTreeMap<String, String>,
        referenced_names: &[String],
    ) -> Result<BTreeMap<String, Option<String>>, BuildError> {
        let expected_env = self.normal(&string_map(environment));
        let hook = self.next("env_values").clone();
        assert_eq!(hook["manager"], manager, "environment manager");
        assert_eq!(hook["env"], expected_env, "environment values");
        assert_eq!(
            hook["names"],
            Value::from(referenced_names.to_vec()),
            "referenced names"
        );
        let result = hook["result"].as_object().expect("environment result");
        Ok(result
            .iter()
            .map(|(key, value)| (key.clone(), value.as_str().map(str::to_owned)))
            .collect())
    }

    fn launch_identity(
        &mut self,
        requested: &str,
        arguments: &[String],
        search_path: Option<&str>,
        cwd: &str,
        environment: &BTreeMap<String, String>,
    ) -> Value {
        let expected_env = self.normal(&string_map(environment));
        let hook = self.next("launch_identity").clone();
        assert_eq!(hook["requested"], requested, "launch requested");
        assert_eq!(
            hook["args"],
            self.normal(&Value::from(arguments.to_vec())),
            "launch args"
        );
        assert_eq!(
            hook["search_path"],
            self.normal(&search_path.map_or(Value::Null, Value::from)),
            "launch search path"
        );
        assert_eq!(hook["cwd"], self.normal(&Value::from(cwd)), "launch cwd");
        assert_eq!(hook["env"], expected_env, "launch environment");
        self.expanded(&hook["result"])
    }

    fn launch_identity_reusable(&mut self, identity: &Value) -> bool {
        let expected = self.normal(identity);
        let hook = self.next("reusable").clone();
        assert_eq!(hook["identity"], expected, "reusable identity");
        hook["result"].as_bool().expect("reusable result")
    }
}

fn scratch_root(index: usize) -> PathBuf {
    let base = std::env::temp_dir()
        .canonicalize()
        .expect("temporary directory");
    let root = base.join(format!("pcv-replay-{}-{index}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("scratch root");
    root
}

fn apply_step(root: &Path, step: &Value) {
    let path = root.join(step["path"].as_str().expect("step path"));
    let root_text = root.to_str().expect("utf-8 scratch root");
    match step["op"].as_str().expect("step op") {
        "write" => {
            std::fs::create_dir_all(path.parent().expect("parent")).expect("parent directory");
            if let Some(size) = step.get("size") {
                let file = std::fs::File::create(&path).expect("create");
                file.set_len(size.as_u64().expect("size"))
                    .expect("truncate");
            } else if let Some(unit) = step.get("repeat") {
                let count = usize::try_from(step["count"].as_u64().expect("count")).expect("count");
                std::fs::write(&path, unit.as_str().expect("repeat").repeat(count)).expect("write");
            } else if let Some(encoded) = step.get("hex") {
                std::fs::write(
                    &path,
                    hex::decode(encoded.as_str().expect("hex")).expect("hex"),
                )
                .expect("write");
            } else {
                let text = step["text"]
                    .as_str()
                    .expect("text")
                    .replace(TOKEN, root_text);
                std::fs::write(&path, text).expect("write");
            }
            let mode = if step.get("exec").and_then(Value::as_bool).unwrap_or(false) {
                0o755
            } else {
                0o644
            };
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
        }
        "mkdir" => std::fs::create_dir_all(&path).expect("mkdir"),
        "symlink" => {
            std::fs::create_dir_all(path.parent().expect("parent")).expect("parent directory");
            let target = step["target"]
                .as_str()
                .expect("target")
                .replace(TOKEN, root_text);
            symlink(target, &path).expect("symlink");
        }
        other => panic!("unknown step {other}"),
    }
}

fn scenarios() -> Vec<Value> {
    let mut decoder = flate2::read::GzDecoder::new(FIXTURE);
    let mut raw = String::new();
    decoder.read_to_string(&mut raw).expect("gunzip fixture");
    let document: Value = serde_json::from_str(&raw).expect("fixture json");
    assert_eq!(document["version"], 1);
    document["scenarios"].as_array().expect("scenarios").clone()
}

fn run(scenario: &Value, index: usize) {
    let root = scratch_root(index);
    let root_text = root.to_str().expect("utf-8 scratch root").to_owned();
    let expand = |value: &Value| replace(value, TOKEN, &root_text);
    for step in scenario["steps"].as_array().expect("steps") {
        apply_step(&root, step);
    }
    let environment: BTreeMap<String, String> = expand(&scenario["env"])
        .as_object()
        .expect("env")
        .iter()
        .map(|(key, value)| (key.clone(), value.as_str().expect("env value").to_owned()))
        .collect();
    let metadata: Map<String, Value> = expand(&scenario["metadata"])
        .as_object()
        .expect("metadata")
        .clone();
    let arguments: Vec<String> = scenario["args"]
        .as_array()
        .expect("args")
        .iter()
        .map(|item| item.as_str().expect("arg").to_owned())
        .collect();
    let workspace = expand(&scenario["workspace"]);
    let cwd = expand(&scenario["cwd"]);
    let home = expand(&scenario["home"]);
    let process_path = expand(&scenario["process_path"]);
    let input = BuildInput {
        workspace_dir: workspace.as_str().expect("workspace"),
        metadata: &metadata,
        executable: scenario["executable"].as_str(),
        executable_args: &arguments,
        environment: &environment,
        process_cwd: cwd.as_str().expect("cwd"),
        process_home: home.as_str().expect("home"),
        process_home_env: home.as_str(),
        process_path: process_path.as_str(),
    };
    let hooks = scenario["hooks"].as_array().expect("hooks");
    let mut replay = Replay {
        root: &root_text,
        hooks,
        cursor: 0,
    };
    let built = build_with_ports(&input, &mut replay)
        .unwrap_or_else(|error| panic!("build failed: {error:?}"));
    assert_eq!(replay.cursor, hooks.len(), "unconsumed hooks");
    let expected = &scenario["expect"];
    assert_eq!(
        Value::from(built.digest.clone()),
        expected["digest"],
        "digest"
    );
    assert_eq!(
        Value::from(built.portable),
        expected["portable"],
        "portable"
    );
    assert_eq!(
        built
            .non_portable_reason
            .clone()
            .map_or(Value::Null, Value::from),
        expected["reason"],
        "reason"
    );
    let components: Vec<Value> = built
        .components
        .iter()
        .map(|item| serde_json::json!({"name": item.name, "digest": item.digest}))
        .collect();
    assert_eq!(
        Value::Array(components),
        expected["components"],
        "components"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn recorded_python_vectors_replay_byte_exact() {
    let scenarios = scenarios();
    assert!(
        scenarios.len() >= MINIMUM_SCENARIOS,
        "fixture has {} scenarios",
        scenarios.len()
    );
    let mut failures = Vec::new();
    for (index, scenario) in scenarios.iter().enumerate() {
        let name = scenario["name"].as_str().unwrap_or("?").to_owned();
        let outcome = catch_unwind(AssertUnwindSafe(|| run(scenario, index)));
        if let Err(payload) = outcome {
            let message = payload
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| {
                    payload
                        .downcast_ref::<&str>()
                        .map(|text| (*text).to_owned())
                })
                .unwrap_or_default();
            failures.push(format!("{name}: {message}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} scenarios diverged:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
