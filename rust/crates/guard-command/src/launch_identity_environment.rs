//! Port of `runtime/launch_identity_environment.py` (:1-186).
//!
//! Side-effect-free effective environment plans for launch observations.

use std::collections::BTreeMap;

use guard_contracts::write_canonical_json;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::command_structure::EmbeddedCommand;
use crate::command_tokens::{
    env_assignment_name, executable_name, leading_environment, shell_tokens,
};
use crate::CommandSegmentV1;

/// `_SCRIPT_SCOPE_WRAPPERS` (:19).
const SCRIPT_SCOPE_WRAPPERS: &[&str] = &[
    "ash", "bash", "bash.exe", "dash", "fish", "ksh", "sh", "sh.exe", "zsh",
];

/// `WrapperLaunchEnvironment` (:22-25).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrapperLaunchEnvironment {
    pub name: String,
    pub environment: BTreeMap<String, String>,
}

/// `LaunchEnvironmentPlan` (:28-32).
#[derive(Clone, Debug)]
pub struct LaunchEnvironmentPlan {
    pub executable_environment: BTreeMap<String, String>,
    pub wrapper_environments: Vec<WrapperLaunchEnvironment>,
    pub complete: bool,
}

/// `inherited_launch_environment` (:35-41).
///
/// `launch_env == None` reads the live process environment via `vars_os()` +
/// `to_str()`. Python counts surrogateescape-decoded entries as `str` (kept,
/// `complete=True`); `vars_os` drops non-UTF-8 entries here, so the plan loses
/// the entry AND reports `complete=false`. That divergence is conservative —
/// an incomplete plan forces a fresh `reuse_nonce`, never stale reuse.
pub fn inherited_launch_environment(
    launch_env: Option<&BTreeMap<String, String>>,
) -> LaunchEnvironmentPlan {
    match launch_env {
        Some(environment) => LaunchEnvironmentPlan {
            executable_environment: environment.clone(),
            wrapper_environments: Vec::new(),
            complete: true,
        },
        None => {
            let mut kept = BTreeMap::new();
            let mut dropped = 0usize;
            for (name, value) in std::env::vars_os() {
                match (name.to_str(), value.to_str()) {
                    (Some(name), Some(value)) => {
                        kept.insert(name.to_owned(), value.to_owned());
                    }
                    _ => dropped += 1,
                }
            }
            LaunchEnvironmentPlan {
                executable_environment: kept,
                wrapper_environments: Vec::new(),
                complete: dropped == 0,
            }
        }
    }
}

/// `plan_launch_environment` (:44-113).
///
/// Applies leading `NAME=VALUE` assignments and static `env` controls in
/// shell order.
pub fn plan_launch_environment(
    tokens: &[String],
    inherited: &BTreeMap<String, String>,
    inherited_complete: bool,
) -> LaunchEnvironmentPlan {
    let mut environment = inherited.clone();
    let (_names, executable_index, wrappers) = leading_environment(tokens);
    let mut wrapper_environments: Vec<WrapperLaunchEnvironment> = Vec::new();
    let mut wrapper_index = 0usize;
    let mut env_options = false;
    let mut complete = inherited_complete;
    let mut index = 0usize;
    while index < executable_index {
        let token = &tokens[index];
        if env_assignment_name(token).is_some() {
            // `_ENVIRONMENT_NAME.fullmatch(name)` — env_assignment_name runs the
            // same name class and the `=` gate in one pass.
            let eq = token.find('=').unwrap();
            environment.insert(token[..eq].to_owned(), token[eq + 1..].to_owned());
            index += 1;
            continue;
        }
        let command_name = executable_name(Some(token));
        if wrapper_index < wrappers.len()
            && command_name.as_deref() == Some(wrappers[wrapper_index].as_str())
        {
            wrapper_environments.push(WrapperLaunchEnvironment {
                name: wrappers[wrapper_index].clone(),
                environment: environment.clone(),
            });
            wrapper_index += 1;
            env_options = command_name.as_deref() == Some("env");
            index += 1;
            continue;
        }
        if !env_options {
            index += 1;
            continue;
        }
        if token == "-i" || token == "--ignore-environment" {
            environment.clear();
            index += 1;
            continue;
        }
        if token == "-u" || token == "--unset" {
            if index + 1 >= executable_index {
                complete = false;
                break;
            }
            environment.remove(&tokens[index + 1]);
            index += 2;
            continue;
        }
        if let Some(name) = token.strip_prefix("--unset=") {
            environment.remove(name);
            index += 1;
            continue;
        }
        if token == "-C" || token == "--chdir" {
            if index + 1 >= executable_index {
                complete = false;
                break;
            }
            index += 2;
            continue;
        }
        if token.starts_with("--chdir=") {
            index += 1;
            continue;
        }
        if token == "--" {
            env_options = false;
            index += 1;
            continue;
        }
        if token.starts_with('-') {
            complete = false;
        }
        index += 1;
    }
    if env_options && executable_index < tokens.len() && tokens[executable_index].starts_with('-') {
        // An option at the executable boundary implies more `env` controls
        // were left unconsumed (:107-108).
        complete = false;
    }
    if wrapper_index < wrappers.len() {
        complete = false;
        for wrapper in &wrappers[wrapper_index..] {
            wrapper_environments.push(WrapperLaunchEnvironment {
                name: wrapper.clone(),
                environment: environment.clone(),
            });
        }
    }
    LaunchEnvironmentPlan {
        executable_environment: environment,
        wrapper_environments,
        complete,
    }
}

/// Segment surface `plan_command_segment_environment` consumes — both
/// `CommandSegment` (internal model) and `CommandSegmentV1` (wire) carry the
/// same `tokens`/`execution_context` pair.
pub trait SegmentEnvView {
    fn tokens(&self) -> &[String];
    fn execution_context(&self) -> &str;
}

impl SegmentEnvView for CommandSegmentV1 {
    fn tokens(&self) -> &[String] {
        &self.tokens
    }
    fn execution_context(&self) -> &str {
        &self.execution_context
    }
}

impl SegmentEnvView for crate::command_model::CommandSegment {
    fn tokens(&self) -> &[String] {
        &self.tokens
    }
    fn execution_context(&self) -> &str {
        &self.execution_context
    }
}

/// `plan_command_segment_environment` (:116-134).
///
/// `embedded_commands` is kept for parity with the Python signature; the
/// CanonicalCommandV1 wire never carries embedded commands, so callers pass
/// `&[]` on the native path.
pub fn plan_command_segment_environment(
    segment: &impl SegmentEnvView,
    embedded_commands: &[EmbeddedCommand],
    inherited: &BTreeMap<String, String>,
) -> LaunchEnvironmentPlan {
    let embedded = embedded_commands.iter().find(|embedded| {
        segment
            .execution_context()
            .starts_with(&format!("{}:", embedded.execution_context))
    });
    if let Some(embedded) = embedded {
        // :124-134 — the OUTER plan applies the embedded command's tokens to
        // the inherited env; the normalized plan then applies the segment's
        // own tokens on top. Wrapper environments concatenate outer→inner.
        let (embedded_tokens, _exact) = shell_tokens(&embedded.text);
        let outer = plan_launch_environment(&embedded_tokens, inherited, true);
        let normalized =
            plan_launch_environment(segment.tokens(), &outer.executable_environment, true);
        let mut wrapper_environments = outer.wrapper_environments;
        wrapper_environments.extend(normalized.wrapper_environments);
        return LaunchEnvironmentPlan {
            executable_environment: normalized.executable_environment,
            wrapper_environments,
            complete: outer.complete && normalized.complete,
        };
    }
    plan_launch_environment(segment.tokens(), inherited, true)
}

/// `launch_search_path` (:137-139).
pub fn launch_search_path(environment: &BTreeMap<String, String>) -> String {
    match environment.get("PATH") {
        Some(search_path) => search_path.clone(),
        None => os_defpath().to_owned(),
    }
}

/// `os.defpath` — `':/bin:/usr/bin'` POSIX, `'.;C:\\bin'` Windows.
fn os_defpath() -> &'static str {
    #[cfg(windows)]
    {
        ".;C:\\bin"
    }
    #[cfg(not(windows))]
    {
        ":/bin:/usr/bin"
    }
}

/// `launch_environment_scope_is_ambiguous` (:142-143).
pub fn launch_environment_scope_is_ambiguous(wrappers: &[String], segment_count: usize) -> bool {
    segment_count > 1
        && wrappers
            .iter()
            .any(|w| SCRIPT_SCOPE_WRAPPERS.contains(&w.as_str()))
}

/// `unresolved_launch_observation` (:146-151). Returns the Python dict shape
/// as a `serde_json::Value`; RNG failure yields an all-zero digest marker so
/// the caller still reports an unresolved observation rather than fabricating
/// a reusable identity.
pub fn unresolved_launch_observation(segment_index: &str) -> Value {
    let mut bytes = [0u8; 32];
    let digest = match getrandom::fill(&mut bytes) {
        Ok(()) => hex::encode(bytes),
        Err(_) => "0".repeat(64),
    };
    json!({
        "segment_index": segment_index,
        "identity_digest": digest,
        "reusable_observation": false,
    })
}

/// `environment_observation_material` (:154-173). Local `hashlib.sha256` over
/// `"hol-guard.launch-environment\x00" + canonical sorted env JSON` — NOT the
/// native `canonical_sha256` op. `reuse_nonce` = `secrets.token_hex(16)`.
pub fn environment_observation_material(plans: &[LaunchEnvironmentPlan]) -> Vec<Value> {
    let mut material = Vec::with_capacity(plans.len());
    for (index, plan) in plans.iter().enumerate() {
        // `json.dumps(sorted(env.items()), separators=(",",":"), ensure_ascii=True)`
        let items: Vec<Value> = plan
            .executable_environment
            .iter()
            .map(|(name, value)| json!([name, value]))
            .collect();
        let mut payload = Vec::new();
        let _ = write_canonical_json(&Value::Array(items), &mut payload);
        let mut frame = b"hol-guard.launch-environment\x00".to_vec();
        frame.extend_from_slice(&payload);
        let environment_digest = hex::encode(Sha256::digest(&frame));
        let mut entry = json!({
            "index": index,
            "complete": plan.complete,
            "entry_count": plan.executable_environment.len(),
            "environment_digest": environment_digest,
        });
        if !plan.complete {
            let mut nonce = [0u8; 16];
            let reuse_nonce = match getrandom::fill(&mut nonce) {
                Ok(()) => hex::encode(nonce),
                Err(_) => "0".repeat(32),
            };
            entry["reuse_nonce"] = Value::String(reuse_nonce);
        }
        material.push(entry);
    }
    material
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn environment_digest_matches_python_oracle() {
        // python3: sorted(env.items()), canonical separators, ensure_ascii
        // → sha256(b"hol-guard.launch-environment\x00" + payload)
        // env = {PATH:/usr/bin:/bin, HOME:/root, X_VAR:héllo}
        //   → c8b48a549dbb2a0102373f1aa8ce2d53e23b3229889c519823e4a41eb49b4624
        let plan = LaunchEnvironmentPlan {
            executable_environment: env(&[
                ("PATH", "/usr/bin:/bin"),
                ("HOME", "/root"),
                ("X_VAR", "héllo"),
            ]),
            wrapper_environments: Vec::new(),
            complete: true,
        };
        let material = environment_observation_material(&[plan]);
        assert_eq!(
            material[0]["environment_digest"],
            "c8b48a549dbb2a0102373f1aa8ce2d53e23b3229889c519823e4a41eb49b4624"
        );
        assert_eq!(material[0]["entry_count"], 3);
        assert_eq!(material[0]["complete"], true);
        assert!(material[0].get("reuse_nonce").is_none());
    }

    #[test]
    fn incomplete_plan_gets_reuse_nonce() {
        let plan = LaunchEnvironmentPlan {
            executable_environment: env(&[]),
            wrapper_environments: Vec::new(),
            complete: false,
        };
        let material = environment_observation_material(&[plan]);
        let nonce = material[0]["reuse_nonce"].as_str().unwrap();
        assert_eq!(nonce.len(), 32);
    }

    #[test]
    fn plan_applies_assignments_and_env_controls() {
        // `FOO=1 env -i -u HOME BAR=2 prog` — wait, assignments after `env`
        // land in the env-options region; mirror Python: leading assignments
        // apply first, then `env` controls in shell order.
        let tokens: Vec<String> = ["FOO=1", "env", "-i", "--unset=PATH", "BAR=2", "prog"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let inherited = env(&[("PATH", "/bin"), ("HOME", "/root"), ("KEEP", "1")]);
        let plan = plan_launch_environment(&tokens, &inherited, true);
        // leading_environment treats `env` as a wrapper consuming up to
        // `prog`; the plan applies FOO=1, snapshots env, then `-i` clears and
        // `--unset=PATH` is a no-op on the cleared map, `BAR=2` sets.
        assert_eq!(
            plan.executable_environment.get("BAR"),
            Some(&"2".to_string())
        );
        assert!(!plan.executable_environment.contains_key("HOME"));
        assert_eq!(
            plan.wrapper_environments.first().map(|w| w.name.as_str()),
            Some("env")
        );
    }

    #[test]
    fn ambiguous_scope_needs_multiple_segments_and_script_wrapper() {
        let wrappers = vec!["bash".to_string()];
        assert!(launch_environment_scope_is_ambiguous(&wrappers, 2));
        assert!(!launch_environment_scope_is_ambiguous(&wrappers, 1));
        assert!(!launch_environment_scope_is_ambiguous(
            &["env".to_string()],
            3
        ));
    }

    #[test]
    fn unresolved_observation_shape() {
        let value = unresolved_launch_observation("seg:0");
        assert_eq!(value["segment_index"], "seg:0");
        assert_eq!(value["reusable_observation"], false);
        assert_eq!(value["identity_digest"].as_str().unwrap().len(), 64);
    }

    #[test]
    fn search_path_falls_back_to_defpath() {
        assert_eq!(launch_search_path(&env(&[])), os_defpath().to_string());
        assert_eq!(
            launch_search_path(&env(&[("PATH", "/x")])),
            "/x".to_string()
        );
    }
}
