//! Resident-observed Bash identity. This descriptor is not a permission token.
//! Current policy, authenticated consent and native launch assurance are checked
//! separately. No request/session ID or publication timestamp belongs here.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Only descriptor inspection is available; this advertises no launch authority.
pub const NATIVE_BASH_SUBJECT_INSPECTION_FEATURE: &str = "native-bash-subject-inspection-v1";

/// Read-only resident inspection. Supplied context is not execution authority.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeBashCaptureV1 {
    pub harness: String,
    pub command: String,
    pub cwd: String,
    pub workspace: String,
    pub home_dir: String,
    pub guard_home: String,
    pub execution_environment: crate::GuardExecutionEnvironmentV1,
    /// Selected host-observed locale/temp values, never the daemon environment.
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
    /// Host-observed mask; unknown is not a default permission setting.
    #[serde(default)]
    pub file_creation_mask: Option<u32>,
    pub budget_ms: u64,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum NativeBashSubjectSchemaV1 {
    #[serde(rename = "guard.bash-subject.v1")]
    V1,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum NativeBashHostV1 {
    OmpInputRewriteV1,
    PiInputMutationV1,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum NativeBashAssuranceV1 {
    MacosReadonlyRootFramedOutputsV1,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum NativeScriptInputKindV1 {
    Interpreter,
    Entry,
    Helper,
    Source,
    Native,
    Startup,
    ResolverConfig,
    Loader,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeScriptCodeInputV1 {
    pub kind: NativeScriptInputKindV1,
    pub requested_path: String,
    pub resolved_path: String,
    pub content_sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeBashContextV1 {
    pub host: NativeBashHostV1,
    pub host_scope_digest: String,
    pub guard_home_scope_digest: String,
    pub project: String,
    pub cwd: String,
    pub home: String,
    #[serde(default)]
    pub file_creation_mask: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeScriptInvocationV1 {
    pub source_path: String,
    pub argv: Vec<String>,
    pub resolved_executable: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeScriptOutputV1 {
    pub requested_path: String,
    pub resolved_path: String,
    pub append: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeBashSubjectV1 {
    pub schema: NativeBashSubjectSchemaV1,
    pub context: NativeBashContextV1,
    pub argv: Vec<String>,
    pub code_inputs: Vec<NativeScriptCodeInputV1>,
    /// Hashes of behavior-relevant, observed values only. Never raw secrets or
    /// an all-environment digest containing ephemeral/irrelevant host values.
    pub environment_bindings: BTreeMap<String, String>,
    pub invocations: Vec<NativeScriptInvocationV1>,
    pub outputs: Vec<NativeScriptOutputV1>,
    /// Required assurance, not a claim that this operation already started.
    pub execution_assurance: NativeBashAssuranceV1,
}

impl NativeBashSubjectV1 {
    /// Stable identity only. Possessing this digest never authorizes a launch.
    pub fn identity_sha256(&self) -> Result<String, &'static str> {
        self.validate()?;
        let mut value = serde_json::to_value(self).map_err(|_| "native_bash_subject_encoding")?;
        value.sort_all_objects();
        let encoded = serde_json::to_vec(&value).map_err(|_| "native_bash_subject_encoding")?;
        let mut digest = Sha256::new();
        digest.update(b"hol-guard.native-bash-subject.v1\0");
        digest.update(encoded);
        Ok(format!("{:x}", digest.finalize()))
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.argv.is_empty()
            || self.argv.len() > 256
            || self.code_inputs.len() > 64
            || self.invocations.len() > 1024
            || self.outputs.len() > 64
            || self.environment_bindings.len() > 128
        {
            return Err("native_bash_subject_bounds");
        }
        if !digest(&self.context.host_scope_digest)
            || !digest(&self.context.guard_home_scope_digest)
            || [&self.context.project, &self.context.cwd, &self.context.home]
                .iter()
                .any(|path| !absolute(path))
        {
            return Err("native_bash_subject_context_invalid");
        }
        if self
            .context
            .file_creation_mask
            .is_some_and(|mask| mask > 0o777)
            || (!self.outputs.is_empty() && self.context.file_creation_mask.is_none())
        {
            return Err("native_bash_subject_creation_mask_unavailable");
        }
        if self.argv[0].is_empty() || !self.argv.iter().all(|arg| text(arg)) {
            return Err("native_bash_subject_argv_invalid");
        }
        let mut entries = 0;
        let mut interpreters = 0;
        let mut previous = None;
        for input in &self.code_inputs {
            if !text(&input.requested_path)
                || !absolute(&input.resolved_path)
                || !digest(&input.content_sha256)
            {
                return Err("native_bash_subject_code_invalid");
            }
            let key = (input.kind, &input.requested_path, &input.resolved_path);
            if previous.as_ref().is_some_and(|prior| prior >= &key) {
                return Err("native_bash_subject_code_order_invalid");
            }
            previous = Some(key);
            if input.kind == NativeScriptInputKindV1::Entry {
                entries += 1;
                if input.requested_path != self.argv[0] {
                    return Err("native_bash_subject_entry_invalid");
                }
            }
            if input.kind == NativeScriptInputKindV1::Interpreter {
                interpreters += 1;
            }
        }
        if entries != 1 || interpreters != 1 {
            return Err("native_bash_subject_code_invalid");
        }
        if self.environment_bindings.iter().any(|(name, value)| {
            name.is_empty()
                || name.len() > 128
                || name.as_bytes()[0].is_ascii_digit()
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
                || !digest(value)
        }) {
            return Err("native_bash_subject_environment_invalid");
        }
        if self.invocations.iter().any(|call| {
            !text(&call.source_path)
                || call.argv.is_empty()
                || call.argv.len() > 256
                || call.argv[0].is_empty()
                || !call.argv.iter().all(|arg| text(arg))
                || call
                    .resolved_executable
                    .as_ref()
                    .is_some_and(|path| !absolute(path))
        }) {
            return Err("native_bash_subject_invocation_invalid");
        }
        if self
            .outputs
            .iter()
            .any(|output| !text(&output.requested_path) || !absolute(&output.resolved_path))
        {
            return Err("native_bash_subject_output_invalid");
        }
        // Bound aggregate data as well as individual fields. Per-field limits
        // alone permit thousands of individually valid oversized invocations.
        let bytes: usize = self.argv.iter().map(String::len).sum::<usize>()
            + self
                .code_inputs
                .iter()
                .map(|i| i.requested_path.len() + i.resolved_path.len() + 64)
                .sum::<usize>()
            + self
                .invocations
                .iter()
                .map(|i| {
                    i.source_path.len()
                        + i.argv.iter().map(String::len).sum::<usize>()
                        + i.resolved_executable.as_ref().map_or(0, String::len)
                })
                .sum::<usize>()
            + self
                .outputs
                .iter()
                .map(|o| o.requested_path.len() + o.resolved_path.len())
                .sum::<usize>()
            + self
                .environment_bindings
                .iter()
                .map(|(k, v)| k.len() + v.len())
                .sum::<usize>()
            + self.context.project.len()
            + self.context.cwd.len()
            + self.context.home.len();
        if bytes > 1024 * 1024 {
            return Err("native_bash_subject_bounds");
        }
        Ok(())
    }
}

fn text(value: &str) -> bool {
    value.len() <= 32 * 1024 && !value.contains('\0')
}
fn absolute(value: &str) -> bool {
    value.starts_with('/')
        && text(value)
        && !value.split('/').any(|part| part == "." || part == "..")
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subject() -> NativeBashSubjectV1 {
        serde_json::from_value(serde_json::json!({
            "schema": "guard.bash-subject.v1",
            "context": {"host": "omp-input-rewrite-v1", "host_scope_digest": "a".repeat(64),
                "guard_home_scope_digest": "b".repeat(64), "project": "/project",
                "cwd": "/project", "home": "/home", "file_creation_mask": 18},
            "argv": ["maintenance.sh", "dry"],
            "code_inputs": [
                {"kind": "interpreter", "requested_path": "/bin/bash", "resolved_path": "/bin/bash", "content_sha256": "c".repeat(64)},
                {"kind": "entry", "requested_path": "maintenance.sh", "resolved_path": "/project/maintenance.sh", "content_sha256": "d".repeat(64)}
            ],
            "environment_bindings": {}, "invocations": [], "outputs": [],
            "execution_assurance": "macos-readonly-root-framed-outputs-v1"
        })).unwrap()
    }

    #[test]
    fn native_bash_subject_rejects_unknown_contracts_and_identity_drift() {
        let valid = subject();
        assert_eq!(valid.validate(), Ok(()));
        let mut wire = serde_json::to_value(&valid).unwrap();
        wire["session_id"] = "unrecognized".into();
        assert!(serde_json::from_value::<NativeBashSubjectV1>(wire).is_err());
        let mut wire = serde_json::to_value(&valid).unwrap();
        wire["schema"] = "guard.bash-subject.v2".into();
        assert!(serde_json::from_value::<NativeBashSubjectV1>(wire).is_err());
        let mut changed = valid.clone();
        changed.argv[0] = "other.sh".into();
        assert_eq!(changed.validate(), Err("native_bash_subject_entry_invalid"));
        let mut changed = valid;
        changed.code_inputs.reverse();
        assert_eq!(
            changed.validate(),
            Err("native_bash_subject_code_order_invalid")
        );
    }

    #[test]
    fn native_bash_subject_bounds_aggregate_expansion() {
        let mut subject = subject();
        subject.invocations = vec![
            NativeScriptInvocationV1 {
                source_path: "/project/maintenance.sh".into(),
                argv: vec!["printf".into(), "x".repeat(32 * 1024)],
                resolved_executable: None,
            };
            33
        ];
        assert_eq!(subject.validate(), Err("native_bash_subject_bounds"));
        subject.invocations.clear();
        subject
            .environment_bindings
            .insert("1INVALID".into(), "a".repeat(64));
        assert_eq!(
            subject.validate(),
            Err("native_bash_subject_environment_invalid")
        );
    }

    #[test]
    fn native_bash_subject_requires_observed_creation_mask_for_outputs() {
        let mut subject = subject();
        subject.context.file_creation_mask = None;
        assert_eq!(subject.validate(), Ok(()));
        subject.outputs.push(NativeScriptOutputV1 {
            requested_path: "/report".into(),
            resolved_path: "/report".into(),
            append: false,
        });
        assert_eq!(
            subject.validate(),
            Err("native_bash_subject_creation_mask_unavailable")
        );
        subject.context.file_creation_mask = Some(0o1000);
        assert_eq!(
            subject.validate(),
            Err("native_bash_subject_creation_mask_unavailable")
        );
        subject.context.file_creation_mask = Some(0o022);
        assert_eq!(subject.validate(), Ok(()));
    }

    #[test]
    fn native_bash_subject_identity_is_stable_and_binds_mode_code_and_context() {
        let original = subject();
        let identity = original.identity_sha256().unwrap();
        for _ in 0..10 {
            let restored: NativeBashSubjectV1 =
                serde_json::from_slice(&serde_json::to_vec(&original).unwrap()).unwrap();
            assert_eq!(restored.identity_sha256().unwrap(), identity);
        }
        let mut changed = original.clone();
        changed.argv[1] = "delete".into();
        assert_ne!(changed.identity_sha256().unwrap(), identity);
        let mut changed = original.clone();
        changed.code_inputs[1].content_sha256 = "e".repeat(64);
        assert_ne!(changed.identity_sha256().unwrap(), identity);
        let mut changed = original.clone();
        changed.context.cwd = "/other".into();
        assert_ne!(changed.identity_sha256().unwrap(), identity);
        let mut changed = original;
        changed.context.guard_home_scope_digest = "f".repeat(64);
        assert_ne!(changed.identity_sha256().unwrap(), identity);
        changed = subject();
        changed.context.file_creation_mask = Some(0o077);
        assert_ne!(changed.identity_sha256().unwrap(), identity);
    }
}
