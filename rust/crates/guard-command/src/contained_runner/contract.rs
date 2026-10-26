//! Typed containment contract for contained local runners.
//!
//! Faithful port of `runtime/containment_contract.py` for the offline,
//! no-declared-output requests node, TypeScript and Bun runners build. Every
//! digest is byte-identical to the Python original; payload construction takes
//! an injectable path digester so parity vectors can be verified without
//! depending on the machine-specific absolute path.

use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{json, Value};

use super::common::{
    canonical_directory, canonical_executable, canonical_file, framed_digest, text_digest,
};
use crate::effect_decision::{PositiveProof, ProofRequirement, ProofRoute};

pub(crate) const CONTAINMENT_SCHEMA_VERSION: &str = "guard.containment.v1";
pub(crate) const CONTAINMENT_POLICY_VERSION: &str = "guard.containment-policy.v1";

static SHA256: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[0-9a-f]{64}\z").unwrap());
static STABLE_ID: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*\z").unwrap());
static SECRET_ENV: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(?:^|_)(?:auth|credential|key|password|secret|token)(?:_|\n?\z)|^(?:aws|azure|gcp|github|gitlab|npm|pypi)_",
    )
    .unwrap()
});
const PROTECTED_PARTS: [&str; 9] = [
    ".git",
    ".ssh",
    ".aws",
    ".gnupg",
    ".guard",
    "guard-home",
    "credentials",
    "credentials.json",
    "secrets.json",
];

pub(crate) fn is_sha256(value: &str) -> bool {
    SHA256.is_match(value)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Backend {
    Unsupported,
    MacosSandbox,
    LinuxBwrap,
}

impl Backend {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Backend::Unsupported => "unsupported",
            Backend::MacosSandbox => "macos-sandbox",
            Backend::LinuxBwrap => "linux-bwrap",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Failure {
    UnsupportedPlatform,
    BackendUnavailable,
    BackendIdentityMismatch,
    ApplyFailed,
    #[allow(dead_code)]
    OutputBoundaryViolation,
}

impl Failure {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Failure::UnsupportedPlatform => "unsupported-platform",
            Failure::BackendUnavailable => "backend-unavailable",
            Failure::BackendIdentityMismatch => "backend-identity-mismatch",
            Failure::ApplyFailed => "apply-failed",
            Failure::OutputBoundaryViolation => "output-boundary-violation",
        }
    }
}

/// Lower-cased protected-part test shared by input and output validation.
fn protected_part(part: &str) -> bool {
    let lowered = part.to_lowercase();
    PROTECTED_PARTS.contains(&lowered.as_str()) || lowered.starts_with(".env")
}

/// `PurePosixPath(value).parts` for a relative path: empty and `.` components
/// collapse; absolute paths are reported as `None`.
fn posix_parts(value: &str) -> Option<Vec<&str>> {
    if value.starts_with('/') {
        return None;
    }
    Some(
        value
            .split('/')
            .filter(|part| !part.is_empty() && *part != ".")
            .collect(),
    )
}

pub(crate) fn require_within(path: &str, root: &str, name: &str) -> Result<(), String> {
    if Path::new(path).starts_with(root) {
        Ok(())
    } else {
        Err(format!("{name} must remain inside the workspace"))
    }
}

/// One exact workspace file copied into the isolated execution snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Input {
    pub(crate) source_path: String,
    pub(crate) snapshot_path: String,
    pub(crate) content_digest: String,
}

impl Input {
    pub(crate) fn new(
        source_path: &str,
        snapshot_path: &str,
        content_digest: &str,
    ) -> Result<Self, String> {
        let source = canonical_file(source_path, "containment input")?;
        let parts = posix_parts(snapshot_path)
            .filter(|parts| !parts.is_empty())
            .filter(|parts| parts.iter().all(|part| *part != ".."))
            .filter(|parts| !parts.iter().any(|part| protected_part(part)))
            .ok_or_else(|| "snapshot_path must be a safe relative workspace path".to_owned())?;
        if !is_sha256(content_digest) {
            return Err("content_digest must be a lowercase SHA-256 digest".to_owned());
        }
        Ok(Self {
            source_path: source,
            snapshot_path: parts.join("/"),
            content_digest: content_digest.to_owned(),
        })
    }
}

/// Exact deny-by-default offline policy for one contained launch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Policy {
    pub(crate) workspace: String,
}

impl Policy {
    pub(crate) fn new(workspace: &str) -> Result<Self, String> {
        Ok(Self {
            workspace: canonical_directory(workspace, "workspace")?,
        })
    }

    pub(crate) fn payload(&self, path_digest: &dyn Fn(&str) -> String) -> Value {
        json!({
            "schema_version": CONTAINMENT_SCHEMA_VERSION,
            "policy_version": CONTAINMENT_POLICY_VERSION,
            "workspace": path_digest(&self.workspace),
            "allowed_write_paths": [],
            "network_mode": "offline",
            "proxy_endpoint_digest": null,
            "proxy_verifier_key_digest": null,
            "secret_reads": "deny",
            "external_writes": "deny",
            "guard_controls": "deny",
        })
    }

    pub(crate) fn digest_with(
        &self,
        path_digest: &dyn Fn(&str) -> String,
    ) -> Result<String, String> {
        framed_digest(&self.payload(path_digest))
    }

    pub(crate) fn digest(&self) -> Result<String, String> {
        self.digest_with(&text_digest)
    }
}

/// Path-pinned execution request whose identity is checked immediately before spawn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Request {
    pub(crate) argv: Vec<String>,
    pub(crate) cwd: String,
    pub(crate) environment: Vec<(String, String)>,
    pub(crate) policy: Policy,
    pub(crate) inputs: Vec<Input>,
    pub(crate) launch_digest: String,
    pub(crate) executable_digest: String,
    pub(crate) operation_id: String,
}

impl Request {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        argv: &[String],
        cwd: &str,
        environment: &[(String, String)],
        policy: Policy,
        inputs: Vec<Input>,
        launch_digest: &str,
        executable_digest: &str,
        operation_id: &str,
    ) -> Result<Self, String> {
        if argv.is_empty() || argv.iter().any(|arg| arg.contains('\0')) {
            return Err("argv must contain non-NUL strings".to_owned());
        }
        let executable = canonical_executable(&argv[0])?;
        let cwd = canonical_directory(cwd, "cwd")?;
        require_within(&cwd, &policy.workspace, "cwd")?;
        if !is_sha256(launch_digest) {
            return Err("launch_digest must be a lowercase SHA-256 digest".to_owned());
        }
        if !is_sha256(executable_digest) {
            return Err("executable_digest must be a lowercase SHA-256 digest".to_owned());
        }
        if !STABLE_ID.is_match(operation_id) {
            return Err("operation_id must be a stable identifier".to_owned());
        }
        let environment = validated_environment(environment)?;
        let inputs = validated_inputs(inputs, &policy.workspace)?;
        let mut canonical_argv = vec![executable];
        canonical_argv.extend(argv[1..].iter().cloned());
        Ok(Self {
            argv: canonical_argv,
            cwd,
            environment,
            policy,
            inputs,
            launch_digest: launch_digest.to_owned(),
            executable_digest: executable_digest.to_owned(),
            operation_id: operation_id.to_owned(),
        })
    }

    pub(crate) fn payload(&self, path_digest: &dyn Fn(&str) -> String) -> Result<Value, String> {
        Ok(json!({
            "schema_version": CONTAINMENT_SCHEMA_VERSION,
            "operation_id": self.operation_id,
            "argv": self.argv,
            "cwd": path_digest(&self.cwd),
            "environment": self
                .environment
                .iter()
                .map(|(key, value)| json!([key, text_digest(value)]))
                .collect::<Vec<_>>(),
            "inputs": self
                .inputs
                .iter()
                .map(|item| json!({
                    "source_path": path_digest(&item.source_path),
                    "snapshot_path": item.snapshot_path,
                    "content_digest": item.content_digest,
                }))
                .collect::<Vec<_>>(),
            "declared_outputs": [],
            "policy_digest": self.policy.digest_with(path_digest)?,
            "launch_digest": self.launch_digest,
            "executable_digest": self.executable_digest,
        }))
    }

    pub(crate) fn binding_digest_with(
        &self,
        path_digest: &dyn Fn(&str) -> String,
    ) -> Result<String, String> {
        framed_digest(&self.payload(path_digest)?)
    }

    pub(crate) fn binding_digest(&self) -> Result<String, String> {
        self.binding_digest_with(&text_digest)
    }
}

fn validated_environment(values: &[(String, String)]) -> Result<Vec<(String, String)>, String> {
    let mut result: Vec<(String, String)> = Vec::new();
    for (key, value) in values {
        if key.contains('\0') || value.contains('\0') {
            return Err("environment entries must be non-NUL strings".to_owned());
        }
        if key.is_empty() || key.contains('=') || SECRET_ENV.is_match(key) {
            return Err("contained environment cannot carry secret-bearing keys".to_owned());
        }
        result.push((key.clone(), value.clone()));
    }
    let mut keys: Vec<&String> = result.iter().map(|(key, _)| key).collect();
    keys.sort();
    keys.dedup();
    if keys.len() != result.len() {
        return Err("contained environment keys cannot repeat".to_owned());
    }
    result.sort();
    Ok(result)
}

fn validated_inputs(mut inputs: Vec<Input>, workspace: &str) -> Result<Vec<Input>, String> {
    for item in &inputs {
        require_within(&item.source_path, workspace, "containment input")?;
    }
    inputs.sort_by(|left, right| left.snapshot_path.cmp(&right.snapshot_path));
    if inputs
        .windows(2)
        .any(|pair| pair[0].snapshot_path == pair[1].snapshot_path)
    {
        return Err("containment snapshot paths cannot repeat".to_owned());
    }
    Ok(inputs)
}

/// Privacy-safe statement that an exact launch ran under an exact backend policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Attestation {
    pub(crate) backend: Backend,
    pub(crate) backend_digest: String,
    pub(crate) request_digest: String,
    pub(crate) policy_digest: String,
    pub(crate) launch_digest: String,
    pub(crate) executable_digest: String,
    pub(crate) enforced: bool,
    pub(crate) failure: Option<Failure>,
}

impl Attestation {
    pub(crate) fn new(
        backend: Backend,
        backend_digest: &str,
        request: &Request,
        failure: Option<Failure>,
    ) -> Result<Self, String> {
        if !is_sha256(backend_digest) {
            return Err("backend_digest must be a lowercase SHA-256 digest".to_owned());
        }
        Ok(Self {
            backend,
            backend_digest: backend_digest.to_owned(),
            request_digest: request.binding_digest()?,
            policy_digest: request.policy.digest()?,
            launch_digest: request.launch_digest.clone(),
            executable_digest: request.executable_digest.clone(),
            enforced: failure.is_none(),
            failure,
        })
    }

    pub(crate) fn bound_payload(&self) -> Value {
        json!({
            "attestation": self.request_digest,
            "backend": self.backend.as_str(),
            "backend_digest": self.backend_digest,
            "policy": self.policy_digest,
            "launch": self.launch_digest,
            "executable": self.executable_digest,
        })
    }

    /// `execution_bound_proof`: the execution-bound portion of proof; runtime
    /// health must gate its caller.
    pub(crate) fn execution_bound_proof(
        &self,
        request: &Request,
        requirements: &[ProofRequirement],
    ) -> Result<PositiveProof, String> {
        if !self.enforced || self.failure.is_some() {
            return Err("failed containment cannot mint positive proof".to_owned());
        }
        if self.request_digest != request.binding_digest()? {
            return Err("containment request binding changed".to_owned());
        }
        if self.policy_digest != request.policy.digest()? {
            return Err("containment policy binding changed".to_owned());
        }
        if self.launch_digest != request.launch_digest {
            return Err("contained launch identity changed".to_owned());
        }
        if self.executable_digest != request.executable_digest {
            return Err("contained executable identity changed".to_owned());
        }
        let mut satisfied: Vec<ProofRequirement> = requirements.to_vec();
        satisfied.push(ProofRequirement::ContainmentIdentity);
        satisfied.sort();
        satisfied.dedup();
        Ok(PositiveProof {
            route: ProofRoute::Contained,
            binding_digest: framed_digest(&self.bound_payload())?,
            satisfied_requirements: satisfied,
            enforced: true,
        })
    }
}
