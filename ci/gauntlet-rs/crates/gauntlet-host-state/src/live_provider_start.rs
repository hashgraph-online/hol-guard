//! Fixed plan and bounded output boundary for the existing Python/MLX launcher.
//! This module never spawns or admits a provider. File custody and PID ownership
//! must be supplied by the eventual trusted host process supervisor.

use gauntlet_contracts::canonicalize;
use serde_json::{json, Value};
use std::fmt;
use std::path::{Component, Path};

const MODEL_ID: &str = "mlx-community/Qwen3.6-35B-A3B-8bit";
const MAX_STDOUT: usize = 1024 * 1024;
const CEILING: u64 = 14_468_885;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveProviderStartError {
    Identity,
    Repository,
    Output,
}

impl fmt::Display for LiveProviderStartError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Identity => "fixed provider job, profile and candidate source required",
            Self::Repository => "absolute reviewed provider repository path required",
            Self::Output => "provider startup output differs from fixed launch",
        })
    }
}

impl std::error::Error for LiveProviderStartError {}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn literal_repository(path: &Path) -> bool {
    let Some(literal) = path.to_str() else {
        return false;
    };
    path.is_absolute()
        && !literal.chars().any(char::is_whitespace)
        && !literal.contains("//")
        && !literal.ends_with('/')
        && path.file_name().and_then(|name| name.to_str())
            == Some("workflow-benchmark-implementation")
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveProviderStartPlan {
    pub argv: Vec<String>,
    pub cwd: String,
    pub timeout_seconds: u64,
    job_id: String,
}

impl LiveProviderStartPlan {
    pub fn to_json(&self) -> Value {
        json!({
            "argv":self.argv,
            "cwd":self.cwd,
            "timeout_seconds":self.timeout_seconds,
            "execution_eligible":false,
        })
    }

    /// Parse only the final JSON line of a bounded Python startup transcript.
    /// The result is a producer claim until manifest bytes and kernel PID are
    /// independently opened and matched by a trusted host owner.
    pub fn parse_startup_stdout(
        &self,
        stdout: &[u8],
        expected_known_tokens: u64,
    ) -> Result<Value, LiveProviderStartError> {
        if stdout.len() > MAX_STDOUT || !stdout.ends_with(b"\n") {
            return Err(LiveProviderStartError::Output);
        }
        std::str::from_utf8(stdout).map_err(|_| LiveProviderStartError::Output)?;
        let last = stdout[..stdout.len() - 1]
            .rsplit(|byte| *byte == b'\n')
            .next()
            .filter(|line| !line.is_empty())
            .ok_or(LiveProviderStartError::Output)?;
        let canonical = canonicalize(last).map_err(|_| LiveProviderStartError::Output)?;
        let value: Value =
            serde_json::from_slice(&canonical).map_err(|_| LiveProviderStartError::Output)?;
        let object = value.as_object().ok_or(LiveProviderStartError::Output)?;
        let expected = [
            "binding_sha256",
            "known_tokens_before",
            "maximum_accounted_tokens",
            "model_id",
            "model_manifest",
            "model_sha256",
            "pid",
            "provider_manifest",
            "provider_sha256",
            "root",
        ];
        if object.len() != expected.len() || expected.iter().any(|key| !object.contains_key(*key)) {
            return Err(LiveProviderStartError::Output);
        }
        let project = Path::new(&self.cwd)
            .parent()
            .ok_or(LiveProviderStartError::Repository)?;
        let root = project.join(format!("local-model-provider-gauntlet-{}", self.job_id));
        let expected_root = root.to_str().ok_or(LiveProviderStartError::Repository)?;
        let provider_manifest = root.join("provider-manifest.json");
        let model_manifest = root.join("model-manifest.json");
        if value["root"].as_str() != Some(expected_root)
            || value["provider_manifest"].as_str() != provider_manifest.to_str()
            || value["model_manifest"].as_str() != model_manifest.to_str()
            || value["model_id"].as_str() != Some(MODEL_ID)
            || value["known_tokens_before"].as_u64() != Some(expected_known_tokens)
            || value["maximum_accounted_tokens"].as_u64() != Some(CEILING)
            || !value["pid"]
                .as_u64()
                .is_some_and(|pid| (1..=i32::MAX as u64).contains(&pid))
            || ["provider_sha256", "model_sha256", "binding_sha256"]
                .iter()
                .any(|key| {
                    !value[*key]
                        .as_str()
                        .is_some_and(|digest| lower_hex(digest, 64))
                })
        {
            return Err(LiveProviderStartError::Output);
        }
        Ok(json!({
            "schema":"hol-gauntlet-live-provider-startup-claim.v1",
            "job_id":self.job_id,
            "pid":value["pid"],
            "provider_sha256":value["provider_sha256"],
            "model_sha256":value["model_sha256"],
            "binding_sha256":value["binding_sha256"],
            "known_tokens_before":expected_known_tokens,
            "producer_claim_only":true,
            "execution_eligible":false,
        }))
    }
}

pub fn fixed_live_provider_start_plan(
    job_id: &str,
    profile: &str,
    candidate_source_sha: &str,
    reviewed_repository: &Path,
) -> Result<LiveProviderStartPlan, LiveProviderStartError> {
    if !lower_hex(job_id, 16)
        || !lower_hex(candidate_source_sha, 40)
        || !matches!(profile, "beta-e2e" | "feature-ai" | "feature-ai-protocol")
    {
        return Err(LiveProviderStartError::Identity);
    }
    if !literal_repository(reviewed_repository) {
        return Err(LiveProviderStartError::Repository);
    }
    let cwd = reviewed_repository
        .to_str()
        .ok_or(LiveProviderStartError::Repository)?
        .to_owned();
    Ok(LiveProviderStartPlan {
        argv: [
            "/opt/homebrew/bin/uv",
            "run",
            "--no-project",
            "--with",
            "cryptography==50.0.0",
            "python",
            "-B",
            "-m",
            "ci.gauntlet.control_plane.live_provider",
            job_id,
            profile,
            candidate_source_sha,
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        cwd,
        timeout_seconds: 900,
        job_id: job_id.to_owned(),
    })
}
