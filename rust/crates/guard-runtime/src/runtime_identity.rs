//! `runtime-identity-assess --stdin`: match observed runtime artifacts and
//! process instances against cached runtime advisories.
//!
//! An artifact is one immutable executable identity. A location maps a path to
//! whatever artifact sits there now; an instance binds a running process
//! (boot, PID, start identity) to the artifact it actually started from, so a
//! replaced file on disk never rewrites what an old process is running.
//!
//! Matching is exact on family and vendor: Bun is not Node and a standalone
//! Brotli is not the copy bundled inside another runtime. A positive match acts
//! on a self-reported version; clearing a runtime requires a trusted identity.
//! A fix is verified only when every affected instance in a complete scope has
//! exited and a trusted replacement is running from a bound launch.
//!
//! The command reads no files and starts no processes.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub(crate) const COMMAND: &str = "runtime-identity-assess";
pub(crate) const FEATURE: &str = "runtime-identity-assess-v1";
const RESULT_SCHEMA: &str = "guard.runtime-identity-assessment.v1";

const MAX_ARTIFACTS: usize = 512;
const MAX_LOCATIONS: usize = 2_048;
const MAX_INSTANCES: usize = 4_096;
const MAX_ADVISORIES: usize = 1_024;
const MAX_RANGES: usize = 64;
const MAX_TEXT: usize = 256;
/// Every artifact can produce one row per advisory; this keeps the reply well
/// inside the bridge's output limit and the work inside its timeout.
const MAX_ARTIFACT_ADVISORY_PAIRS: usize = 16_384;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Assurance {
    Unknown,
    SelfReported,
    LocallyTrusted,
    VendorVerified,
}

impl Assurance {
    fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::SelfReported => "self_reported",
            Self::LocallyTrusted => "locally_trusted",
            Self::VendorVerified => "vendor_verified",
        }
    }

    fn trusted(self) -> bool {
        self >= Self::LocallyTrusted
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Coverage {
    ObservedOnly,
    PreflightOnly,
    BoundLaunch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum LocationState {
    Present,
    Missing,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum InstanceState {
    Running,
    Exited,
    Unknown,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    artifacts: Vec<ArtifactInput>,
    #[serde(default)]
    locations: Vec<LocationInput>,
    #[serde(default)]
    instances: Vec<InstanceInput>,
    #[serde(default)]
    advisories: Vec<AdvisoryInput>,
    #[serde(default)]
    scope_complete: bool,
    #[serde(default)]
    cached_bundle: Option<bundle::CachedBundleInput>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactInput {
    artifact_id: String,
    family: String,
    vendor: Option<String>,
    version: Option<String>,
    build_id: Option<String>,
    os: String,
    arch: String,
    executable_sha256: Option<String>,
    component_identity_sha256: Option<String>,
    identity_assurance: Assurance,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocationInput {
    location_id: String,
    artifact_id: Option<String>,
    state: LocationState,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstanceInput {
    instance_id: String,
    boot_identity: String,
    pid: u32,
    start_identity: String,
    artifact_id: String,
    location_id: Option<String>,
    state: InstanceState,
    coverage: Coverage,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdvisoryInput {
    advisory_id: String,
    family: String,
    vendor: Option<String>,
    version_scheme: String,
    ranges: Vec<RangeInput>,
    #[serde(default)]
    include_prerelease: bool,
    #[serde(default)]
    backport_build_ids: Vec<String>,
    /// Empty applies to every platform.
    #[serde(default)]
    platforms: Vec<PlatformInput>,
    /// A component bundled inside the runtime, whose own version the probe
    /// does not observe.
    #[serde(default)]
    bundled_component: Option<String>,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    known_exploited: bool,
    #[serde(default)]
    title: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlatformInput {
    os: String,
    arch: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RangeInput {
    introduced: Option<String>,
    fixed: Option<String>,
    last_affected: Option<String>,
}

pub(crate) fn run_command(bytes: &[u8]) -> Result<Value, String> {
    let request: Request =
        serde_json::from_slice(bytes).map_err(|_| "runtime_identity_request_invalid".to_owned())?;
    Ok(match assess(&request) {
        Ok(result) => json!({"ok": true, "result": result}),
        Err(error) => json!({"ok": false, "error": error}),
    })
}

/// A matched artifact's status for one advisory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Match {
    Affected(&'static str),
    NotAffected(&'static str),
    Unknown(&'static str),
}

struct Artifact<'a> {
    input: &'a ArtifactInput,
    assurance: Assurance,
    downgraded: Option<&'static str>,
}

pub(crate) fn assess(request: &Request) -> Result<Value, String> {
    let budget = bundle::Budget {
        artifacts: request.artifacts.len(),
        supplied: &request.advisories,
    };
    let (bundled, advisory_source) =
        bundle::bundle_advisories(request.cached_bundle.as_ref(), &budget);
    assess_with(request, &bundled, &advisory_source)
}

/// Launch admission: one probed artifact against advisories already taken
/// from the cached bundle by [`launch_advisories`].
pub(crate) fn assess_launch(artifact: &Value, bundled: &LaunchAdvisories) -> Result<Value, String> {
    let artifact = ArtifactInput::deserialize(artifact)
        .map_err(|_| "runtime_identity_request_invalid".to_owned())?;
    let request = Request {
        artifacts: vec![artifact],
        locations: Vec::new(),
        instances: Vec::new(),
        advisories: Vec::new(),
        scope_complete: false,
        cached_bundle: None,
    };
    assess_with(&request, &bundled.advisories, &bundled.source)
}

fn assess_with(
    request: &Request,
    bundled: &[AdvisoryInput],
    advisory_source: &Value,
) -> Result<Value, String> {
    // An unanchored bundle can report a runtime affected but never clear it.
    let clear_from = if advisory_source["anchored"] == true {
        usize::MAX
    } else {
        request.advisories.len()
    };
    let supplied: Vec<&AdvisoryInput> = request.advisories.iter().chain(bundled).collect();
    validate_bounds(request, &supplied)?;
    let artifacts = artifacts_by_id(&request.artifacts)?;
    let locations = locations_by_id(&request.locations, &artifacts)?;
    validate_instances(&request.instances, &artifacts, &locations)?;
    let advisories = supplied
        .into_iter()
        .map(|advisory| parse_intervals(advisory).map(|intervals| (advisory, intervals)))
        .collect::<Result<Vec<_>, _>>()?;
    let mut advisory_ids = BTreeSet::new();
    if !advisories
        .iter()
        .all(|(advisory, _)| advisory_ids.insert(advisory.advisory_id.as_str()))
    {
        return Err("runtime_identity_advisory_duplicate".to_owned());
    }

    let mut artifact_rows = Vec::with_capacity(artifacts.len());
    let mut matches: Vec<BTreeMap<&str, Match>> = vec![BTreeMap::new(); advisories.len()];
    for (id, artifact) in &artifacts {
        let mut rows = Vec::new();
        for (index, (advisory, intervals)) in advisories.iter().enumerate() {
            let Some(mut found) = match_artifact(artifact, advisory, intervals) else {
                continue;
            };
            if index >= clear_from && matches!(found, Match::NotAffected(_)) {
                found = Match::Unknown("advisory_source_unanchored");
            }
            matches[index].insert(id, found);
            let (status, reason) = match found {
                Match::Affected(reason) => ("affected", reason),
                Match::NotAffected(reason) => ("not_affected", reason),
                Match::Unknown(reason) => ("unknown", reason),
            };
            rows.push(
                json!({"advisory_id": advisory.advisory_id, "status": status, "reason": reason}),
            );
        }
        artifact_rows.push(json!({
            "artifact_id": id,
            "identity_fingerprint": fingerprint(artifact.input),
            "identity_assurance": artifact.assurance.as_str(),
            "assurance_downgraded": artifact.downgraded,
            "matches": rows,
        }));
    }

    let advisory_rows = advisories
        .iter()
        .zip(&matches)
        .map(|((advisory, _), by_artifact)| {
            advisory_verdict(request, &artifacts, &locations, advisory, by_artifact)
        })
        .collect::<Vec<_>>();

    Ok(json!({
        "schema": RESULT_SCHEMA,
        "scope_complete": request.scope_complete,
        "artifacts": artifact_rows,
        "advisories": advisory_rows,
        "advisory_source": advisory_source,
    }))
}

fn validate_bounds(request: &Request, advisories: &[&AdvisoryInput]) -> Result<(), String> {
    let over = request.artifacts.len() > MAX_ARTIFACTS
        || request.locations.len() > MAX_LOCATIONS
        || request.instances.len() > MAX_INSTANCES
        || advisories.len() > MAX_ADVISORIES
        || request.artifacts.len() * advisories.len() > MAX_ARTIFACT_ADVISORY_PAIRS
        || advisories.iter().any(|a| {
            a.ranges.len() > MAX_RANGES
                || a.backport_build_ids.len() > MAX_RANGES
                || a.platforms.len() > MAX_RANGES
        });
    if over {
        return Err("runtime_identity_request_too_large".to_owned());
    }
    Ok(())
}

fn text_ok(text: &str) -> bool {
    !text.trim().is_empty() && text.len() <= MAX_TEXT && !text.chars().any(char::is_control)
}

fn digest_ok(text: &Option<String>) -> bool {
    text.as_ref().is_none_or(|value| {
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

fn artifacts_by_id(inputs: &[ArtifactInput]) -> Result<BTreeMap<&str, Artifact<'_>>, String> {
    let mut artifacts = BTreeMap::new();
    for input in inputs {
        let optional_text = [&input.vendor, &input.version, &input.build_id];
        let valid = [&input.artifact_id, &input.family, &input.os, &input.arch]
            .into_iter()
            .all(|value| text_ok(value))
            && optional_text
                .into_iter()
                .flatten()
                .all(|value| text_ok(value))
            && digest_ok(&input.executable_sha256)
            && digest_ok(&input.component_identity_sha256);
        if !valid {
            return Err("runtime_identity_artifact_invalid".to_owned());
        }
        let (assurance, downgraded) = effective_assurance(input);
        let artifact = Artifact {
            input,
            assurance,
            downgraded,
        };
        if artifacts
            .insert(input.artifact_id.as_str(), artifact)
            .is_some()
        {
            return Err("runtime_identity_artifact_duplicate".to_owned());
        }
    }
    Ok(artifacts)
}

/// A vendor-verified claim needs the hash and version that prove it, and local
/// trust needs the hash; anything less is a self-reported hint.
fn effective_assurance(input: &ArtifactInput) -> (Assurance, Option<&'static str>) {
    let claimed = input.identity_assurance;
    if claimed == Assurance::VendorVerified
        && (input.executable_sha256.is_none() || input.version.is_none())
    {
        let fallback = if input.version.is_some() {
            Assurance::SelfReported
        } else {
            Assurance::Unknown
        };
        return (fallback, Some("vendor_verified_without_hash_or_version"));
    }
    if claimed == Assurance::LocallyTrusted && input.executable_sha256.is_none() {
        return (
            Assurance::SelfReported,
            Some("locally_trusted_without_hash"),
        );
    }
    (claimed, None)
}

fn fingerprint(input: &ArtifactInput) -> Option<String> {
    let executable = input.executable_sha256.as_deref()?;
    let fields = [
        "guard.runtime-artifact.v1",
        &input.family.to_ascii_lowercase(),
        &input.vendor.as_deref().unwrap_or("").to_ascii_lowercase(),
        input.version.as_deref().unwrap_or(""),
        input.build_id.as_deref().unwrap_or(""),
        &input.os.to_ascii_lowercase(),
        &input.arch.to_ascii_lowercase(),
        executable,
        input.component_identity_sha256.as_deref().unwrap_or(""),
    ];
    Some(hex::encode(Sha256::digest(fields.join("\0").as_bytes())))
}

fn locations_by_id<'a>(
    inputs: &'a [LocationInput],
    artifacts: &BTreeMap<&str, Artifact<'_>>,
) -> Result<BTreeMap<&'a str, &'a LocationInput>, String> {
    let mut locations = BTreeMap::new();
    for input in inputs {
        if !text_ok(&input.location_id) {
            return Err("runtime_identity_location_invalid".to_owned());
        }
        if input
            .artifact_id
            .as_deref()
            .is_some_and(|id| !artifacts.contains_key(id))
        {
            return Err("runtime_identity_unknown_artifact".to_owned());
        }
        if locations
            .insert(input.location_id.as_str(), input)
            .is_some()
        {
            return Err("runtime_identity_location_duplicate".to_owned());
        }
    }
    Ok(locations)
}

fn validate_instances(
    inputs: &[InstanceInput],
    artifacts: &BTreeMap<&str, Artifact<'_>>,
    locations: &BTreeMap<&str, &LocationInput>,
) -> Result<(), String> {
    let mut ids = BTreeSet::new();
    let mut processes = BTreeSet::new();
    for input in inputs {
        let valid = [
            &input.instance_id,
            &input.boot_identity,
            &input.start_identity,
        ]
        .into_iter()
        .all(|value| text_ok(value))
            && input.pid > 0;
        if !valid {
            return Err("runtime_identity_instance_invalid".to_owned());
        }
        if !artifacts.contains_key(input.artifact_id.as_str()) {
            return Err("runtime_identity_unknown_artifact".to_owned());
        }
        if input
            .location_id
            .as_deref()
            .is_some_and(|id| !locations.contains_key(id))
        {
            return Err("runtime_identity_unknown_location".to_owned());
        }
        if !ids.insert(input.instance_id.as_str()) {
            return Err("runtime_identity_instance_duplicate".to_owned());
        }
        // One process identity is one immutable instance.
        let process = (
            input.boot_identity.as_str(),
            input.pid,
            input.start_identity.as_str(),
        );
        if !processes.insert(process) {
            return Err("runtime_identity_instance_conflict".to_owned());
        }
    }
    Ok(())
}

#[path = "runtime_identity_verdict.rs"]
mod verdict;
use verdict::{advisory_verdict, match_artifact, parse_intervals};

#[path = "runtime_identity_bundle.rs"]
mod bundle;
pub(crate) use bundle::{
    launch_bundle_advisories as launch_advisories, now_seconds, CachedBundleInput,
    LaunchAdvisories, FEATURE as BUNDLE_FEATURE,
};

#[cfg(test)]
#[path = "runtime_identity_tests.rs"]
mod tests;
