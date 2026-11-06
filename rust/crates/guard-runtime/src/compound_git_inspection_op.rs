//! `CompoundGitInspection` resident op.
//!
//! Rust owns the verdict for whether a modeled shell command is a
//! deterministic, bounded Git routine. The Python transport sends the modeled
//! segments plus observed facts and relays `allowed`. A malformed request is
//! an error result with `allowed = false`; nothing here falls back to Python.

use std::path::Path;

use guard_contracts::{
    CompoundGitCheckV1, CompoundGitInspectionRequestV1, CompoundGitInspectionResultV1,
    CompoundGitSegmentV1, COMPOUND_GIT_INSPECTION_MAX_BYTES,
    COMPOUND_GIT_INSPECTION_REQUEST_SCHEMA, COMPOUND_GIT_INSPECTION_RESULT_SCHEMA,
};
use guard_policy_snapshot::digest_bytes;

use super::context_digest_json::write_canonical_json_with_limit;
use crate::compound_git_args as args;
use crate::compound_git_chain as chain;
use crate::compound_git_facts::{GitFacts, ResidentGitFacts};
use crate::compound_git_segments as segments;

const INVALID: &str = "native_compound_git_inspection_invalid";
const MAX_SEGMENTS: usize = 128;
const MAX_TOKENS: usize = 512;
const MAX_STRING_BYTES: usize = 16 * 1024;
const MAX_ENVIRONMENT: usize = 128;
const MAX_PATHSPECS: usize = 16;
const ALLOWED_PAGER_KEYS: [&str; 3] = ["pager.log", "pager.blame", "pager.branch"];

pub(crate) struct Verdict {
    pub(crate) allowed: bool,
    pub(crate) value: Option<String>,
}

impl Verdict {
    fn of(allowed: bool) -> Self {
        Self {
            allowed,
            value: None,
        }
    }
}

fn request_digest(request: &CompoundGitInspectionRequestV1) -> Result<String, &'static str> {
    let material = serde_json::to_value(request).map_err(|_| INVALID)?;
    let mut bytes = Vec::new();
    write_canonical_json_with_limit(&material, &mut bytes, COMPOUND_GIT_INSPECTION_MAX_BYTES)
        .map_err(|_| INVALID)?;
    Ok(format!("sha256:{}", digest_bytes(&bytes)))
}

fn segment_is_bounded(segment: &CompoundGitSegmentV1) -> bool {
    segment.tokens.len() <= MAX_TOKENS
        && segment.control_before.len() <= 8
        && segment.control_after.len() <= 8
        && segment
            .tokens
            .iter()
            .chain(&segment.control_before)
            .chain(&segment.control_after)
            .all(|value| value.len() <= MAX_STRING_BYTES)
        && segment
            .effective_cwd
            .iter()
            .chain(segment.directory_operation.iter())
            .all(|value| value.len() <= MAX_STRING_BYTES && !value.contains('\0'))
}

fn path_field_is_bounded(value: &Option<String>) -> bool {
    value
        .iter()
        .all(|text| text.len() <= MAX_STRING_BYTES && !text.contains('\0'))
}

fn request_is_bounded(request: &CompoundGitInspectionRequestV1) -> bool {
    request.request_id.len() <= 128
        && request.segments.len() <= MAX_SEGMENTS
        && request.segments.iter().all(segment_is_bounded)
        && request.environment.len() <= MAX_ENVIRONMENT
        && request.groups.len() <= 256
        && request.values.len() <= MAX_PATHSPECS
        && request
            .values
            .iter()
            .all(|value| value.len() <= MAX_STRING_BYTES)
        && request
            .command_text
            .iter()
            .chain(request.value.iter())
            .all(|text| text.len() <= MAX_STRING_BYTES)
        && path_field_is_bounded(&request.cwd)
        && path_field_is_bounded(&request.home_dir)
        && path_field_is_bounded(&request.repository_path)
        && path_field_is_bounded(&request.git_binary)
        && path_field_is_bounded(&request.account_home)
        && request
            .pager_key
            .iter()
            .all(|key| ALLOWED_PAGER_KEYS.contains(&key.as_str()))
        && !request.home.contains('\0')
        && request.home.len() <= MAX_STRING_BYTES
        && request.environment.iter().all(|(key, value)| {
            key.len() <= 256 && value.len() <= MAX_STRING_BYTES && !value.contains('\0')
        })
}

/// The verdict for one check, or `None` when a required field is missing.
pub(crate) fn decide(
    request: &CompoundGitInspectionRequestV1,
    facts: &dyn GitFacts,
) -> Option<Verdict> {
    let home_dir = request.home_dir.as_deref().map(Path::new);
    let one_segment = || match request.segments.as_slice() {
        [segment] => Some(segment),
        _ => None,
    };
    Some(match request.check {
        CompoundGitCheckV1::Compound => Verdict::of(chain::is_low_risk_compound_git_inspection(
            facts,
            &request.segments,
            request.complete,
        )),
        CompoundGitCheckV1::Segment => Verdict::of(segments::is_low_risk_git_inspection_segment(
            facts,
            one_segment()?,
            home_dir,
        )),
        CompoundGitCheckV1::PushSegment => Verdict::of(segments::is_low_risk_git_push_segment(
            facts,
            one_segment()?,
        )),
        CompoundGitCheckV1::Standalone => Verdict::of(chain::is_low_risk_standalone_git_routine(
            facts,
            &request.segments,
            request.complete,
            home_dir,
        )),
        CompoundGitCheckV1::ObjectExistenceQuery => {
            Verdict::of(chain::is_safe_standalone_git_object_existence_query(
                facts,
                request.command_text.as_deref()?,
                Path::new(request.cwd.as_deref()?),
            ))
        }
        CompoundGitCheckV1::HomeGitCPath => {
            let value = args::canonical_home_git_c_path(request.command_text.as_deref()?);
            Verdict {
                allowed: value.is_some(),
                value,
            }
        }
        CompoundGitCheckV1::RepositoryPath => {
            Verdict::of(args::safe_repository_path(request.value.as_deref()?))
        }
        CompoundGitCheckV1::CachedDiffPathspecs => {
            Verdict::of(args::safe_cached_diff_pathspecs(&request.values))
        }
        CompoundGitCheckV1::ShowConfig => Verdict::of(segments::show_config_is_execution_free(
            facts,
            one_segment()?,
            request.repository_path.as_deref(),
        )),
        CompoundGitCheckV1::LogConfig => Verdict::of(segments::log_config_is_execution_free(
            facts,
            Path::new(request.cwd.as_deref()?),
            Path::new(request.git_binary.as_deref()?),
            request.pager_key.as_deref().unwrap_or("pager.log"),
        )),
    })
}

pub(crate) fn evaluate_compound_git_inspection_request(
    request: &CompoundGitInspectionRequestV1,
) -> Result<Vec<u8>, String> {
    evaluate_with_facts(request, &ResidentGitFacts::new(request))
}

pub(crate) fn evaluate_with_facts(
    request: &CompoundGitInspectionRequestV1,
    facts: &dyn GitFacts,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request).map_err(str::to_owned)?;
    let (status, code, verdict) = if request.schema != COMPOUND_GIT_INSPECTION_REQUEST_SCHEMA {
        (
            "error",
            "native_compound_git_inspection_schema_mismatch",
            Verdict::of(false),
        )
    } else if !request_is_bounded(request) {
        ("error", INVALID, Verdict::of(false))
    } else {
        match decide(request, facts) {
            Some(verdict) => ("ok", "ok", verdict),
            None => ("error", INVALID, Verdict::of(false)),
        }
    };
    crate::encode_response(&CompoundGitInspectionResultV1 {
        schema: COMPOUND_GIT_INSPECTION_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: status.to_owned(),
        code: code.to_owned(),
        allowed: verdict.allowed,
        value: verdict.value,
    })
}
