//! `GithubCliClassify` — resident op for the GitHub CLI capability classifier.
//!
//! Pure: classifies one GitHub CLI argument vector through
//! `guard_command::github_command_capabilities::classify_github_cli`. No IO.

use crate::package_authority_op::request_digest_with_limit;
use guard_contracts::{
    GithubCliAssessmentV1, GithubCliClassifyRequestV1, GithubCliClassifyResultV1,
    GITHUB_CLI_CLASSIFY_MAX_BYTES, GITHUB_CLI_CLASSIFY_REQUEST_SCHEMA,
    GITHUB_CLI_CLASSIFY_RESULT_SCHEMA,
};

pub(crate) fn evaluate_github_cli_classify_request(
    request: &GithubCliClassifyRequestV1,
) -> Result<Vec<u8>, String> {
    // Bound the complete canonical request (every field, JSON-escaped) before any
    // hashing or classification work; an oversized request has no digest to bind.
    let request_sha256 = request_digest_with_limit(request, GITHUB_CLI_CLASSIFY_MAX_BYTES)
        .map_err(|_| "native_github_cli_classify_too_large".to_owned())?;
    let (status, code, assessment, pr_body_file_operand) = match evaluate(request) {
        Ok((assessment, operand)) => ("ok".to_owned(), "ok".to_owned(), Some(assessment), operand),
        Err(code) => ("error".to_owned(), code, None, None),
    };
    crate::encode_response(&GithubCliClassifyResultV1 {
        schema: GITHUB_CLI_CLASSIFY_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status,
        code,
        assessment,
        pr_body_file_operand,
    })
}

fn evaluate(
    request: &GithubCliClassifyRequestV1,
) -> Result<(GithubCliAssessmentV1, Option<String>), String> {
    if request.schema != GITHUB_CLI_CLASSIFY_REQUEST_SCHEMA {
        return Err("native_github_cli_classify_schema_mismatch".to_owned());
    }
    let assessment = guard_command::github_command_capabilities::classify_github_cli(&request.args);
    let operand = guard_command::github_command_capabilities::static_markdown_pr_body_file_operand(
        &request.args,
    );
    Ok((
        GithubCliAssessmentV1 {
            capability: assessment.capability.as_str().to_owned(),
            reason_code: assessment.reason_code,
            detail: assessment.detail,
            capabilities: assessment
                .capabilities
                .iter()
                .map(|item| item.as_str().to_owned())
                .collect(),
        },
        operand,
    ))
}

#[cfg(test)]
#[path = "github_cli_classify_op_tests.rs"]
mod tests;
