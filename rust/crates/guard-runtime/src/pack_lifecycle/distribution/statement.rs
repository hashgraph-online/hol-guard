//! The in-toto statement Sigstore verified must bind the exact bytes to this
//! repository's workflow, ref and source commit. A statement that attests a
//! different subject is not an error: the caller decides whether any bundle
//! attested the subject it needs.
use super::{hex, json_failure};
use serde_json::{json, Value};

const CONTENT_TYPE: &str = "application/vnd.in-toto+json";
const MAX_STATEMENT_BYTES: usize = 1024 * 1024;
const MAX_SUBJECTS: usize = 64;
const REPOSITORY_URI: &str = "https://github.com/hashgraph-online/hol-guard";
const WORKFLOW_PATH: &str = ".github/workflows/extension-artifact-regen.yml";
const WORKFLOW_ID: &str =
    "https://github.com/hashgraph-online/hol-guard/.github/workflows/extension-artifact-regen.yml@refs/heads/main";
const SOURCE_URI: &str = "git+https://github.com/hashgraph-online/hol-guard@refs/heads/main";
const BUILD_TYPE: &str = "https://actions.github.io/buildtypes/workflow/v1";

fn reject<T>(code: &str) -> Result<T, String> {
    Err(code.to_owned())
}

fn decode(payload: &str) -> Result<Value, String> {
    crate::strict_json::parse(payload.as_bytes()).map_err(|code| json_failure(&code).to_owned())
}

pub(super) fn validate(input: &Value) -> Result<Value, String> {
    let text = |key: &str| input[key].as_str().ok_or("distribution_request_invalid");
    let (content_type, payload) = (text("content_type")?, text("payload")?);
    let (subject, digest, source) = (text("subject")?, text("digest")?, text("source")?);
    if !hex(digest, 64) || !hex(source, 40) {
        return reject("distribution_request_invalid");
    }
    if content_type != CONTENT_TYPE || payload.len() > MAX_STATEMENT_BYTES {
        return reject("distribution_statement_payload_invalid");
    }
    let statement = decode(payload)?;
    if statement["_type"] != "https://in-toto.io/Statement/v1"
        || statement["predicateType"] != "https://slsa.dev/provenance/v1"
    {
        return reject("distribution_statement_type_invalid");
    }
    let predicate = &statement["predicate"];
    if !predicate.is_object() {
        return reject("distribution_predicate_invalid");
    }
    let (build, run) = (&predicate["buildDefinition"], &predicate["runDetails"]);
    if !build.is_object()
        || !run.is_object()
        || !build["externalParameters"].is_object()
        || !run["builder"].is_object()
    {
        return reject("distribution_build_definition_invalid");
    }
    let workflow =
        json!({"repository": REPOSITORY_URI, "path": WORKFLOW_PATH, "ref": "refs/heads/main"});
    if build["buildType"] != BUILD_TYPE
        || build["externalParameters"]["workflow"] != workflow
        || run["builder"]["id"] != WORKFLOW_ID
    {
        return reject("distribution_builder_differs");
    }
    let Some(dependencies) = build["resolvedDependencies"].as_array() else {
        return reject("distribution_dependencies_invalid");
    };
    let mut sources = dependencies
        .iter()
        .filter(|row| row.is_object() && row["uri"] == SOURCE_URI);
    let pinned = json!({"gitCommit": source});
    match (sources.next(), sources.next()) {
        (Some(row), None) if row["digest"] == pinned => {}
        _ => return reject("distribution_source_differs"),
    }
    let subjects = statement["subject"]
        .as_array()
        .filter(|rows| !rows.is_empty() && rows.len() <= MAX_SUBJECTS);
    let Some(subjects) = subjects else {
        return reject("distribution_subject_count_invalid");
    };
    let mut named = subjects
        .iter()
        .filter(|row| row.is_object() && row["name"] == subject);
    let candidate = named.next();
    if named.next().is_some() {
        return reject("distribution_duplicate_subjects");
    }
    let attested = candidate.is_some_and(|row| row["digest"] == json!({"sha256": digest}));
    Ok(json!({"attested": attested}))
}
