//! `evaluation_contract` runner-authority kind: the semantic checks behind
//! `evaluation_contracts.py`. Python validates each record against its JSON
//! schema first; this kind then binds paths, endpoints, timestamps, cases
//! and the optional profile together.
//!
//! Requests: `{"op":"profile","profile","portable","temp_root"}` and
//! `{"op":"result","result","profile":object|null,"portable","temp_root"}`.
//! Answers: `{"ok":true}`, or `{"error":message}` for a record that breaks a
//! rule. `temp_root` is the caller's `tempfile.gettempdir()`.

use std::collections::HashSet;

use serde_json::{json, Map, Value};

use crate::evaluation_contract_scope::{
    endpoint_identity, local_endpoint, record_timestamp, Check, Scope,
};
use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

/// A field the schema requires is absent or has another type.
const MALFORMED: &str = "evaluation record is malformed";
const ENFORCING_ACTIONS: [&str; 4] = ["block", "approval", "rewrite", "redact-before-forward"];
const SUMMARY_KEYS: [(&str, &str); 5] = [
    ("passed", "passed"),
    ("failed", "failed"),
    ("unsupported", "unsupported"),
    ("blocked_environment", "blockedEnvironment"),
    ("not_run", "notRun"),
];

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let args = args_object(args)?;
    let temp_root = args
        .get("temp_root")
        .and_then(Value::as_str)
        .ok_or(ERR_INVALID)?;
    let portable = args
        .get("portable")
        .and_then(Value::as_bool)
        .ok_or(ERR_INVALID)?;
    let scope = Scope {
        portable,
        temp_root,
    };
    let checked = match args.get("op").and_then(Value::as_str) {
        Some("profile") => profile_semantics(args.get("profile").ok_or(ERR_INVALID)?, &scope),
        Some("result") => {
            let profile = args.get("profile").filter(|profile| !profile.is_null());
            let result = args.get("result").ok_or(ERR_INVALID)?;
            profile
                .map_or(Ok(()), |profile| profile_semantics(profile, &scope))
                .and_then(|()| result_semantics(result, profile, &scope))
        }
        _ => return Err(ERR_INVALID),
    };
    Ok(match checked {
        Ok(()) => json!({"ok": true}),
        Err(message) => json!({"error": message}),
    })
}

fn mapping<'v>(value: &'v Value, name: &str) -> Check<&'v Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| format!("{name} must be an object"))
}

fn field<'v>(object: &'v Map<String, Value>, key: &str) -> Check<&'v Value> {
    object.get(key).ok_or_else(|| MALFORMED.to_owned())
}

fn text<'v>(object: &'v Map<String, Value>, key: &str) -> Check<&'v str> {
    field(object, key)?
        .as_str()
        .ok_or_else(|| MALFORMED.to_owned())
}

fn list<'v>(object: &'v Map<String, Value>, key: &str) -> Check<&'v Vec<Value>> {
    field(object, key)?
        .as_array()
        .ok_or_else(|| MALFORMED.to_owned())
}

/// `dict.get(key)` that is present and not `None`.
fn present<'v>(object: &'v Map<String, Value>, key: &str) -> Option<&'v Value> {
    object.get(key).filter(|value| !value.is_null())
}

/// Python `==` on decoded JSON: `True == 1`, `1 == 1.0`, recursive containers.
fn py_eq(left: &Value, right: &Value) -> bool {
    match (py_number(left), py_number(right)) {
        (Some(left), Some(right)) => return left == right,
        (Some(_), None) | (None, Some(_)) => return false,
        (None, None) => {}
    }
    match (left, right) {
        (Value::Array(left), Value::Array(right)) => {
            left.len() == right.len() && left.iter().zip(right).all(|(a, b)| py_eq(a, b))
        }
        (Value::Object(left), Value::Object(right)) => {
            left.len() == right.len()
                && left
                    .iter()
                    .all(|(key, value)| right.get(key).is_some_and(|other| py_eq(value, other)))
        }
        _ => left == right,
    }
}

enum PyNumber {
    Int(i128),
    Float(f64),
}

fn py_number(value: &Value) -> Option<PyNumberValue> {
    match value {
        Value::Bool(flag) => Some(PyNumberValue(PyNumber::Int(i128::from(*flag)))),
        Value::Number(number) => Some(PyNumberValue(
            number
                .as_i64()
                .map(i128::from)
                .or_else(|| number.as_u64().map(i128::from))
                .map_or_else(
                    || PyNumber::Float(number.as_f64().unwrap_or(f64::NAN)),
                    PyNumber::Int,
                ),
        )),
        _ => None,
    }
}

struct PyNumberValue(PyNumber);

impl PartialEq for PyNumberValue {
    fn eq(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (PyNumber::Int(left), PyNumber::Int(right)) => left == right,
            (PyNumber::Float(left), PyNumber::Float(right)) => left == right,
            (PyNumber::Int(int), PyNumber::Float(float))
            | (PyNumber::Float(float), PyNumber::Int(int)) => int_eq_float(*int, *float),
        }
    }
}

/// Python compares an int with a float exactly.
fn int_eq_float(int: i128, float: f64) -> bool {
    float.is_finite() && float.fract() == 0.0 && float.abs() < 1e38 && float as i128 == int
}

/// `_validate_profile_semantics`.
fn profile_semantics(profile: &Value, scope: &Scope<'_>) -> Check<()> {
    let profile = mapping(profile, "profile")?;
    let build = mapping(field(profile, "buildIdentity")?, "buildIdentity")?;
    let mut digests = Vec::new();
    for item in list(profile, "installedArtifacts")? {
        digests.push(field(mapping(item, "installedArtifacts[]")?, "digest")?);
    }
    let build_digest = field(build, "artifactDigest")?;
    if !digests.iter().any(|digest| py_eq(digest, build_digest)) {
        return Err("buildIdentity.artifactDigest must identify an installed artifact".to_owned());
    }
    let mut capability_ids = HashSet::new();
    let mut duplicate = false;
    for item in list(profile, "expectedCapabilities")? {
        let id = text(mapping(item, "expectedCapabilities[]")?, "capabilityId")?;
        duplicate |= !capability_ids.insert(id);
    }
    if duplicate {
        return Err("profile has duplicate expected capability IDs".to_owned());
    }

    let target = mapping(field(profile, "targetScope")?, "targetScope")?;
    let root_path = scope.record_path(field(target, "rootPath")?, "targetScope.rootPath")?;
    for path in list(target, "allowedPaths")? {
        let candidate = scope.record_path(path, "targetScope.allowedPaths[]")?;
        if !scope.within(candidate, root_path) {
            return Err(
                "targetScope.allowedPaths[] must remain under targetScope.rootPath".to_owned(),
            );
        }
    }
    let mut scope_endpoints = HashSet::new();
    for endpoint in list(target, "allowedEndpoints")? {
        scope_endpoints.insert(local_endpoint(endpoint, "targetScope.allowedEndpoints[]")?);
    }

    let network = mapping(field(profile, "network")?, "network")?;
    let mut network_endpoints = Vec::new();
    for endpoint in list(network, "allowedEndpoints")? {
        network_endpoints.push(local_endpoint(endpoint, "network.allowedEndpoints[]")?);
    }
    if !network_endpoints
        .iter()
        .all(|endpoint| scope_endpoints.contains(endpoint))
    {
        return Err(
            "network.allowedEndpoints must be within targetScope.allowedEndpoints".to_owned(),
        );
    }
    if let Some(proxy) = present(network, "proxyUrl") {
        if !scope_endpoints.contains(local_endpoint(proxy, "network.proxyUrl")?) {
            return Err("network.proxyUrl must be within targetScope.allowedEndpoints".to_owned());
        }
    }
    Ok(())
}

/// `(finished - started).total_seconds() > maxDurationSeconds`.
fn exceeds_duration(micros: i128, limit: &Value) -> Check<bool> {
    if let Some(seconds) = limit.as_i64() {
        return Ok(micros > i128::from(seconds) * 1_000_000);
    }
    let seconds = limit.as_f64().ok_or_else(|| MALFORMED.to_owned())?;
    Ok(micros as f64 / 1e6 > seconds)
}

/// One case's own rules, before the profile binding.
fn case_semantics(
    case: &Map<String, Value>,
    evidence_type: &Value,
    scope: &Scope<'_>,
) -> Check<()> {
    let status = text(case, "status")?;
    let expected = field(case, "expectedAction")?;
    let expected_text = expected.as_str();
    if status == "passed"
        && (field(case, "proofType")? == "not_run"
            || matches!(expected_text, Some("unsupported" | "not_run"))
            || !py_eq(field(case, "observedAction")?, expected))
    {
        return Err("passed case requires executed proof and matching action".to_owned());
    }
    let witness = mapping(field(case, "witness")?, "cases[].witness")?;
    for key in ["path", "allowedPath"] {
        if let Some(path) = present(witness, key) {
            scope.record_path(path, &format!("cases[].witness.{key}"))?;
        }
    }
    for key in ["endpoint", "allowedEndpoint"] {
        if let Some(endpoint) = present(witness, key) {
            local_endpoint(endpoint, &format!("cases[].witness.{key}"))?;
        }
    }
    if status != "passed"
        || !expected_text.is_some_and(|action| ENFORCING_ACTIONS.contains(&action))
    {
        return Ok(());
    }
    if field(case, "proofType")? != "live_installed_host_test"
        || evidence_type != "live_installed_host_test"
    {
        return Err("passed enforcement case requires live installed host evidence".to_owned());
    }
    let distinct =
        || "passed enforcement case requires distinct denied and allowed witnesses".to_owned();
    let kind = field(witness, "kind")?.as_str();
    let paths = matches!(kind, Some("local_file" | "local_database"));
    let (denied, allowed) = match kind {
        _ if paths => (witness.get("path"), witness.get("allowedPath")),
        Some("loopback_receiver") => (witness.get("endpoint"), witness.get("allowedEndpoint")),
        _ => (None, None),
    };
    let (Some(denied), Some(allowed)) = (
        denied.and_then(Value::as_str),
        allowed.and_then(Value::as_str),
    ) else {
        return Err(distinct());
    };
    let same_target = if paths {
        scope.within(denied, allowed) && scope.within(allowed, denied)
    } else {
        endpoint_identity(denied) == endpoint_identity(allowed)
    };
    if same_target {
        return Err(distinct());
    }
    if witness.get("receiverReady") != Some(&Value::Bool(true))
        || witness.get("deniedReached") != Some(&Value::Bool(false))
        || witness.get("allowedReached") != Some(&Value::Bool(true))
    {
        return Err("passed enforcement case requires ready receiver, absent denied effect, and present allowed effect".to_owned());
    }
    Ok(())
}

/// `_validate_result_semantics`.
fn result_semantics(result: &Value, profile: Option<&Value>, scope: &Scope<'_>) -> Check<()> {
    let result = mapping(result, "evaluation result")?;
    let profile = profile
        .map(|profile| mapping(profile, "profile"))
        .transpose()?;
    let started = record_timestamp(field(result, "startedAt")?, "startedAt")?;
    let finished = record_timestamp(field(result, "finishedAt")?, "finishedAt")?;
    if finished < started {
        return Err("finishedAt must not precede startedAt".to_owned());
    }
    if let Some(profile) = profile {
        let limits = mapping(field(profile, "resourceLimits")?, "resourceLimits")?;
        if exceeds_duration(finished - started, field(limits, "maxDurationSeconds")?)? {
            return Err("result duration exceeds profile maxDurationSeconds".to_owned());
        }
    }
    let artifact_value = field(result, "artifactIdentity")?;
    let artifact = mapping(artifact_value, "artifactIdentity")?;
    let build = mapping(field(result, "buildIdentity")?, "buildIdentity")?;
    let evidence = mapping(field(result, "evidenceIdentity")?, "evidenceIdentity")?;
    let artifact_digest = field(artifact, "digest")?;
    if !py_eq(field(build, "artifactDigest")?, artifact_digest) {
        return Err("buildIdentity.artifactDigest must match artifactIdentity.digest".to_owned());
    }
    if !py_eq(field(evidence, "artifactDigest")?, artifact_digest) {
        return Err(
            "evidenceIdentity.artifactDigest must match artifactIdentity.digest".to_owned(),
        );
    }
    let evidence_type = field(evidence, "evidenceType")?;
    let passed = field(result, "status")? == "passed";
    if passed && evidence_type == "not_run" {
        return Err("passed evaluation result requires executed evidence".to_owned());
    }

    let cases = list(result, "cases")?;
    let mut case_ids = HashSet::new();
    let mut statuses = Vec::new();
    for raw_case in cases {
        let case = mapping(raw_case, "cases[]")?;
        if !case_ids.insert(text(case, "caseId")?) {
            return Err("duplicate result caseId".to_owned());
        }
        statuses.push(text(case, "status")?);
        case_semantics(case, evidence_type, scope)?;
    }
    if passed && statuses.iter().any(|status| *status != "passed") {
        return Err("passed evaluation result cannot include an unpassed case".to_owned());
    }
    if let Some(summary) = present(result, "summary") {
        let summary = mapping(summary, "summary")?;
        for (status, key) in SUMMARY_KEYS {
            let count = statuses.iter().filter(|each| **each == status).count();
            if !py_eq(field(summary, key)?, &json!(count)) {
                return Err("result summary does not match cases".to_owned());
            }
        }
    }

    let Some(profile) = profile else {
        if passed || statuses.contains(&"passed") {
            return Err(
                "passed result requires the evaluation profile for complete coverage".to_owned(),
            );
        }
        return Ok(());
    };
    profile_binding(result, profile, artifact_value, &case_ids, scope)
}

/// The tail of `_validate_result_semantics` that binds a result to its profile.
fn profile_binding(
    result: &Map<String, Value>,
    profile: &Map<String, Value>,
    artifact: &Value,
    case_ids: &HashSet<&str>,
    scope: &Scope<'_>,
) -> Check<()> {
    if !py_eq(
        field(result, "profileId")?,
        &Value::from(text(profile, "profileId")?),
    ) {
        return Err("result.profileId does not match the supplied profile".to_owned());
    }
    if !py_eq(
        field(result, "buildIdentity")?,
        field(profile, "buildIdentity")?,
    ) {
        return Err("result.buildIdentity does not match the supplied profile".to_owned());
    }
    let mut installed = Vec::new();
    for item in list(profile, "installedArtifacts")? {
        installed.push(mapping(item, "installedArtifacts[]")?);
    }
    let artifact = mapping(artifact, "artifactIdentity")?;
    let is_installed = installed.iter().any(|item| {
        item.len() == artifact.len()
            && item
                .iter()
                .all(|(key, value)| artifact.get(key).is_some_and(|other| py_eq(value, other)))
    });
    if !is_installed {
        return Err("result.artifactIdentity is not installed by the supplied profile".to_owned());
    }
    let mut expected = Vec::new();
    for item in list(profile, "expectedCapabilities")? {
        let item = mapping(item, "expectedCapabilities[]")?;
        expected.push((text(item, "capabilityId")?, field(item, "expectedAction")?));
    }
    let expected_ids: HashSet<&str> = expected.iter().map(|(id, _)| *id).collect();
    if expected_ids.len() != expected.len() {
        return Err("profile has duplicate expected capability IDs".to_owned());
    }
    if *case_ids != expected_ids {
        return Err("result cases must cover exactly the profile expected capabilities".to_owned());
    }
    let target = mapping(field(profile, "targetScope")?, "targetScope")?;
    let root_path = text(target, "rootPath")?;
    let mut allowed_paths = Vec::new();
    for path in list(target, "allowedPaths")? {
        allowed_paths.push(path.as_str().ok_or_else(|| MALFORMED.to_owned())?);
    }
    let allowed_endpoints = list(target, "allowedEndpoints")?;
    for raw_case in list(result, "cases")? {
        let case = mapping(raw_case, "cases[]")?;
        let case_id = text(case, "caseId")?;
        let action = expected
            .iter()
            .find_map(|(id, action)| (*id == case_id).then_some(*action))
            .ok_or_else(|| MALFORMED.to_owned())?;
        if !py_eq(field(case, "expectedAction")?, action) {
            return Err("result case expected action differs from the profile".to_owned());
        }
        let witness = mapping(field(case, "witness")?, "cases[].witness")?;
        for key in ["path", "allowedPath"] {
            let Some(path) = present(witness, key) else {
                continue;
            };
            let path = path.as_str().ok_or_else(|| MALFORMED.to_owned())?;
            if !scope.within(path, root_path)
                || !allowed_paths
                    .iter()
                    .any(|allowed| scope.within(path, allowed))
            {
                return Err("result witness path is outside the profile target scope".to_owned());
            }
        }
        for key in ["endpoint", "allowedEndpoint"] {
            if present(witness, key).is_some_and(|endpoint| {
                !allowed_endpoints
                    .iter()
                    .any(|allowed| py_eq(allowed, endpoint))
            }) {
                return Err(
                    "result witness endpoint is outside the profile target scope".to_owned(),
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "evaluation_contract_tests.rs"]
mod tests;
