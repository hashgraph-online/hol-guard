//! `network_status_build` runner-authority kind: the daemon's
//! `guard.network-status.v1` payload, built from the platform capability
//! profiles and the network supervisor's health without promoting a static
//! profile to protection.
//!
//! Python keeps the profile table and the supervisor and sends
//! `{"platform": str, "profiles": [...], "explicit": bool, "host_only": bool,
//! "supervisor": {...} | null, "legacy_domain_policy": {...} | null}`.
//! `platform` is the host's `sys.platform` spelling. Each profile carries
//! `backend_id`, `platform`, `maximum_grade`, `production_ready`,
//! `requires_privilege` and `reason_code`. `explicit` marks profiles the caller
//! chose, which count as supported off their own platform; `host_only` keeps
//! only the host's profiles. `supervisor` is the supervisor health projection.
//! The answer is the status payload `network_status_validation` checks.

use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::network_status_validation::GRADES;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const STATUS_SCHEMA: &str = "guard.network-status.v1";
const UNAVAILABLE: &str = "unavailable";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    platform: String,
    profiles: Vec<Profile>,
    explicit: bool,
    host_only: bool,
    supervisor: Option<Map<String, Value>>,
    legacy_domain_policy: Option<Map<String, Value>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    backend_id: String,
    platform: String,
    maximum_grade: String,
    production_ready: bool,
    requires_privilege: bool,
    reason_code: String,
}

/// What the supervisor reports about the backend it runs.
struct Health<'a> {
    backend_id: Option<&'a str>,
    installed: bool,
    grade: &'a str,
    permits_enforcement: bool,
}

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let request = Request::deserialize(args).map_err(|_| ERR_INVALID)?;
    let health = request.supervisor.as_ref().map(health).transpose()?;
    let host = host_family(&request.platform);
    let profiles: Vec<&Profile> = request
        .profiles
        .iter()
        .filter(|profile| !request.host_only || host == Some(profile.platform.as_str()))
        .collect();

    let mut active_grade = UNAVAILABLE;
    let mut backends = Vec::with_capacity(profiles.len());
    for profile in &profiles {
        let maximum = grade_rank(&profile.maximum_grade)?;
        let on_host = host == Some(profile.platform.as_str());
        let selected = health
            .as_ref()
            .filter(|health| on_host && health.backend_id == Some(profile.backend_id.as_str()));
        let installed = selected.is_some_and(|health| health.installed);
        let verified = match selected {
            Some(health) => {
                let rank = grade_rank(health.grade)?;
                health.installed && rank != 0 && rank <= maximum
            }
            None => false,
        };
        let active = selected.is_some_and(|health| health.permits_enforcement)
            && verified
            && profile.production_ready;
        let effective_grade = match selected {
            Some(health) if active => health.grade,
            _ => UNAVAILABLE,
        };
        if active {
            active_grade = effective_grade;
        }
        let reason_code = if active {
            "independent-observer-unavailable"
        } else if selected.is_none() {
            "no-live-provider-probe"
        } else {
            profile.reason_code.as_str()
        };
        backends.push(json!({
            "backend_id": profile.backend_id,
            "platform": profile.platform,
            "supported": on_host || request.explicit,
            "installed": installed,
            "verified": verified,
            "active": active,
            "observed": false,
            "advertised_maximum_grade": profile.maximum_grade,
            "effective_grade": effective_grade,
            "production_ready": profile.production_ready,
            "requires_privilege": profile.requires_privilege,
            "reason_code": reason_code,
            "reference_reason_code": profile.reason_code,
        }));
    }

    let protection_active = backends.iter().any(|backend| backend["active"] == true);
    let reason_code = match host {
        None => "unsupported-host-platform",
        Some(_) if profiles.is_empty() => "no-platform-provider-profile",
        Some(_)
            if health
                .as_ref()
                .is_some_and(|health| health.backend_id.is_some())
                && !protection_active =>
        {
            "provider-probe-not-enforcing"
        }
        Some(_) => "no-verified-installed-backend",
    };
    // The grade borrows from the supervisor report, which moves into the
    // status below.
    let effective_grade = json!(active_grade);
    let mut status = Map::new();
    status.insert("schema".into(), json!(STATUS_SCHEMA));
    status.insert("host_platform".into(), json!(host.unwrap_or("unsupported")));
    status.insert("effective_grade".into(), effective_grade.clone());
    status.insert("independently_observed_grade".into(), json!(UNAVAILABLE));
    status.insert("protection_active".into(), json!(protection_active));
    status.insert("independently_observed".into(), json!(false));
    status.insert("reason_code".into(), json!(reason_code));
    status.insert("backends".into(), Value::Array(backends));
    if let Some(policy) = request.legacy_domain_policy {
        status.insert("legacy_domain_policy".into(), Value::Object(policy));
    }
    if let Some(mut supervisor) = request.supervisor {
        supervisor.insert("effective_grade".into(), effective_grade);
        supervisor.insert("permits_enforcement".into(), json!(protection_active));
        status.insert("supervisor".into(), Value::Object(supervisor));
    }
    Ok(Value::Object(status))
}

fn health(supervisor: &Map<String, Value>) -> Result<Health<'_>, &'static str> {
    let backend_id = match supervisor.get("backend_id") {
        None | Some(Value::Null) => None,
        Some(Value::String(backend_id)) => Some(backend_id.as_str()),
        Some(_) => return Err(ERR_INVALID),
    };
    let grade = supervisor
        .get("effective_grade")
        .and_then(Value::as_str)
        .ok_or(ERR_INVALID)?;
    grade_rank(grade)?;
    Ok(Health {
        backend_id,
        installed: supervisor
            .get("backend_digest")
            .is_some_and(|digest| !digest.is_null()),
        grade,
        permits_enforcement: supervisor
            .get("permits_enforcement")
            .and_then(Value::as_bool)
            .ok_or(ERR_INVALID)?,
    })
}

/// The platform family `sys.platform` names, or `None` for a host without one.
fn host_family(platform: &str) -> Option<&'static str> {
    let platform = platform.to_ascii_lowercase();
    if platform.starts_with("linux") {
        Some("linux")
    } else if platform == "darwin" {
        Some("macos")
    } else if matches!(platform.as_str(), "win32" | "cygwin" | "msys") {
        Some("windows")
    } else {
        None
    }
}

fn grade_rank(grade: &str) -> Result<usize, &'static str> {
    GRADES
        .iter()
        .position(|known| *known == grade)
        .ok_or(ERR_INVALID)
}

#[cfg(test)]
#[path = "network_status_build_tests.rs"]
mod tests;
