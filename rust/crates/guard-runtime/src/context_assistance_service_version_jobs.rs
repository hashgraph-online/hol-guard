//! Route all bounded preparation/switch jobs through one operator contract.
//! Progress never authorizes a runtime; the live coordinator owns every effect.
use super::*;
#[cfg(unix)]
use crate::policy_store::context_assistance_registry::switching::jobs as switches;
use std::path::Path;

fn invalid() -> String {
    "native_context_assistance_versions_request_invalid".into()
}
fn generation(raw: &str) -> Result<u64, String> {
    raw.parse::<u64>()
        .ok()
        .filter(|n| *n > 0 && n.to_string() == raw)
        .ok_or_else(invalid)
}
fn is_switch(home: &Path, id: &str) -> Result<bool, String> {
    #[cfg(unix)]
    {
        Ok(switches::get(home, id)?.is_some())
    }
    #[cfg(not(unix))]
    {
        let _ = (home, id);
        Ok(false)
    }
}
pub(super) fn list(service: &Service, home: &Path) -> Result<Value, String> {
    let mut values = service.updates.list(home)?;
    #[cfg(unix)]
    for job in switches::list(home)? {
        if values.iter().any(|v| v["job_id"] == job.request.job_id) {
            return Err("native_context_assistance_switch_idempotency_conflict".into());
        }
        values.push(service.switch_job(home, &job.request.job_id)?);
    }
    if values.len() > 32 {
        return Err("native_context_assistance_install_job_limit".into());
    }
    values.sort_by(|a, b| {
        b["created_at_ms"]
            .as_u64()
            .cmp(&a["created_at_ms"].as_u64())
            .then(a["job_id"].as_str().cmp(&b["job_id"].as_str()))
    });
    Ok(json!({"jobs":values}))
}
pub(super) fn get(service: &Service, home: &Path, id: &str) -> Result<Value, String> {
    if is_switch(home, id)? {
        #[cfg(unix)]
        return service.switch_job(home, id);
    }
    service.updates.get(home, id)
}
pub(super) fn cancel(service: &Service, home: &Path, id: &str) -> Result<Value, String> {
    if is_switch(home, id)? {
        #[cfg(unix)]
        return service.cancel_switch(home, id);
    }
    service.updates.cancel(home, id)
}
pub(super) fn recover(
    service: &Service,
    home: &Path,
    id: &str,
    expected: Option<&str>,
) -> Result<Value, String> {
    if is_switch(home, id)? {
        let generation = generation(expected.ok_or_else(invalid)?)?;
        #[cfg(unix)]
        return service.reconcile_switch(home, id, generation);
        #[cfg(not(unix))]
        {
            let _ = generation;
        }
    }
    if expected.is_some() {
        return Err(invalid());
    }
    service.updates.recover(home, id)
}
pub(super) fn prepare(
    service: &Service,
    home: &Path,
    id: &str,
    target: Option<&str>,
    expected: &str,
) -> Result<Value, String> {
    let generation = generation(expected)?;
    #[cfg(unix)]
    {
        match target {
            Some(target) => service.prepare_switch(
                home,
                switches::SwitchRequest {
                    job_id: id.into(),
                    target_runtime_id: target.into(),
                    expected_generation: generation,
                    rollback: false,
                },
            ),
            None => service.prepare_rollback(home, id, generation),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (service, home, id, target, generation);
        Err("native_context_assistance_switch_platform_unsupported".into())
    }
}
pub(super) fn commit(
    service: &Service,
    home: &Path,
    id: &str,
    expected: &str,
    reconnect: bool,
) -> Result<Value, String> {
    let generation = generation(expected)?;
    #[cfg(unix)]
    {
        service.commit_switch(home, id, generation, reconnect)
    }
    #[cfg(not(unix))]
    {
        let _ = (service, home, id, generation, reconnect);
        Err("native_context_assistance_switch_platform_unsupported".into())
    }
}
