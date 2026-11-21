//! An execution RPC must not outlive the CLI sink that supervises it.
//! Unlike the pooled stream client, this process owns one request and exits
//! on parent-pipe death, closing its socket so the resident cancels the launch.
use guard_contained_process::host_owner::HostOwner;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;

pub(crate) fn run(
    state_base: &Path,
    payload: Vec<u8>,
    host_pid: Option<u32>,
) -> Result<Vec<u8>, String> {
    let value = crate::strict_json_value(&payload)?;
    if value.get("operation").and_then(serde_json::Value::as_str) != Some("native_bash_execute") {
        return Err("native_bash_client_request_invalid".into());
    }
    if std::env::var_os(crate::PARENT_LIVENESS_FD_ENV).is_none() {
        return Err("native_bash_client_parent_unbound".into());
    }
    let alive = crate::resident_transport_service::resident_parent_liveness()?;
    let host = host_pid
        .map(|pid| -> Result<HostOwner, String> {
            let harness = value
                .pointer("/request/capture/harness")
                .and_then(serde_json::Value::as_str)
                .ok_or("native_bash_host_owner_unavailable")?;
            let names: &[&str] = match harness {
                "omp" => &["bun", "node", "omp"],
                "pi" => &["bun", "node", "pi"],
                _ => return Err("native_bash_host_owner_unavailable".into()),
            };
            HostOwner::observe(pid, names).map_err(|_| "native_bash_host_owner_unavailable".into())
        })
        .transpose();
    let host = match host {
        Ok(host) => host,
        // This check precedes the request thread and socket. Its structured
        // refusal proves no dispatch; later transport loss stays uncertain.
        Err(_) => return owner_refused_before_request(&value),
    };
    let state_base = state_base.to_owned();
    let timeout = crate::managed_resident::client_timeout(&payload);
    let request = value
        .get("request")
        .cloned()
        .ok_or("native_bash_client_request_invalid")?;
    let response = wait_for_owner(alive, host, move || {
        crate::managed_resident::client_request(&state_base, &payload, timeout)
    })?;
    let reply = crate::strict_json_value(&response)?;
    if !crate::native_bash_reply_validation::bound_execution(&reply, &request) {
        return Err("native_bash_response_invalid".into());
    }
    Ok(response)
}

fn owner_refused_before_request(value: &serde_json::Value) -> Result<Vec<u8>, String> {
    use guard_contracts::{NativeBashExecuteRequestV1, NativeBashExecuteResultV1};
    let request: NativeBashExecuteRequestV1 = serde_json::from_value(
        value
            .get("request")
            .cloned()
            .ok_or("native_bash_client_request_invalid")?,
    )
    .map_err(|_| "native_bash_client_request_invalid")?;
    let request_sha256 = crate::package_authority_op::request_digest_with_limit(
        &request,
        guard_contracts::NATIVE_BASH_LAUNCH_MAX_REQUEST_BYTES,
    )
    .map_err(|_| "native_bash_client_request_invalid")?;
    crate::encode_response(&NativeBashExecuteResultV1 {
        schema: guard_contracts::NATIVE_BASH_EXECUTE_RESULT_SCHEMA.into(),
        request_id: request.request_id,
        request_sha256,
        status: "error".into(),
        code: "native_bash_host_owner_unavailable".into(),
        grant_claimed: false,
        dispatch_acknowledged: false,
        replayed: false,
        operation: None,
        review_lineage: None,
        payload: None,
    })
}

fn wait_for_owner(
    alive: Arc<AtomicBool>,
    host: Option<HostOwner>,
    request: impl FnOnce() -> Result<Vec<u8>, String> + Send + 'static,
) -> Result<Vec<u8>, String> {
    if !alive.load(Ordering::Acquire) || host.as_ref().is_some_and(|host| !host.is_alive()) {
        return Err("native_bash_client_parent_lost".into());
    }
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("guard-bash-owned-client".into())
        .spawn(move || {
            let _ = sender.send(request());
        })
        .map_err(|_| "native_bash_client_unavailable")?;
    loop {
        if !alive.load(Ordering::Acquire) || host.as_ref().is_some_and(|host| !host.is_alive()) {
            // runtime_cli returns immediately; main exits this dedicated
            // process, closing the worker's socket even during a blocking RPC.
            return Err("native_bash_client_parent_lost".into());
        }
        match receiver.recv_timeout(Duration::from_millis(2)) {
            Ok(result) => return result,
            Err(mpsc::RecvTimeoutError::Timeout) => (),
            Err(_) => return Err("native_bash_client_unavailable".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dead_owner_never_starts_a_request() {
        let result = wait_for_owner(Arc::new(AtomicBool::new(false)), None, || {
            panic!("must not start")
        });
        assert_eq!(result.unwrap_err(), "native_bash_client_parent_lost");
    }

    #[test]
    fn owner_loss_interrupts_wait_without_reissuing_the_request() {
        let alive = Arc::new(AtomicBool::new(true));
        let trigger = Arc::clone(&alive);
        let (finish, wait) = mpsc::sync_channel(1);
        let result = wait_for_owner(alive, None, move || {
            trigger.store(false, Ordering::Release);
            wait.recv().unwrap();
            Ok(vec![1])
        });
        assert_eq!(result.unwrap_err(), "native_bash_client_parent_lost");
        finish.send(()).unwrap();
    }
}
