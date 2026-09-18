use serde_json::Value;
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[path = "claude_launcher_pilot_auth.rs"]
mod auth;
#[path = "claude_launcher_pilot_files.rs"]
mod files;
#[path = "claude_launcher_pilot_http.rs"]
mod http;
#[path = "claude_launcher_pilot_identity.rs"]
mod identity;
#[path = "claude_launcher_pilot_stdin.rs"]
mod stdin;

type Result<T> = std::result::Result<T, Failure>;

#[derive(Debug)]
pub(super) struct Failure {
    value: Value,
}

impl Failure {
    fn identity(detail: &str) -> Self {
        Self {
            value: serde_json::json!({"kind": "identity", "detail": detail}),
        }
    }
    fn timeout() -> Self {
        Self {
            value: serde_json::json!({"kind": "timeout", "detail": "Guard daemon hook request exceeded its absolute deadline"}),
        }
    }
    fn http(status: u16, detail: &str) -> Self {
        Self {
            value: serde_json::json!({"kind": "http", "status": status, "detail": detail.trim()}),
        }
    }
    fn io(error: std::io::Error) -> Self {
        if matches!(
            error.kind(),
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
        ) {
            return Self::timeout();
        }
        Self {
            value: serde_json::json!({"kind": "io", "errno": error.raw_os_error().unwrap_or(5)}),
        }
    }
}

fn monotonic_ns() -> Result<u64> {
    let time = nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC)
        .map_err(|_| Failure::identity("claude_pilot_monotonic_clock_unavailable"))?;
    let nanos = i128::from(time.tv_sec()) * 1_000_000_000 + i128::from(time.tv_nsec());
    u64::try_from(nanos).map_err(|_| Failure::identity("claude_pilot_monotonic_clock_invalid"))
}

fn encode_handoff(raw: &[u8], deadline_ns: u64, mut value: Value) -> Result<Vec<u8>> {
    use crate::approval::approval_v4_crypto::encode_base64url;
    value["body_base64"] = Value::String(encode_base64url(raw));
    value["deadline_monotonic_ns"] = Value::from(deadline_ns);
    let bytes = value.to_string().into_bytes();
    if bytes.len() > 8_000_000 {
        return Err(Failure::identity("claude_pilot_memory_handoff_limit"));
    }
    Ok(bytes)
}

fn handoff(
    registration: &identity::Registration,
    event: &str,
    raw: &[u8],
    deadline_ns: u64,
    value: Value,
) -> Result<()> {
    // Anonymous memory, not a temporary on-disk request or argv payload. exec
    // preserves the harness-owned PID/process group and its outer containment.
    use nix::fcntl::{fcntl, FcntlArg, SealFlag};
    use nix::sys::memfd::{memfd_create, MFdFlags};
    let encoded = encode_handoff(raw, deadline_ns, value)?;
    let descriptor = memfd_create(
        c"hol-guard-claude-pilot-handoff",
        MFdFlags::MFD_CLOEXEC | MFdFlags::MFD_ALLOW_SEALING,
    )
    .map_err(|_| Failure::identity("claude_pilot_memory_handoff_unavailable"))?;
    let mut memory = std::fs::File::from(descriptor);
    memory.write_all(&encoded).map_err(Failure::io)?;
    memory.seek(SeekFrom::Start(0)).map_err(Failure::io)?;
    fcntl(
        &memory,
        FcntlArg::F_ADD_SEALS(
            SealFlag::F_SEAL_SHRINK
                | SealFlag::F_SEAL_GROW
                | SealFlag::F_SEAL_WRITE
                | SealFlag::F_SEAL_SEAL,
        ),
    )
    .map_err(|_| Failure::identity("claude_pilot_memory_handoff_seal_failed"))?;
    let files = &registration.record["files"];
    // Revalidate at the exec boundary, including the invocation symlink.
    for file in files
        .as_object()
        .ok_or_else(|| Failure::identity("claude_pilot_files_missing"))?
        .values()
    {
        files::verify_file(file)?;
    }
    let interpreter = files["interpreter"]["path"]
        .as_str()
        .ok_or_else(|| Failure::identity("claude_pilot_interpreter_missing"))?;
    let helper = files["helper"]["path"]
        .as_str()
        .ok_or_else(|| Failure::identity("claude_pilot_helper_missing"))?;
    let error = Command::new(interpreter)
        .args(["-I", helper])
        .arg(&registration.path)
        .arg(event)
        .stdin(Stdio::from(memory))
        .exec();
    Err(Failure::io(error))
}

pub(super) fn run(path: &Path, event: &str) -> Result<()> {
    let began = Instant::now();
    let deadline_ns = monotonic_ns()?.saturating_add(8_000_000_000);
    let registration = identity::load_registration(path, event)?;
    let raw = stdin::read(std::io::stdin().lock()).map_err(Failure::io)?;
    let before_send =
        |value: &Value| value.get("kind").and_then(Value::as_str) == Some("before_send");
    let mut fallback = serde_json::json!({"kind": "before_send"});
    let data = std::str::from_utf8(&raw).ok();
    let parsed = data.and_then(|text| serde_json::from_str::<Value>(text).ok());
    let supported = data.is_some_and(|text| {
        text.len() <= 1_000_000 && !text.chars().any(|ch| matches!(ch, '\u{1c}'..='\u{1f}'))
    }) && parsed.as_ref().and_then(Value::as_object).is_some()
        && parsed
            .as_ref()
            .and_then(|value| value.get("hook_event_name").or_else(|| value.get("event")))
            .and_then(Value::as_str)
            == Some(event);
    // Stalled stdin is bounded by the existing outer harness supervisor, as
    // in the frozen Python bridge. Never send after its operation budget elapsed.
    if supported && began.elapsed() < Duration::from_secs(8) {
        let config = &registration.record["bridge"];
        let state_path = config["state_path"]
            .as_str()
            .ok_or_else(|| Failure::identity("claude_pilot_state_path_missing"))?;
        let query = config["query"]
            .as_str()
            .ok_or_else(|| Failure::identity("claude_pilot_query_missing"))?;
        // Initial state unavailability retains the exact existing recovery
        // path. Once native sends anything, only explicit completion is handed off.
        if let Ok(state) = auth::load_state(Path::new(state_path)) {
            if !auth::string(&state.value, "host")?.eq_ignore_ascii_case("localhost") {
                let total_deadline = began + Duration::from_secs(8);
                let request_deadline =
                    (Instant::now() + Duration::from_secs(2)).min(total_deadline);
                match http::request(
                    &state,
                    Path::new(state_path),
                    query,
                    data.unwrap_or_default().trim(),
                    event,
                    request_deadline,
                ) {
                    Ok(response) => {
                        if serde_json::from_str::<Value>(response.trim())
                            .is_ok_and(|value| value.is_object())
                        {
                            std::io::stdout()
                                .write_all(response.trim().as_bytes())
                                .map_err(Failure::io)?;
                            return Ok(());
                        }
                        fallback = serde_json::json!({"kind": "response", "response": response});
                    }
                    Err(failure) => fallback = failure.value,
                }
            }
        }
    }
    if before_send(&fallback) {
        fallback["attempted_hook_post"] = Value::Bool(false);
    }
    if registration.record["require_native_transport"] == Value::Bool(true) {
        return Err(Failure::identity("claude_pilot_native_transport_required"));
    }
    handoff(&registration, event, &raw, deadline_ns, fallback)
}

#[cfg(test)]
#[path = "claude_launcher_pilot_tests.rs"]
mod tests;
