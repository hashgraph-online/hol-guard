#![forbid(unsafe_code)]

use guard_contracts::{
    NativeHookRequestV1, RuntimeCapabilitiesV1, MAX_NATIVE_REQUEST_BYTES, MAX_NATIVE_RESPONSE_BYTES,
    NATIVE_PROTOCOL_VERSION,
};
use guard_hook_core::review_post_tool;
use std::env;
use std::io::{self, Read, Write};

const BUILD_SHA: &str = match option_env!("HOL_GUARD_BUILD_SHA") {
    Some(value) => value,
    None => "unknown",
};
const PACKAGE_VERSION: &str = match option_env!("HOL_GUARD_PACKAGE_VERSION") {
    Some(value) => value,
    None => env!("CARGO_PKG_VERSION"),
};

fn capabilities() -> RuntimeCapabilitiesV1 {
    RuntimeCapabilitiesV1 {
        protocol_version: NATIVE_PROTOCOL_VERSION,
        runtime_version: PACKAGE_VERSION.to_owned(),
        rule_digest: guard_rules::rule_digest(),
        build_sha: BUILD_SHA.to_owned(),
        target: format!("{}-{}", env::consts::ARCH, env::consts::OS),
        features: vec![
            "post-tool-inline-v1".into(),
            "post-tool-source-read-v1".into(),
            "oneshot-v1".into(),
            "framed-serve-v1".into(),
        ],
    }
}

fn read_stdin_bounded() -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    io::stdin()
        .take(MAX_NATIVE_REQUEST_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "native_request_read_failed".to_owned())?;
    if bytes.len() > MAX_NATIVE_REQUEST_BYTES {
        return Err("native_request_too_large".into());
    }
    Ok(bytes)
}

fn evaluate_bytes(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let request: NativeHookRequestV1 =
        serde_json::from_slice(bytes).map_err(|_| "native_request_invalid_json".to_owned())?;
    let response = review_post_tool(&request);
    let encoded = serde_json::to_vec(&response).map_err(|_| "native_response_encode_failed".to_owned())?;
    if encoded.len() > MAX_NATIVE_RESPONSE_BYTES {
        return Err("native_response_too_large".into());
    }
    Ok(encoded)
}

fn write_json<T: serde::Serialize>(value: &T) -> Result<(), String> {
    serde_json::to_writer(io::stdout().lock(), value)
        .map_err(|_| "native_response_encode_failed".to_owned())?;
    println!();
    Ok(())
}

#[cfg(unix)]
fn serve(socket_path: &str) -> Result<(), String> {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::Path;

    fn handle(mut stream: UnixStream) -> Result<(), String> {
        let mut header = [0u8; 4];
        stream
            .read_exact(&mut header)
            .map_err(|_| "native_frame_read_failed".to_owned())?;
        let length = u32::from_be_bytes(header) as usize;
        if length > MAX_NATIVE_REQUEST_BYTES {
            return Err("native_request_too_large".into());
        }
        let mut request = vec![0u8; length];
        stream
            .read_exact(&mut request)
            .map_err(|_| "native_frame_read_failed".to_owned())?;
        let response = evaluate_bytes(&request)?;
        stream
            .write_all(&(response.len() as u32).to_be_bytes())
            .map_err(|_| "native_frame_write_failed".to_owned())?;
        stream
            .write_all(&response)
            .map_err(|_| "native_frame_write_failed".to_owned())?;
        Ok(())
    }

    let path = Path::new(socket_path);
    if path.exists() {
        let metadata = fs::symlink_metadata(path).map_err(|_| "native_socket_stat_failed".to_owned())?;
        if metadata.file_type().is_symlink() {
            return Err("native_socket_symlink_rejected".into());
        }
        fs::remove_file(path).map_err(|_| "native_socket_cleanup_failed".to_owned())?;
    }
    let listener = UnixListener::bind(path).map_err(|_| "native_socket_bind_failed".to_owned())?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|_| "native_socket_permissions_failed".to_owned())?;
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let _ = handle(stream);
            }
            Err(_) => return Err("native_socket_accept_failed".into()),
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn serve(_socket_path: &str) -> Result<(), String> {
    Err("native_named_pipe_not_available".into())
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.as_slice() {
        [command] if command == "capabilities" => write_json(&capabilities()),
        [command, flag] if command == "capabilities" && flag == "--json" => write_json(&capabilities()),
        [command] if command == "self-test" => {
            write_json(&serde_json::json!({"ok": true, "capabilities": capabilities()}))
        }
        [command, flag] if command == "self-test" && flag == "--json" => {
            write_json(&serde_json::json!({"ok": true, "capabilities": capabilities()}))
        }
        [command, flag] if command == "hook" && flag == "--stdin" => {
            let bytes = read_stdin_bounded()?;
            let response = evaluate_bytes(&bytes)?;
            io::stdout()
                .write_all(&response)
                .map_err(|_| "native_response_write_failed".to_owned())?;
            io::stdout()
                .write_all(b"\n")
                .map_err(|_| "native_response_write_failed".to_owned())?;
            Ok(())
        }
        [command, flag, path] if command == "serve" && flag == "--socket" => serve(path),
        _ => Err(
            "usage: hol-guard-runtime capabilities --json | self-test --json | hook --stdin | serve --socket PATH"
                .into(),
        ),
    }
}

fn main() {
    if let Err(code) = run() {
        eprintln!("{code}");
        std::process::exit(2);
    }
}
