#[cfg(target_os = "windows")]
use super::MAX_SECRET_TEXT_BYTES;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use super::{MAX_SECRET_TEXT_BYTES, SERVICE_NAME};

#[cfg(target_os = "windows")]
#[path = "windows_approval_secure_storage.rs"]
mod windows_secure_storage;

#[path = "approval_enrollment_platform_dispatch.rs"]
mod dispatch;
#[cfg(not(test))]
pub(super) use dispatch::read_platform_secret_for_state;
pub(super) use dispatch::write_platform_secret_for_state;
#[cfg(target_os = "windows")]
pub(super) use dispatch::{read_platform_secret, write_platform_secret};
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub(super) use dispatch::{read_platform_secret, write_platform_secret};

#[cfg(any(target_os = "linux", all(test, unix)))]
#[path = "approval_enrollment_platform_transport.rs"]
mod bounded_transport;

#[cfg(any(target_os = "linux", all(test, unix)))]
const SECURE_STATE_INVALID: &str = "native_approval_secure_state_invalid";
#[cfg(any(target_os = "linux", all(test, unix)))]
const SECURE_STATE_UNAVAILABLE: &str = "native_approval_secure_state_unavailable";

#[cfg(target_os = "macos")]
fn require_noninteractive_keychain() -> Result<(), String> {
    use security_framework::os::macos::keychain::{KeychainUserInteractionLock, SecKeychain};
    use std::sync::LazyLock;
    // Retain the process-wide guard: dropping per-call guards would re-enable UI
    // while another native worker is still using Keychain.
    static UI: LazyLock<Result<KeychainUserInteractionLock, ()>> =
        LazyLock::new(|| SecKeychain::disable_user_interaction().map_err(|_| ()));
    UI.as_ref()
        .map(|_| ())
        .map_err(|_| "native_approval_secure_state_unavailable".to_owned())
}

#[cfg(target_os = "macos")]
pub(super) fn read_platform_secret(account: &str) -> Result<Option<String>, String> {
    read_platform_secret_with_limit(account, MAX_SECRET_TEXT_BYTES)
}

#[cfg(target_os = "macos")]
pub(super) fn read_platform_secret_with_limit(
    account: &str,
    max_bytes: usize,
) -> Result<Option<String>, String> {
    use security_framework::passwords::generic_password;

    require_noninteractive_keychain()?;
    let value = match generic_password(
        security_framework::passwords::PasswordOptions::new_generic_password(SERVICE_NAME, account),
    ) {
        Ok(value) => value,
        // Security.framework's stable errSecItemNotFound value. Do not turn
        // any other keychain failure into an apparent unenrolled state.
        Err(error) if error.code() == -25300 => return Ok(None),
        Err(error) => return Err(map_keychain_error(error)),
    };
    let value =
        String::from_utf8(value).map_err(|_| "native_approval_secure_state_invalid".to_owned())?;
    if value.len() > max_bytes {
        return Err("native_approval_secure_state_invalid".to_owned());
    }
    Ok(Some(value.trim().to_owned()))
}

#[cfg(target_os = "macos")]
pub(super) fn write_platform_secret(account: &str, value: &str) -> Result<(), String> {
    write_platform_secret_with_limit(account, value, MAX_SECRET_TEXT_BYTES)
}

#[cfg(target_os = "macos")]
pub(super) fn write_platform_secret_with_limit(
    account: &str,
    value: &str,
    max_bytes: usize,
) -> Result<(), String> {
    use security_framework::passwords::set_generic_password;

    require_noninteractive_keychain()?;
    if value.len() > max_bytes {
        return Err("native_approval_secure_state_invalid".to_owned());
    }
    set_generic_password(SERVICE_NAME, account, value.as_bytes()).map_err(map_keychain_error)
}

#[cfg(target_os = "macos")]
fn map_keychain_error(_error: security_framework::base::Error) -> String {
    "native_approval_secure_state_unavailable".to_owned()
}

#[cfg(target_os = "linux")]
pub(super) fn read_platform_secret(account: &str) -> Result<Option<String>, String> {
    read_platform_secret_with_limit(account, MAX_SECRET_TEXT_BYTES)
}

#[cfg(all(target_os = "linux", test))]
fn test_secret_dir() -> Option<std::path::PathBuf> {
    // Unit tests can opt into a file store. Release builds never consult this variable.
    std::env::var_os("HOL_GUARD_SECURE_STATE_DIR")
        .map(std::path::PathBuf::from)
        .filter(|path| path.is_dir())
}

#[cfg(all(target_os = "linux", not(test)))]
fn test_secret_dir() -> Option<std::path::PathBuf> {
    None
}

#[cfg(target_os = "linux")]
fn test_secret_path(account: &str) -> Option<std::path::PathBuf> {
    let dir = test_secret_dir()?;
    let name = account.replace(['/', '\\'], "_");
    Some(dir.join(format!("{name}.secret")))
}

#[cfg(target_os = "linux")]
pub(super) fn read_platform_secret_with_limit(
    account: &str,
    max_bytes: usize,
) -> Result<Option<String>, String> {
    if let Some(path) = test_secret_path(account) {
        return match std::fs::read_to_string(&path) {
            Ok(raw) => {
                if raw.len() > max_bytes {
                    return Err(SECURE_STATE_INVALID.to_owned());
                }
                Ok(Some(raw.trim().to_owned()))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(SECURE_STATE_UNAVAILABLE.to_owned()),
        };
    }
    let output = bounded_transport::run_helper(
        std::path::Path::new("/usr/bin/secret-tool"),
        &["lookup", "service", SERVICE_NAME, "account", account],
        None,
        max_bytes.saturating_add(1),
        bounded_transport::DEFAULT_TIMEOUT,
    )?;
    bounded_transport::classify_lookup(output, max_bytes)
}

#[cfg(target_os = "linux")]
pub(super) fn write_platform_secret(account: &str, value: &str) -> Result<(), String> {
    write_platform_secret_with_limit(account, value, MAX_SECRET_TEXT_BYTES)
}

#[cfg(target_os = "linux")]
pub(super) fn write_platform_secret_with_limit(
    account: &str,
    value: &str,
    max_bytes: usize,
) -> Result<(), String> {
    if value.len() > max_bytes {
        return Err(SECURE_STATE_INVALID.to_owned());
    }
    if let Some(path) = test_secret_path(account) {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        return std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .and_then(|mut file| file.write_all(value.as_bytes()))
            .map_err(|_| SECURE_STATE_UNAVAILABLE.to_owned());
    }
    let output = bounded_transport::run_helper(
        std::path::Path::new("/usr/bin/secret-tool"),
        &[
            "store",
            "--label",
            "HOL Guard native approval enrollment",
            "service",
            SERVICE_NAME,
            "account",
            account,
        ],
        Some(value.as_bytes()),
        max_bytes,
        bounded_transport::DEFAULT_TIMEOUT,
    )?;
    if output.status.success() && output.stdout.is_empty() && !output.stderr_seen {
        Ok(())
    } else {
        Err(SECURE_STATE_UNAVAILABLE.to_owned())
    }
}

#[cfg(all(test, unix))]
#[path = "approval_enrollment_platform_tests.rs"]
mod tests;

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub(super) fn read_platform_secret_with_limit(
    _account: &str,
    _max_bytes: usize,
) -> Result<Option<String>, String> {
    // No desktop secret store is wired on this platform yet. Treat that as an
    // empty store so reads can fail open to "no enrollment", matching Linux
    // when the helper binary is absent. Writes below still fail closed.
    Ok(None)
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub(super) fn write_platform_secret_with_limit(
    _account: &str,
    _value: &str,
    _max_bytes: usize,
) -> Result<(), String> {
    Err("native_approval_secure_state_unavailable".to_owned())
}
