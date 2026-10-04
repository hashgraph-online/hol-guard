#[cfg(target_os = "windows")]
use super::MAX_SECRET_TEXT_BYTES;

#[cfg(target_os = "windows")]
pub(crate) fn read_platform_secret(account: &str) -> Result<Option<String>, String> {
    super::windows_secure_storage::read_direct(account, MAX_SECRET_TEXT_BYTES)
}

#[cfg(target_os = "windows")]
pub(crate) fn write_platform_secret(account: &str, value: &str) -> Result<(), String> {
    super::windows_secure_storage::write_direct(account, value, MAX_SECRET_TEXT_BYTES)
}

#[cfg(all(not(test), target_os = "windows"))]
pub(crate) fn read_platform_secret_for_state(
    state_base: &std::path::Path,
    account: &str,
    max_bytes: usize,
) -> Result<Option<String>, String> {
    super::windows_secure_storage::read(state_base, account, max_bytes)
}

#[cfg(target_os = "windows")]
pub(crate) fn write_platform_secret_for_state(
    state_base: &std::path::Path,
    account: &str,
    value: &str,
    max_bytes: usize,
) -> Result<(), String> {
    super::windows_secure_storage::write(state_base, account, value, max_bytes)
}

#[cfg(all(not(test), any(target_os = "macos", target_os = "linux")))]
pub(crate) fn read_platform_secret_for_state(
    _state_base: &std::path::Path,
    account: &str,
    max_bytes: usize,
) -> Result<Option<String>, String> {
    super::read_platform_secret_with_limit(account, max_bytes)
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) fn write_platform_secret_for_state(
    _state_base: &std::path::Path,
    account: &str,
    value: &str,
    max_bytes: usize,
) -> Result<(), String> {
    super::write_platform_secret_with_limit(account, value, max_bytes)
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub(crate) fn read_platform_secret(account: &str) -> Result<Option<String>, String> {
    super::read_platform_secret_with_limit(account, 0)
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub(crate) fn write_platform_secret(account: &str, value: &str) -> Result<(), String> {
    super::write_platform_secret_with_limit(account, value, 0)
}

#[cfg(all(
    not(test),
    not(any(target_os = "macos", target_os = "linux", target_os = "windows"))
))]
pub(crate) fn read_platform_secret_for_state(
    _state_base: &std::path::Path,
    account: &str,
    max_bytes: usize,
) -> Result<Option<String>, String> {
    super::read_platform_secret_with_limit(account, max_bytes)
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub(crate) fn write_platform_secret_for_state(
    _state_base: &std::path::Path,
    account: &str,
    value: &str,
    max_bytes: usize,
) -> Result<(), String> {
    super::write_platform_secret_with_limit(account, value, max_bytes)
}
