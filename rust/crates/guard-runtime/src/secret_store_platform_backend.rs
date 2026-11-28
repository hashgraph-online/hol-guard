#[cfg(target_os = "macos")]
pub(crate) fn read_platform_secret_with_service(
    service: &str,
    account: &str,
    max_bytes: usize,
) -> Result<Option<String>, String> {
    use security_framework::passwords::generic_password;

    let value = match generic_password(
        security_framework::passwords::PasswordOptions::new_generic_password(service, account),
    ) {
        Ok(value) => value,
        Err(error) if error.code() == -25300 => return Ok(None),
        Err(error) => return Err(map_keychain_error(error)),
    };
    let value =
        String::from_utf8(value).map_err(|_| "native_approval_secure_state_invalid".to_owned())?;
    if value.len() > max_bytes {
        return Err("native_approval_secure_state_invalid".to_owned());
    }
    Ok(Some(value))
}

#[cfg(target_os = "macos")]
pub(crate) fn read_platform_secret_with_service_trim(
    service: &str,
    account: &str,
    max_bytes: usize,
) -> Result<Option<String>, String> {
    read_platform_secret_with_service(service, account, max_bytes)
        .map(|value| value.map(|value| value.trim().to_owned()))
}

#[cfg(target_os = "macos")]
pub(crate) fn write_platform_secret_with_service(
    service: &str,
    account: &str,
    value: &str,
    max_bytes: usize,
) -> Result<(), String> {
    use security_framework::passwords::set_generic_password;

    if value.len() > max_bytes {
        return Err("native_approval_secure_state_invalid".to_owned());
    }
    set_generic_password(service, account, value.as_bytes()).map_err(map_keychain_error)
}

#[cfg(target_os = "macos")]
pub(crate) fn delete_platform_secret_with_service(
    service: &str,
    account: &str,
) -> Result<(), String> {
    use security_framework::passwords::delete_generic_password;

    match delete_generic_password(service, account) {
        Ok(()) => Ok(()),
        Err(error) if error.code() == -25300 => Ok(()),
        Err(error) => Err(map_keychain_error(error)),
    }
}

#[cfg(target_os = "macos")]
fn map_keychain_error(_error: security_framework::base::Error) -> String {
    "native_approval_secure_state_unavailable".to_owned()
}

#[cfg(target_os = "linux")]
pub(crate) fn read_platform_secret_with_service(
    service: &str,
    account: &str,
    max_bytes: usize,
) -> Result<Option<String>, String> {
    let output = super::bounded_transport::run_helper(
        std::path::Path::new("/usr/bin/secret-tool"),
        &["lookup", "service", service, "account", account],
        None,
        max_bytes.saturating_add(1),
        super::bounded_transport::DEFAULT_TIMEOUT,
    )?;
    super::bounded_transport::classify_lookup_preserving_value(output, max_bytes)
}

#[cfg(target_os = "linux")]
pub(crate) fn read_platform_secret_with_service_trim(
    service: &str,
    account: &str,
    max_bytes: usize,
) -> Result<Option<String>, String> {
    let output = super::bounded_transport::run_helper(
        std::path::Path::new("/usr/bin/secret-tool"),
        &["lookup", "service", service, "account", account],
        None,
        max_bytes.saturating_add(1),
        super::bounded_transport::DEFAULT_TIMEOUT,
    )?;
    super::bounded_transport::classify_lookup(output, max_bytes)
}

#[cfg(target_os = "linux")]
pub(crate) fn write_platform_secret_with_service(
    service: &str,
    account: &str,
    value: &str,
    max_bytes: usize,
) -> Result<(), String> {
    if value.len() > max_bytes {
        return Err(super::SECURE_STATE_INVALID.to_owned());
    }
    let output = super::bounded_transport::run_helper(
        std::path::Path::new("/usr/bin/secret-tool"),
        &[
            "store",
            "--label",
            "HOL Guard native secret",
            "service",
            service,
            "account",
            account,
        ],
        Some(value.as_bytes()),
        max_bytes,
        super::bounded_transport::DEFAULT_TIMEOUT,
    )?;
    if output.status.success() && output.stdout.is_empty() && !output.stderr_seen {
        Ok(())
    } else {
        Err(super::SECURE_STATE_UNAVAILABLE.to_owned())
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn delete_platform_secret_with_service(
    service: &str,
    account: &str,
) -> Result<(), String> {
    let output = super::bounded_transport::run_helper(
        std::path::Path::new("/usr/bin/secret-tool"),
        &["clear", "service", service, "account", account],
        None,
        1,
        super::bounded_transport::DEFAULT_TIMEOUT,
    )?;
    if (output.status.success() || output.status.code() == Some(1))
        && output.stdout.is_empty()
        && !output.stderr_seen
    {
        Ok(())
    } else {
        Err(super::SECURE_STATE_UNAVAILABLE.to_owned())
    }
}
