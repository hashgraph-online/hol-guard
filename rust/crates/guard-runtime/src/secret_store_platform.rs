//! First-party user secret storage backed by the operating-system store.

use zeroize::Zeroizing;

use crate::policy_store::approval_enrollment::{
    delete_native_secret, read_native_secret, write_native_secret,
};

pub(crate) const USER_SECRET_NAMESPACE: &str = "org.hashgraphonline.hol-guard.user-secrets.v1";
pub(crate) const MAX_SECRET_BYTES: usize = 16 * 1024;

#[allow(dead_code)]
pub(crate) struct NativeSecret(Zeroizing<String>);

#[allow(dead_code)]
impl NativeSecret {
    pub(crate) fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    pub(crate) fn expose(&self) -> &str {
        self.0.as_str()
    }

    pub(crate) fn into_inner(self) -> Zeroizing<String> {
        self.0
    }
}

impl std::fmt::Debug for NativeSecret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("NativeSecret(REDACTED)")
    }
}

pub(crate) fn read(account: &str) -> Result<Option<NativeSecret>, String> {
    validate_account(account)?;
    read_native_secret(USER_SECRET_NAMESPACE, account, MAX_SECRET_BYTES)
        .map(|value| value.map(NativeSecret::new))
}

pub(crate) fn write(account: &str, value: &str) -> Result<(), String> {
    validate_account(account)?;
    if value.is_empty() || value.len() > MAX_SECRET_BYTES || value.chars().any(char::is_control) {
        return Err("native_secret_store_invalid".to_owned());
    }
    write_native_secret(USER_SECRET_NAMESPACE, account, value, MAX_SECRET_BYTES)
}

pub(crate) fn delete(account: &str) -> Result<(), String> {
    validate_account(account)?;
    delete_native_secret(USER_SECRET_NAMESPACE, account)
}

fn validate_account(account: &str) -> Result<(), String> {
    if account.is_empty()
        || account.len() > 128
        || account
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')))
    {
        return Err("native_secret_store_invalid".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_debug_output_is_redacted() {
        let value = NativeSecret::new("fixture-value-7".to_owned());
        assert_eq!(format!("{value:?}"), "NativeSecret(REDACTED)");
        assert!(!format!("{value:?}").contains("fixture-value-7"));
    }

    #[test]
    fn account_validation_is_bounded() {
        assert!(validate_account("ref.digest").is_ok());
        assert!(validate_account("").is_err());
        assert!(validate_account("a/b").is_err());
        assert!(validate_account(&"a".repeat(129)).is_err());
    }
}
