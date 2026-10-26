/// `shlex.quote` (:271): safe chars `[A-Za-z0-9@%_+=:,./-]`; single-quote
/// otherwise with `'` → `'"'"'`.
pub fn shlex_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".to_owned();
    }
    if value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "@%_+=:,./-".contains(c))
    {
        return value.to_owned();
    }
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}
