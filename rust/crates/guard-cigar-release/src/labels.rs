//! Native producer labels are exact bounded strings; they never order or
//! execute a build.
pub(crate) fn producer_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._+!-".contains(&byte))
        && !value.contains("..")
}
