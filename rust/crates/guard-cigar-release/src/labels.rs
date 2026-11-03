//! SDK versions are canonical PEP 440. Native producer labels and release tags
//! are exact bounded strings; neither is used to order or execute a build.
pub(crate) fn producer_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._+!-".contains(&byte))
        && !value.contains("..")
}
pub(crate) fn wheel_filename(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 240
        && value.ends_with(".whl")
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-+!".contains(&byte))
        && !value.contains("..")
}
