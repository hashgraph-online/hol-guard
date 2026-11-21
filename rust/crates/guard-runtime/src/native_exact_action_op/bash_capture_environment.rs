//! Closed startup environment for native-owned Bash capture.

use super::{BTreeMap, NativeBashCaptureV1, Result};

use guard_contracts::NATIVE_BASH_SELECTED_ENVIRONMENT_NAMES as SELECTED;

pub(super) fn reject_function(names: &[String], command: &str) -> Result<()> {
    let encoded = format!("BASH_FUNC_{command}%%");
    let apple = format!("__BASH_FUNC<{command}>()");
    if names
        .iter()
        .any(|name| name == command || name == &encoded || name == &apple)
    {
        return Err("bash_command_environment_value_withheld");
    }
    Ok(())
}

pub(super) fn capture(request: &NativeBashCaptureV1) -> Result<BTreeMap<String, String>> {
    let stamp = &request.execution_environment;
    if !stamp.has_valid_shape() || stamp.home.as_deref() != Some(request.home_dir.as_str()) {
        return Err("bash_host_environment_unavailable");
    }
    for name in &stamp.environment_names {
        if matches!(
            name.as_str(),
            "BASH_ENV"
                | "ENV"
                | "SHELLOPTS"
                | "BASHOPTS"
                | "POSIXLY_CORRECT"
                | "GLOBIGNORE"
                | "BASH_ARGV0"
                | "BASH_COMPAT"
                | "BASH_XTRACEFD"
                | "LOCPATH"
                | "PATH_LOCALE"
                | "GCONV_PATH"
                | "NLSPATH"
        ) || name.starts_with("LD_")
            || name.starts_with("DYLD_")
            || name.starts_with("BASH_FUNC_")
            || name.starts_with("__BASH_FUNC")
        {
            return Err("bash_startup_environment_unproven");
        }
        if SELECTED.contains(&name.as_str()) && !request.environment.contains_key(name) {
            return Err("bash_host_environment_value_withheld");
        }
    }
    if request.environment.iter().any(|(name, value)| {
        !SELECTED.contains(&name.as_str())
            || value.len() > 32 * 1024
            || value.contains('\0')
            || !stamp.environment_names.contains(name)
    }) {
        return Err("bash_host_environment_invalid");
    }
    let mut environment = request.environment.clone();
    environment.insert("HOME".into(), request.home_dir.clone());
    environment.insert("PATH".into(), stamp.path.clone());
    if environment
        .values()
        .any(|value| value.trim_start().starts_with("()"))
    {
        return Err("bash_startup_environment_unproven");
    }
    if request.environment.iter().any(|(name, value)| {
        (name == "LANG" || name.starts_with("LC_"))
            && !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.@+-".contains(&byte))
    }) {
        return Err("bash_locale_configuration_unproven");
    }
    Ok(environment)
}

#[cfg(test)]
mod tests {
    #[test]
    fn startup_inputs_and_locale_paths_are_never_silently_discarded() {
        let (_root, mut request) = super::super::tests::fixture();
        for name in [
            "BASH_ARGV0",
            "BASH_COMPAT",
            "BASH_XTRACEFD",
            "LOCPATH",
            "PATH_LOCALE",
            "GCONV_PATH",
            "NLSPATH",
        ] {
            request
                .execution_environment
                .environment_names
                .push(name.into());
            assert_eq!(
                super::capture(&request),
                Err("bash_startup_environment_unproven")
            );
            request.execution_environment.environment_names.pop();
        }
        request
            .execution_environment
            .environment_names
            .push("LC_ALL".into());
        request
            .environment
            .insert("LC_ALL".into(), "/unobserved/locale".into());
        assert_eq!(
            super::capture(&request),
            Err("bash_locale_configuration_unproven")
        );
    }
}
