//! Integrity classification of installed shims (`package_shim_frozen.py`).

use std::collections::BTreeSet;

use super::generate::{is_transient_appimage_path, needs_shell_wrapper, package_shim_interpreter};
use super::values::{parse_py_str_list, py_repr_list, py_splitlines, py_strip, sha256_hex};
use super::{ShimFacts, ShimResult};
use crate::codex_output_py::shlex_split;
use crate::command_launcher_floors::shlex_quote;

const SIDECAR_ATTESTATION_MARK: &[u8] = b"\n# hol-guard-sidecar\n";

/// `frozen_package_shim_python_path`.
pub(crate) fn sidecar_path(facts: &ShimFacts, shim_dir: &str, command: &str) -> String {
    facts.join(shim_dir, &format!(".{command}.py"))
}

/// `package_shim_shell_wrapper`.
pub(crate) fn shell_wrapper(facts: &ShimFacts, python_path: &str) -> String {
    format!(
        "#!/bin/sh\nexec {} {} \"$@\"\n",
        shlex_quote(&package_shim_interpreter(facts)),
        shlex_quote(python_path)
    )
}

fn wrapper_argv(wrapper: &[u8]) -> Option<Vec<String>> {
    let text = std::str::from_utf8(wrapper).ok()?;
    for line in py_splitlines(text) {
        let stripped = py_strip(&line);
        if !stripped.starts_with("exec ") {
            continue;
        }
        let tokens = shlex_split(stripped)?;
        if tokens.len() >= 2 && tokens[0] == "exec" {
            return Some(tokens);
        }
    }
    None
}

/// `package_shim_wrapper_interpreter`.
pub(crate) fn wrapper_interpreter(facts: &ShimFacts, wrapper: &[u8]) -> Option<String> {
    if let Some(tokens) = wrapper_argv(wrapper) {
        return Some(facts.norm(&tokens[1]));
    }
    let text = std::str::from_utf8(wrapper).ok()?;
    for line in py_splitlines(text) {
        let stripped = py_strip(&line);
        if stripped.starts_with("#!") && !stripped.starts_with("#!/bin/sh") {
            let interpreter = py_strip(&stripped[2..]);
            if !interpreter.is_empty() {
                return Some(facts.norm(interpreter));
            }
        }
    }
    None
}

fn path_aliases(facts: &ShimFacts, path: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    names.insert(facts.norm(path));
    if let Ok(resolved) = facts.resolve(path) {
        names.insert(resolved);
    }
    names
}

fn trusted_frozen_cli_path(facts: &ShimFacts, path: &str) -> bool {
    if !facts.is_file(path) {
        return false;
    }
    if !facts.windows && !facts.is_executable(path) {
        return false;
    }
    let mut trusted = BTreeSet::new();
    for trusted_path in &facts.trusted_frozen_cli_paths {
        trusted.extend(path_aliases(facts, trusted_path));
    }
    !path_aliases(facts, path).is_disjoint(&trusted)
}

fn interpreter_runnable(facts: &ShimFacts, wrapper: &[u8]) -> ShimResult<bool> {
    let Some(interpreter) = wrapper_interpreter(facts, wrapper) else {
        return Ok(true);
    };
    if trusted_frozen_cli_path(facts, &interpreter) {
        return Ok(true);
    }
    // A normal unfrozen shebang names `facts.executable`. A spaced path uses a
    // shell wrapper, and an AppImage mount is ephemeral; both stay stale.
    // Frozen builds remain limited to the trusted frozen CLI list above.
    if needs_shell_wrapper(facts) || is_transient_appimage_path(facts, &interpreter)? {
        return Ok(false);
    }
    // Like the trusted-CLI check, the interpreter must exist and be runnable now.
    if !facts.is_file(&interpreter) || (!facts.windows && !facts.is_executable(&interpreter)) {
        return Ok(false);
    }
    Ok(!path_aliases(facts, &interpreter).is_disjoint(&path_aliases(facts, &facts.executable)))
}

/// `_package_shim_base_command`: the first `base_command = [...]` line of the
/// generated source. The Python original parsed the whole file with `ast`; the
/// generated shims put the assignment on one top-level line, which is the only
/// shape this has to recognise.
pub(crate) fn base_command(content: &[u8]) -> Option<Vec<String>> {
    let text = std::str::from_utf8(content).ok()?;
    let line = py_splitlines(text)
        .into_iter()
        .find(|line| line.starts_with("base_command = "))?;
    parse_py_str_list(&line["base_command = ".len()..])
}

fn wrapper_matches_generated(installed: &[u8], expected: &[u8]) -> bool {
    let (Some(installed_argv), Some(expected_argv)) =
        (wrapper_argv(installed), wrapper_argv(expected))
    else {
        return false;
    };
    installed_argv[..1] == expected_argv[..1] && installed_argv[2..] == expected_argv[2..]
}

fn base_args_match_generated(installed: &[u8], expected: &[u8]) -> bool {
    match (base_command(installed), base_command(expected)) {
        (Some(installed), Some(expected)) => installed.get(1..) == expected.get(1..),
        _ => false,
    }
}

/// `package_shim_runtime_binding_is_current`: `Some(false)` is reserved for a
/// complete, trusted binding that points at an old launcher.
pub(crate) fn runtime_binding_is_current(
    facts: &ShimFacts,
    shim_dir: &str,
    command: &str,
    installed_wrapper: &[u8],
) -> Option<bool> {
    if !needs_shell_wrapper(facts) {
        return Some(true);
    }
    let sidecar = sidecar_path(facts, shim_dir, command);
    if facts.is_symlink(&sidecar) || !facts.is_file(&sidecar) {
        return None;
    }
    let sidecar_bytes = facts.read_bytes(&sidecar).ok()?;
    let wrapper_binding = wrapper_interpreter(facts, installed_wrapper)?;
    let sidecar_binding = wrapper_interpreter(facts, &sidecar_bytes)?;
    let base = base_command(&sidecar_bytes)?;
    let base_binding = facts.norm(base.first()?);
    let bindings = [wrapper_binding, sidecar_binding, base_binding];
    if !bindings
        .iter()
        .all(|binding| trusted_frozen_cli_path(facts, binding))
    {
        return None;
    }
    let expected = path_aliases(facts, &package_shim_interpreter(facts));
    Some(
        bindings
            .iter()
            .all(|binding| !path_aliases(facts, binding).is_disjoint(&expected)),
    )
}

/// `normalized_package_shim_content`.
pub(crate) fn normalized_content(content: &[u8]) -> String {
    let Ok(text) = std::str::from_utf8(content) else {
        return String::new();
    };
    let mut lines: Vec<String> = Vec::new();
    for line in py_splitlines(text) {
        let normalized = if line.starts_with("#!") {
            "#!<interpreter>".to_owned()
        } else if line.starts_with("exec ") {
            "exec <python> <shim-python> \"$@\"".to_owned()
        } else if line.starts_with("base_command = ") {
            format!("base_command = {}", normalized_base_command_repr(&line))
        } else if line.starts_with("guard_cwd = ") || line.starts_with("guard_cli_cwd = ") {
            "guard_cli_cwd = '<path>'".to_owned()
        } else if line.starts_with("guard_home = ") {
            "guard_home = '<path>'".to_owned()
        } else if line.starts_with("guard_workspace = ") {
            "guard_workspace = <workspace-path>".to_owned()
        } else if line.starts_with("guard_has_explicit_workspace = ") {
            "guard_has_explicit_workspace = <workspace-mode>".to_owned()
        } else if line.starts_with("shim_dir = ") {
            "shim_dir = '<path>'".to_owned()
        } else {
            line
        };
        lines.push(normalized);
    }
    lines.join("\n")
}

fn normalized_base_command_repr(line: &str) -> String {
    let raw_value = py_strip(line.split_once('=').map_or("", |(_, rest)| rest)).to_owned();
    let Some(value) = parse_py_str_list(&raw_value) else {
        return raw_value;
    };
    let mut normalized: Vec<String> = Vec::new();
    let mut skip_path_after: Option<String> = None;
    for (index, item) in value.iter().enumerate() {
        if index == 0 {
            normalized.push("<python>".to_owned());
            continue;
        }
        if value
            .get(index + 1)
            .is_some_and(|next| next == "codex_plugin_scanner.cli")
        {
            normalized.push("<import-root>".to_owned());
            continue;
        }
        if let Some(label) = skip_path_after.take() {
            normalized.push(format!("<{label}>"));
            continue;
        }
        normalized.push(item.clone());
        if matches!(item.as_str(), "--guard-home" | "--home" | "--workspace") {
            skip_path_after = Some(item.trim_start_matches('-').to_owned());
        }
    }
    py_repr_list(&normalized)
}

/// `expected_package_shim_executable_bytes`.
pub(crate) fn expected_executable_bytes(
    facts: &ShimFacts,
    python_source: &str,
    shim_dir: &str,
    command: &str,
) -> Vec<u8> {
    if !needs_shell_wrapper(facts) {
        return python_source.as_bytes().to_vec();
    }
    shell_wrapper(facts, &sidecar_path(facts, shim_dir, command)).into_bytes()
}

/// `expected_package_shim_attestation_bytes`.
pub(crate) fn expected_attestation_bytes(
    facts: &ShimFacts,
    python_source: &str,
    shim_dir: &str,
    command: &str,
) -> Vec<u8> {
    let mut wrapper = expected_executable_bytes(facts, python_source, shim_dir, command);
    if !needs_shell_wrapper(facts) {
        return wrapper;
    }
    wrapper.extend_from_slice(SIDECAR_ATTESTATION_MARK);
    wrapper.extend_from_slice(python_source.as_bytes());
    wrapper
}

/// `installed_package_shim_attestation_bytes`.
pub(crate) fn installed_attestation_bytes(
    facts: &ShimFacts,
    shim_dir: &str,
    command: &str,
    wrapper: &[u8],
) -> ShimResult<Vec<u8>> {
    let mut bytes = wrapper.to_vec();
    if !needs_shell_wrapper(facts) {
        return Ok(bytes);
    }
    bytes.extend_from_slice(SIDECAR_ATTESTATION_MARK);
    let sidecar = sidecar_path(facts, shim_dir, command);
    if facts.is_symlink(&sidecar) || !facts.is_file(&sidecar) {
        return Ok(bytes);
    }
    bytes.extend(
        facts
            .read_bytes(&sidecar)
            .map_err(|error| error.message(&sidecar))?,
    );
    Ok(bytes)
}

fn content_matches_generated(
    facts: &ShimFacts,
    python_source: &str,
    shim_dir: &str,
    command: &str,
    installed_wrapper: &[u8],
) -> ShimResult<bool> {
    let expected = expected_attestation_bytes(facts, python_source, shim_dir, command);
    let current = installed_attestation_bytes(facts, shim_dir, command, installed_wrapper)?;
    if current == expected {
        return Ok(true);
    }
    let expected_wrapper = expected_executable_bytes(facts, python_source, shim_dir, command);
    if !needs_shell_wrapper(facts) {
        return Ok(normalized_content(installed_wrapper) == normalized_content(&expected_wrapper));
    }
    if !wrapper_matches_generated(installed_wrapper, &expected_wrapper) {
        return Ok(false);
    }
    if normalized_content(installed_wrapper) != normalized_content(&expected_wrapper) {
        return Ok(false);
    }
    let sidecar = sidecar_path(facts, shim_dir, command);
    if facts.is_symlink(&sidecar) || !facts.is_file(&sidecar) {
        return Ok(false);
    }
    let installed_sidecar = facts
        .read_bytes(&sidecar)
        .map_err(|error| error.message(&sidecar))?;
    let expected_sidecar = python_source.as_bytes();
    if !base_args_match_generated(&installed_sidecar, expected_sidecar) {
        return Ok(false);
    }
    Ok(normalized_content(&installed_sidecar) == normalized_content(expected_sidecar))
}

fn integrity_ok(
    facts: &ShimFacts,
    python_source: &str,
    shim_dir: &str,
    command: &str,
    installed_wrapper: &[u8],
) -> ShimResult<bool> {
    if !interpreter_runnable(facts, installed_wrapper)? {
        return Ok(false);
    }
    let sidecar = sidecar_path(facts, shim_dir, command);
    if needs_shell_wrapper(facts) && facts.is_file(&sidecar) && !facts.is_symlink(&sidecar) {
        let sidecar_bytes = facts
            .read_bytes(&sidecar)
            .map_err(|error| error.message(&sidecar))?;
        if !interpreter_runnable(facts, &sidecar_bytes)? {
            return Ok(false);
        }
    }
    if runtime_binding_is_current(facts, shim_dir, command, installed_wrapper) != Some(true) {
        return Ok(false);
    }
    content_matches_generated(facts, python_source, shim_dir, command, installed_wrapper)
}

/// `classify_installed_package_shim_integrity`.
pub(crate) fn classify_integrity(
    facts: &ShimFacts,
    python_source: &str,
    shim_dir: &str,
    command: &str,
    installed_wrapper: &[u8],
    stored_hash: Option<&str>,
) -> ShimResult<&'static str> {
    let current_hash = sha256_hex(&installed_attestation_bytes(
        facts,
        shim_dir,
        command,
        installed_wrapper,
    )?);
    let expected_hash = sha256_hex(&expected_attestation_bytes(
        facts,
        python_source,
        shim_dir,
        command,
    ));
    if !interpreter_runnable(facts, installed_wrapper)? {
        return Ok("stale");
    }
    let binding = runtime_binding_is_current(facts, shim_dir, command, installed_wrapper);
    if binding == Some(false)
        && content_matches_generated(facts, python_source, shim_dir, command, installed_wrapper)?
    {
        return Ok("stale");
    }
    if current_hash == expected_hash
        || integrity_ok(facts, python_source, shim_dir, command, installed_wrapper)?
    {
        return Ok("ok");
    }
    if stored_hash == Some(current_hash.as_str()) {
        return Ok("stale");
    }
    if stored_hash.is_none() {
        return Ok("unknown");
    }
    Ok("tampered")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::super::ShimFacts;
    use super::interpreter_runnable;

    fn facts(executable: &str, frozen: bool) -> ShimFacts {
        ShimFacts {
            environ: BTreeMap::new(),
            home: "/Users/home".to_owned(),
            cwd: "/Users/work".to_owned(),
            executable: executable.to_owned(),
            frozen,
            frozen_cli: String::new(),
            trusted_frozen_cli_paths: Vec::new(),
            python_version: (3, 12),
            import_root: "/Users/src".to_owned(),
            argv0: None,
            windows: false,
            sqlite_connect_timeout_seconds: 30.0,
            now: "2026-01-01T00:00:00+00:00".to_owned(),
            shim_dir_transient: None,
        }
    }

    fn runnable(executable: &str, frozen: bool, wrapper: &[u8]) -> bool {
        interpreter_runnable(&facts(executable, frozen), wrapper).expect("no path error")
    }

    #[test]
    fn unfrozen_shebang_is_runnable_only_for_the_current_executable() {
        let executable = std::env::current_exe().expect("test executable");
        let path = executable.to_str().expect("utf8");
        let wrapper = format!("#!{path}\n");
        assert!(runnable(path, false, wrapper.as_bytes()));
        assert!(!runnable(
            path,
            false,
            b"#!/tmp/not-the-guard-interpreter\n"
        ));
        assert!(!runnable(path, true, wrapper.as_bytes()));
        assert!(!runnable(
            "/Users/missing/python3",
            false,
            b"#!/Users/missing/python3\n"
        ));
        let spaced = "/Users/py bin/python3";
        assert!(!runnable(spaced, false, format!("#!{spaced}\n").as_bytes()));
        assert!(!runnable(
            "/tmp/.mount_HOLabc123/usr/bin/python3",
            false,
            b"#!/tmp/.mount_HOLabc123/usr/bin/python3\n"
        ));
    }
}
