//! Structural launch contracts for an already authenticated Codex generation.
//! Signed commands must still describe the isolated Guard package whose files
//! were checked, rather than merely equal another signed arbitrary command.
use super::super::BridgeConfig;
use crate::claude_hook_bridge_render::py_repr_str;
use serde_json::{json, Value};
use std::path::Path;

pub(super) fn fallback_prefix(python: &str, root: &str) -> Vec<String> {
    vec![python.to_owned(), "-I".into(), "-c".into(), format!(
        "import sys;sys.path.insert(0, {});from codex_plugin_scanner.cli import main;raise SystemExit(main(sys.argv[1:]))", py_repr_str(root))]
}

pub(super) fn start_command(python: &str, root: &str, home: &str, user_home: &str) -> Vec<String> {
    vec![python.to_owned(), "-I".into(), "-c".into(), format!(
        "import os,sys;sys.path.insert(0, {});from pathlib import Path;from codex_plugin_scanner.guard.daemon import schedule_guard_daemon_recovery;failure_kind=os.environ.get('HOL_GUARD_HOOK_FAILURE_KIND','transport-failure');failure_kind=failure_kind if failure_kind in {{'overload','transport-failure','authenticated-control-plane-failure'}} else 'transport-failure';schedule_guard_daemon_recovery(Path({}),home_dir=Path({}),failure_kind=failure_kind)",
        py_repr_str(root), py_repr_str(home), py_repr_str(user_home))]
}

pub(super) fn validate(manifest: &Value, argv: &[String], config: &BridgeConfig) -> Option<()> {
    let target = manifest.pointer("/interpreter/target/path")?.as_str()?;
    let trust = manifest
        .get("packaged_files")?
        .as_array()?
        .iter()
        .find(|file| file.get("role").and_then(Value::as_str) == Some("runtime_trust"))?;
    if trust.get("path")?.as_str()? == target {
        return frozen(manifest, argv, config);
    }
    source(manifest, argv, config)
}

fn source(manifest: &Value, argv: &[String], config: &BridgeConfig) -> Option<()> {
    let interpreter = manifest.get("interpreter")?;
    let python = interpreter.get("invocation_path")?.as_str()?;
    let files = manifest.get("packaged_files")?.as_array()?;
    let file = |role: &str| {
        files
            .iter()
            .find(|f| f.get("role").and_then(Value::as_str) == Some(role))
    };
    let path = |role: &str| file(role)?.get("path")?.as_str();
    let trust = Path::new(path("runtime_trust")?);
    let guard = trust.parent()?;
    if trust.file_name()? != "codex_hook_runtime_trust.py" || guard.file_name()? != "guard" {
        return None;
    }
    let package = guard.parent()?;
    if package.file_name()? != "codex_plugin_scanner" {
        return None;
    }
    let root = super::canonical(package.parent()?)?;
    for (role, relative) in [
        ("bridge", "adapters/codex_daemon_hook_bridge.py"),
        ("bridge_runtime", "codex_hook_bridge_runtime.py"),
        ("launch_runtime", "codex_hook_launch_runtime.py"),
        ("runtime_trust", "codex_hook_runtime_trust.py"),
        ("windows_job", "codex_hook_windows_job.py"),
    ] {
        if path(role)? != super::canonical(&guard.join(relative))? {
            return None;
        }
        if manifest.get("transport")?.get(role)? != file(role)? {
            return None;
        }
    }
    if !manifest
        .get("transport")?
        .get("wrapper")
        .unwrap_or(&Value::Null)
        .is_null()
    {
        return None;
    }
    for (role, relative) in [
        ("hook_probe", "runtime_transition_hook_probe.py"),
        ("native_receipt", "native_decision_receipt.py"),
    ] {
        if let Some(identity) = file(role) {
            if identity.get("path")?.as_str()? != super::canonical(&guard.join(relative))? {
                return None;
            }
        }
    }
    for (role, relative) in [
        ("daemon_entrypoint", "daemon/__init__.py"),
        ("daemon_manager", "daemon/manager.py"),
    ] {
        if path(role)? != super::canonical(&guard.join(relative))? {
            return None;
        }
    }
    event_prefix(manifest, &[python, "-I", path("bridge")?])?;
    if path("fallback_entrypoint")? != super::canonical(&package.join("cli.py"))? {
        return None;
    }
    match argv {
        [_config] => {} // Python launcher supplies config only; signed membership is checked by caller.
        [program, isolated, bridge, _config]
            if program == python && isolated == "-I" && bridge == path("bridge")? => {}
        _ => return None,
    }
    let fallback = manifest.get("fallback")?;
    if fallback.get("argv")? != &json!(config.fallback_command)
        || fallback.get("interpreter")? != interpreter
        || fallback.get("package_roles")? != &json!(["fallback_entrypoint"])
        || config.fallback_command.get(..4)? != fallback_prefix(python, &root)
        || config.fallback_command.get(4..8)? != ["guard", "hook", "--harness", "codex"]
    {
        return None;
    }
    let home = manifest.pointer("/context/runtime_guard_home")?.as_str()?;
    let user_home = manifest.pointer("/context/home_dir")?.as_str()?;
    if super::canonical(Path::new(&config.state_path).parent()?)? != home
        || super::canonical(Path::new(user_home))? != user_home
    {
        return None;
    }
    let start = manifest.get("daemon_start")?;
    if start.get("argv")? != &json!(config.start_command)
        || start.get("interpreter")? != interpreter
        || start.get("package_roles")? != &json!(["daemon_entrypoint", "daemon_manager"])
        || config.start_command != start_command(python, &root, home, user_home)
    {
        return None;
    }
    Some(())
}

const FROZEN_BRIDGE: &str = "--_hol-guard-codex-bridge";
const FROZEN_RECOVER: &str = "--_hol-guard-codex-daemon-recover";

fn event_prefix(manifest: &Value, prefix: &[&str]) -> Option<()> {
    let events = manifest.get("events")?.as_array()?;
    if events.is_empty() {
        return None;
    }
    for event in events {
        let argv = event.get("argv")?.as_array()?;
        let argv = if argv.get(1).and_then(Value::as_str) == Some("codex-hook-bridge")
            && argv
                .first()?
                .as_str()
                .is_some_and(|value| !value.is_empty())
        {
            &argv[2..]
        } else {
            argv.as_slice()
        };
        if argv.len() != prefix.len() + 1
            || !argv
                .iter()
                .zip(prefix)
                .all(|(value, expected)| value.as_str() == Some(*expected))
        {
            return None;
        }
    }
    Some(())
}

/// Frozen Desktop binds every role to one immutable sidecar executable;
/// it never imports a Python source tree or accepts a source bootstrap.
fn frozen(manifest: &Value, argv: &[String], config: &BridgeConfig) -> Option<()> {
    let interpreter = manifest.get("interpreter")?;
    let program = interpreter.get("invocation_path")?.as_str()?;
    let target = interpreter.pointer("/target/path")?.as_str()?;
    if program != target {
        return None;
    }
    let files = manifest.get("packaged_files")?.as_array()?;
    if files
        .iter()
        .any(|file| file.get("path").and_then(Value::as_str) != Some(target))
    {
        return None;
    }
    let transport = manifest.get("transport")?;
    if !transport.get("wrapper").unwrap_or(&Value::Null).is_null() {
        return None;
    }
    for role in [
        "bridge",
        "bridge_runtime",
        "launch_runtime",
        "runtime_trust",
        "windows_job",
    ] {
        let file = files
            .iter()
            .find(|file| file.get("role").and_then(Value::as_str) == Some(role))?;
        if transport.get(role)? != file {
            return None;
        }
    }
    event_prefix(manifest, &[program, FROZEN_BRIDGE])?;
    match argv {
        [_config] => {}
        [executable, flag, _config] if executable == program && flag == FROZEN_BRIDGE => {}
        _ => return None,
    }
    let fallback = manifest.get("fallback")?;
    if fallback.get("interpreter")? != interpreter
        || fallback.get("package_roles")? != &json!(["fallback_entrypoint"])
        || fallback.get("argv")? != &json!(config.fallback_command)
        || config.fallback_command.get(..4)? != [program, "hook", "--harness", "codex"]
    {
        return None;
    }
    let start = manifest.get("daemon_start")?;
    let home = manifest.pointer("/context/runtime_guard_home")?.as_str()?;
    let user_home = manifest.pointer("/context/home_dir")?.as_str()?;
    if super::canonical(Path::new(&config.state_path).parent()?)? != home
        || start.get("interpreter")? != interpreter
        || start.get("package_roles")? != &json!(["daemon_entrypoint", "daemon_manager"])
        || start.get("argv")? != &json!(config.start_command)
        || config.start_command.len() != 3
        || config.start_command.get(..2)? != [program, FROZEN_RECOVER]
    {
        return None;
    }
    let payload: Value = serde_json::from_str(config.start_command.get(2)?).ok()?;
    (payload == json!({"guard_home":home,"home_dir":user_home})).then_some(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn python_literal_paths_are_escaped_in_bootstraps() {
        let prefix = fallback_prefix("python", "C:\\it's\\Guard");
        assert_eq!(prefix.len(), 4);
        assert!(prefix[3].contains("\"C:\\\\it's\\\\Guard\""));
        let start = start_command("python", "/pkg", "/guard", "/home");
        assert_eq!(start[3], "import os,sys;sys.path.insert(0, '/pkg');from pathlib import Path;from codex_plugin_scanner.guard.daemon import schedule_guard_daemon_recovery;failure_kind=os.environ.get('HOL_GUARD_HOOK_FAILURE_KIND','transport-failure');failure_kind=failure_kind if failure_kind in {'overload','transport-failure','authenticated-control-plane-failure'} else 'transport-failure';schedule_guard_daemon_recovery(Path('/guard'),home_dir=Path('/home'),failure_kind=failure_kind)");
    }
}
