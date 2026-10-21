//! `bun -e/-p <program>` in the same read-only boundary as `node -e`.
//!
//! Bun reads files through the same syscalls as Node, so the Node evaluation
//! profile applies unchanged: no workspace writes, no network, no process
//! execution beyond the approved image, and credential-filtered reads. Only
//! the image approval differs; Bun is not installed through nvm.
use super::*;

const INVALID: &str = "inline_eval_invalid_command";

/// A root- or user-owned native Bun image that no other account can replace,
/// installed by the system, Homebrew, or Bun's own installer in the request
/// HOME. A workspace copy is never approved: the repository could supply it.
pub(super) fn approved_bun(executable: &Path, home: Option<&Path>) -> bool {
    let Ok(metadata) = executable.metadata() else {
        return false;
    };
    if ![0, nix::unistd::getuid().as_raw()].contains(&metadata.uid())
        || metadata.mode() & 0o022 != 0
        || executable.file_name() != Some(OsStr::new("bun"))
    {
        return false;
    }
    let installer = request_home(home).map(|home| home.join(".bun/bin/bun"));
    let trusted = [
        Path::new("/usr/bin"),
        Path::new("/usr/local"),
        Path::new("/opt/homebrew"),
    ]
    .iter()
    .any(|root| path_is_within(executable, root))
        || installer.as_deref() == Some(executable);
    trusted && native_image(executable)
}

/// Plan for an `inline_eval` Bun argv: `[bun, -e|--eval|-p|--print, program]`.
pub(super) fn prepare_eval(input: &Input, argv: &[String]) -> Result<Value, RestrictedPytestError> {
    if argv.len() != 3 || !matches!(argv[1].as_str(), "-e" | "--eval" | "-p" | "--print") {
        return Err(RestrictedPytestError::new(
            INVALID,
            "Protected Bun evaluation requires direct bun -e argv.",
        ));
    }
    let (backend, backend_executable) = select_backend(
        &input.platform,
        input.backend_executable.as_deref(),
        &input.search_path,
    )?;
    let workspace =
        validation::resolve_workspace_with_home(&input.workspace, input.home.as_deref())?;
    let cwd = resolve_cwd(&input.cwd, &workspace)?;
    let executable = resolve_executable(&argv[0], &cwd, &input.search_path)?;
    if !approved_bun(&executable, input.home.as_deref()) {
        return Err(RestrictedPytestError::new(
            INVALID,
            "The Bun runtime does not resolve to an approved native executable.",
        ));
    }
    let launcher = locate_executable(&argv[0], &cwd, &input.search_path)?;
    let mut allowed = vec![launcher];
    if !allowed.contains(&executable) {
        allowed.push(executable.clone());
    }
    let mut command = vec![executable.to_string_lossy().into_owned()];
    command.extend_from_slice(&argv[1..]);
    Ok(
        json!({"profile_version":"node-eval-readonly-v1","backend":backend,"backend_executable":backend_executable,
        "workspace":workspace,"cwd":cwd,"executable":executable,"command":command,"allowed_executables":allowed,
        "denied_capabilities":["host-home-read","host-secret-environment","network","docker-socket","workspace-write","workspace-credential-read","unapproved-process-exec","privileged-operation"]}),
    )
}
