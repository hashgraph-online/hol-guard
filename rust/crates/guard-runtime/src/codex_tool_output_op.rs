//! `CodexToolOutput` resident op.
//!
//! Rust owns every verdict about Codex tool-output commands: read-only source
//! inspection, secret-like source names, git pathspec identities, local content
//! reads and focused pytest. Python sends the command text and observed facts
//! and relays the answer. A malformed or oversized request is an error result
//! with `allowed = false`; nothing here falls back to Python.

use std::collections::BTreeMap;

use guard_command::{review_codex_tool_output, Ctx, GitCheck, GitProbe, GitRun, InspectionHost};
use guard_contracts::{
    CodexToolOutputActionV1, CodexToolOutputFactsV1, CodexToolOutputRequestV1,
    CodexToolOutputResultV1, CompoundGitSegmentV1, GitExecutionSafetyCheckV1,
    GitExecutionSafetyRequestV1, CODEX_POST_TOOL_OUTPUT_MAX_BYTES, CODEX_TOOL_OUTPUT_MAX_BYTES,
    CODEX_TOOL_OUTPUT_REQUEST_SCHEMA, CODEX_TOOL_OUTPUT_RESULT_SCHEMA,
    GIT_EXECUTION_SAFETY_REQUEST_SCHEMA,
};
use guard_policy_snapshot::digest_bytes;

use super::context_digest_json::write_canonical_json_with_limit;
use crate::codex_tool_output_git::run_pathspec_git;

const INVALID: &str = "native_codex_tool_output_invalid";
const SCHEMA_MISMATCH: &str = "native_codex_tool_output_schema_mismatch";
const MAX_TEXT_BYTES: usize = 64 * 1024;
const MAX_COMMANDS: usize = 256;
const MAX_ENVIRONMENT: usize = 128;
const MAX_GROUPS: usize = 256;

pub(crate) struct ResidentInspectionHost<'a> {
    pub(crate) facts: &'a CodexToolOutputFactsV1,
}

impl ResidentInspectionHost<'_> {
    fn decide_git(
        &self,
        check: GitExecutionSafetyCheckV1,
        cwd: Option<&str>,
        arguments: &[String],
        git_path: Option<&str>,
    ) -> bool {
        self.git_request_allowed(check, cwd, arguments, git_path, None)
    }

    pub(crate) fn git_request_allowed(
        &self,
        check: GitExecutionSafetyCheckV1,
        cwd: Option<&str>,
        arguments: &[String],
        git_path: Option<&str>,
        reference: Option<&str>,
    ) -> bool {
        let request = GitExecutionSafetyRequestV1 {
            schema: GIT_EXECUTION_SAFETY_REQUEST_SCHEMA.to_owned(),
            request_id: String::new(),
            check,
            cwd: cwd.unwrap_or(&self.facts.home).to_owned(),
            home: self.facts.home.clone(),
            account_home: self.facts.account_home.clone(),
            groups: self.facts.groups.clone(),
            environment: self.facts.environment.clone(),
            git_binary: None,
            git_path: git_path.map(str::to_owned),
            arguments: arguments.to_vec(),
            branch: None,
            reference: reference.map(str::to_owned),
        };
        crate::git_execution_safety_checks::decide(&request).allowed
    }
}

impl InspectionHost for ResidentInspectionHost<'_> {
    fn env(&self, name: &str) -> Option<String> {
        self.facts.environment.get(name).cloned()
    }

    fn environment(&self) -> Vec<(String, String)> {
        self.facts
            .environment
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect()
    }

    fn git_executable(&self) -> Option<String> {
        self.facts.git_executable.clone()
    }

    fn git_binary_trusted(&self, git: &str, cwd: &str) -> bool {
        self.decide_git(
            GitExecutionSafetyCheckV1::BinaryTrusted,
            Some(cwd),
            &[],
            Some(git),
        )
    }

    fn git_safety(&self, check: GitCheck, cwd: Option<&str>, arguments: &[String]) -> bool {
        let check = match check {
            GitCheck::ResolveBinary => GitExecutionSafetyCheckV1::ResolveBinary,
            GitCheck::ConfigEnvironmentClean => GitExecutionSafetyCheckV1::ConfigEnvironmentClean,
            GitCheck::StatusArguments => GitExecutionSafetyCheckV1::StatusArguments,
            GitCheck::StatusConfig => GitExecutionSafetyCheckV1::StatusConfig,
        };
        self.decide_git(check, cwd, arguments, None)
    }

    fn run_git(&self, git: &str, args: &[String], cwd: &str) -> GitRun {
        run_pathspec_git(git, args, cwd, &self.facts.environment)
    }

    fn compound_git_chain(&self, segments: &[CompoundGitSegmentV1], complete: bool) -> bool {
        self.svc_compound_chain(segments, complete)
    }

    fn git_inspection_segment(
        &self,
        segment: &CompoundGitSegmentV1,
        home_dir: Option<&str>,
    ) -> bool {
        self.svc_inspection_segment(segment, home_dir)
    }

    fn cached_diff_pathspecs(&self, values: &[String]) -> bool {
        self.svc_cached_diff_pathspecs(values)
    }

    fn git_show_config(
        &self,
        segment: &CompoundGitSegmentV1,
        repository_path: Option<&str>,
    ) -> bool {
        self.svc_show_config(segment, repository_path)
    }

    fn git_log_execution_free_config(&self, cwd: &str, git: &str) -> bool {
        self.svc_log_config(cwd, git)
    }

    fn standalone_git_routine(
        &self,
        segments: &[CompoundGitSegmentV1],
        complete: bool,
        home_dir: Option<&str>,
    ) -> bool {
        self.svc_standalone_routine(segments, complete, home_dir)
    }

    fn trusted_path_command(&self, command: &str, cwd: &str, home_dir: &str) -> bool {
        self.svc_trusted_path_command(command, cwd, home_dir)
    }

    /// The evidence builder reads the package, lock and executable through the
    /// crate's `O_NOFOLLOW` integrity helpers, which are POSIX-only, so
    /// `contained_runner` itself is `cfg(unix)`. Off Unix the resident keeps the
    /// trait's fail-closed answer and the chain stays unrecognized, exactly as
    /// it did before this hook was answered anywhere.
    #[cfg(unix)]
    fn bun_script_evidence_complete(&self, script_args: &[String], workspace: &str) -> bool {
        guard_command::contained_runner::bun_script_evidence_complete(
            script_args,
            std::path::Path::new(workspace),
        )
    }

    fn trusted_git_binary(&self, cwd: &str) -> Option<String> {
        self.svc_trusted_git(cwd)
    }

    fn git_probe(&self, git: &str, args: &[String], cwd: &str) -> Option<GitProbe> {
        self.svc_probe(git, args, cwd)
    }

    fn git_worktree_add_config(&self, git: &str, cwd: &str, reference: &str) -> bool {
        self.svc_worktree_add_config(git, cwd, reference)
    }

    fn git_lfs_trusted(&self, cwd: &str) -> bool {
        self.svc_trusted_path_command("git-lfs", cwd, &self.facts.home)
    }

    fn home_git_c_path(&self, command: &str) -> Option<String> {
        self.svc_home_git_c_path(command)
    }

    fn git_object_existence_query(&self, command: &str, cwd: &str) -> bool {
        self.svc_object_existence(command, cwd)
    }

    fn real_path(&self, path: &str) -> Option<String> {
        path.starts_with('/')
            .then(|| crate::oci_path::resolve_lenient(path))
    }

    fn is_directory(&self, path: &str) -> bool {
        std::path::Path::new(path).is_dir()
    }

    fn is_regular_file(&self, path: &str) -> bool {
        std::path::Path::new(path).is_file()
    }

    fn file_text_prefix(&self, path: &str, max_bytes: usize) -> Option<String> {
        use std::io::Read;

        let file = std::fs::File::open(path).ok()?;
        if !file.metadata().ok()?.is_file() {
            return None;
        }
        let mut bytes = Vec::new();
        file.take(max_bytes as u64).read_to_end(&mut bytes).ok()?;
        Some(guard_command::codex_prompt_credential_file::decode_ignoring_errors(&bytes))
    }

    fn path_contains_symlink(&self, path: &str, base_dir: &str) -> bool {
        let base = std::path::Path::new(base_dir);
        let Ok(relative) = std::path::Path::new(path).strip_prefix(base) else {
            // Not under the root it was measured against: refuse rather than
            // walk a path that could leave it.
            return true;
        };
        let mut candidate = base.to_path_buf();
        for part in relative.components() {
            let std::path::Component::Normal(name) = part else {
                continue;
            };
            candidate.push(name);
            match std::fs::symlink_metadata(&candidate) {
                Ok(metadata) => {
                    if metadata.file_type().is_symlink() {
                        return true;
                    }
                }
                Err(_) => return true,
            }
        }
        false
    }

    #[cfg(unix)]
    fn attachment_reader(
        &self,
        attachment_root: &str,
        relative: &[String],
        max_bytes: u64,
    ) -> Option<Box<dyn std::io::Read + '_>> {
        use std::os::unix::fs::MetadataExt;

        use nix::fcntl::{open, openat, OFlag};
        use nix::sys::stat::Mode;

        let (last, parents) = relative.split_last()?;
        if relative
            .iter()
            .any(|part| part.is_empty() || part == "." || part == "..")
        {
            return None;
        }
        let directory_flags =
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
        let resolved_root = std::fs::canonicalize(attachment_root).ok()?;
        let root = std::fs::File::from(open(attachment_root, directory_flags, Mode::empty()).ok()?);
        // The descriptor the walk starts from has to be the resolved root
        // itself; an intermediate component of the spelling may have been
        // retargeted while it was opened.
        let opened = root.metadata().ok()?;
        let expected = std::fs::symlink_metadata(&resolved_root).ok()?;
        if opened.dev() != expected.dev() || opened.ino() != expected.ino() {
            return None;
        }
        let mut directory = std::os::fd::OwnedFd::from(root);
        for part in parents {
            directory = openat(&directory, part.as_str(), directory_flags, Mode::empty()).ok()?;
        }
        let file = std::fs::File::from(
            openat(
                &directory,
                last.as_str(),
                OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .ok()?,
        );
        // Python read the descriptor's `fstat` before the first chunk, so an
        // attachment past the limit never cost a scan.
        let metadata = file.metadata().ok()?;
        if !metadata.is_file() || metadata.len() > max_bytes {
            return None;
        }
        Some(Box::new(file))
    }

    /// Without `openat` the walk cannot be descriptor-relative, so the opened
    /// path is resolved once and required to stay under the resolved root,
    /// which is the branch CPython takes on the same platforms.
    #[cfg(not(unix))]
    fn attachment_reader(
        &self,
        attachment_root: &str,
        relative: &[String],
        max_bytes: u64,
    ) -> Option<Box<dyn std::io::Read + '_>> {
        if relative.is_empty()
            || relative
                .iter()
                .any(|part| part.is_empty() || part == "." || part == "..")
        {
            return None;
        }
        let resolved_root = std::fs::canonicalize(attachment_root).ok()?;
        let mut candidate = std::path::PathBuf::from(attachment_root);
        for part in relative {
            candidate.push(part);
        }
        let resolved = std::fs::canonicalize(&candidate).ok()?;
        if !resolved.starts_with(&resolved_root) {
            return None;
        }
        let file = std::fs::File::open(&resolved).ok()?;
        // Python read the descriptor's `fstat` before the first chunk, so an
        // attachment past the limit never cost a scan.
        let metadata = file.metadata().ok()?;
        if !metadata.is_file() || metadata.len() > max_bytes {
            return None;
        }
        Some(Box::new(file))
    }
}

fn request_digest(request: &CodexToolOutputRequestV1) -> Result<String, &'static str> {
    let material = serde_json::to_value(request).map_err(|_| INVALID)?;
    // A harness accepts up to a megabyte of hook input, so a prompt review
    // carries whatever the user pasted. Holding it to the ordinary request
    // limit turned a long prompt into an invalid request, and a prompt review
    // that cannot answer is a review the user did not need.
    let limit = match request.action {
        CodexToolOutputActionV1::PostToolOutput(_)
        | CodexToolOutputActionV1::PostToolReadOnlyPayload(_)
        | CodexToolOutputActionV1::PromptCredentialFile(_)
        | CodexToolOutputActionV1::PromptAttachment(_) => CODEX_POST_TOOL_OUTPUT_MAX_BYTES,
        _ => CODEX_TOOL_OUTPUT_MAX_BYTES,
    };
    let mut bytes = Vec::new();
    write_canonical_json_with_limit(&material, &mut bytes, limit).map_err(|_| INVALID)?;
    Ok(format!("sha256:{}", digest_bytes(&bytes)))
}

fn text_is_bounded(value: &str) -> bool {
    value.len() <= MAX_TEXT_BYTES
}

fn path_is_bounded(value: &str) -> bool {
    text_is_bounded(value) && !value.contains('\0')
}

fn option_path_is_bounded(value: &Option<String>) -> bool {
    value.as_deref().is_none_or(path_is_bounded)
}

fn action_is_bounded(action: &CodexToolOutputActionV1) -> bool {
    use CodexToolOutputActionV1 as Action;
    match action {
        Action::ReadOnlyInspection(scope) => {
            text_is_bounded(&scope.command)
                && option_path_is_bounded(&scope.cwd)
                && option_path_is_bounded(&scope.home_dir)
        }
        Action::PostToolReadOnly(scope) => {
            scope.commands.len() <= MAX_COMMANDS
                && scope
                    .commands
                    .iter()
                    .all(|command| text_is_bounded(command))
                && option_path_is_bounded(&scope.cwd)
                && option_path_is_bounded(&scope.home_dir)
        }
        Action::SecretLikeSourceName(scope) => {
            text_is_bounded(&scope.command)
                && option_path_is_bounded(&scope.cwd)
                && option_path_is_bounded(&scope.home_dir)
        }
        Action::GitPathspecIdentity(scope)
        | Action::LocalContentTail(scope)
        | Action::GitMetadata(scope) => {
            text_is_bounded(&scope.command) && option_path_is_bounded(&scope.cwd)
        }
        Action::ReadsEnvironmentPipeline(text) | Action::FocusedPytest(text) => {
            text_is_bounded(&text.command)
        }
        // The canonical digest already bounds the whole body.
        Action::PostToolOutput(_) | Action::PostToolReadOnlyPayload(_) => true,
        // A prompt is prose, not a command line: the canonical digest limit
        // bounds it, as it does for every other prompt review.
        Action::PromptCredentialFile(scope) => {
            option_path_is_bounded(&scope.cwd) && path_is_bounded(&scope.config_path)
        }
        // Prose again, bounded by the canonical digest like the credential-file
        // scan beside it.
        Action::PromptAttachment(scope) => {
            path_is_bounded(&scope.home_dir) && path_is_bounded(&scope.config_path)
        }
    }
}

fn environment_is_bounded(environment: &BTreeMap<String, String>) -> bool {
    environment.len() <= MAX_ENVIRONMENT
        && environment
            .iter()
            .all(|(key, value)| key.len() <= 256 && path_is_bounded(value))
}

fn request_is_bounded(request: &CodexToolOutputRequestV1) -> bool {
    let facts = &request.facts;
    request.request_id.len() <= 128
        && action_is_bounded(&request.action)
        && path_is_bounded(&facts.process_cwd)
        && path_is_bounded(&facts.home)
        && option_path_is_bounded(&facts.account_home)
        && option_path_is_bounded(&facts.git_executable)
        && facts.groups.len() <= MAX_GROUPS
        && environment_is_bounded(&facts.environment)
}

pub(crate) fn evaluate_codex_tool_output_request(
    request: &CodexToolOutputRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request).map_err(str::to_owned)?;
    let (status, code, allowed, value) = if request.schema != CODEX_TOOL_OUTPUT_REQUEST_SCHEMA {
        ("error", SCHEMA_MISMATCH, false, None)
    } else if !request_is_bounded(request) {
        ("error", INVALID, false, None)
    } else {
        let host = ResidentInspectionHost {
            facts: &request.facts,
        };
        let ctx = Ctx::new(&host, &request.facts.process_cwd, &request.facts.home);
        let outcome = review_codex_tool_output(&ctx, &request.action);
        ("ok", "ok", outcome.allowed, outcome.value)
    };
    crate::encode_response(&CodexToolOutputResultV1 {
        schema: CODEX_TOOL_OUTPUT_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: status.to_owned(),
        code: code.to_owned(),
        allowed,
        value,
    })
}
