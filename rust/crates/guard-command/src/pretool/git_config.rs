use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

#[path = "git_config_filters.rs"]
mod filters;
#[path = "git_config_pager.rs"]
mod pager;
#[path = "git_config_textconv.rs"]
mod textconv;

const CONFIG_LIMIT: u64 = 65_536;

pub(super) fn execution_free(
    executable: &str,
    arguments: &[String],
    context: super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
    stdout_piped: bool,
) -> Option<bool> {
    execution_free_paging(
        executable,
        arguments,
        None,
        context,
        deadline,
        execution_environment,
        stdout_piped,
    )
}

/// [`execution_free`] while paging is proved under `pager_operation` instead
/// of the command's own name. A `stash show` diff is still a diff, but it
/// pages under `pager.stash`.
pub(super) fn execution_free_paging(
    executable: &str,
    arguments: &[String],
    pager_operation: Option<&str>,
    context: super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
    stdout_piped: bool,
) -> Option<bool> {
    let remaining = crate::command_compatibility::git_inspection_arguments(arguments, context)?;
    let operation = remaining.first()?.as_str();
    if !matches!(
        operation,
        "status"
            | "diff"
            | "log"
            | "show"
            | "grep"
            | "branch"
            | "hash-object"
            | "config"
            | "merge-base"
            | "ls-tree"
            | "cat-file"
            | "show-ref"
            | "for-each-ref"
            | "rev-list"
    ) {
        return None;
    }
    // Other object-read forms can run drivers; their own review floors decide.
    if matches!(operation, "ls-tree" | "cat-file")
        && !super::git_object_reads::read_form(operation, &remaining[1..])
    {
        return None;
    }
    if matches!(operation, "show-ref" | "for-each-ref")
        && !super::git_ref_listings::read_form(operation, &remaining[1..])
    {
        return None;
    }
    if operation == "rev-list" && !super::git_rev_list::read_form(&remaining[1..]) {
        return None;
    }
    // A plain configuration write is no read; its own proof decides it.
    if operation == "config"
        && super::git_config_reads::writes::plain_write(&remaining[1..]).is_some()
    {
        return None;
    }
    let pager_operation = pager_operation.unwrap_or(operation).to_owned();
    // The memo key has no field of its own for which pager this proof uses,
    // so the operation rides with the executable. A real executable has no NUL.
    let key = (
        format!("{executable}\0{pager_operation}"),
        arguments.to_vec(),
        context.home_dir.map(str::to_owned),
        context.cwd.map(str::to_owned),
        stdout_piped,
    );
    super::git_probe::memoized(key, || {
        Some(
            probe(
                executable,
                arguments,
                remaining,
                Paging {
                    operation: &pager_operation,
                    stdout_piped,
                },
                context,
                deadline,
                execution_environment,
            )
            .unwrap_or(false),
        )
    })
}

/// How the read would page: the configuration key the pager is proved under,
/// and whether the caller already sends stdout down a pipe, which leaves Git
/// no terminal to page to.
struct Paging<'a> {
    operation: &'a str,
    stdout_piped: bool,
}

fn probe(
    executable: &str,
    arguments: &[String],
    remaining: &[String],
    paging: Paging<'_>,
    context: super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> Option<bool> {
    let Paging {
        operation: pager_operation,
        stdout_piped,
    } = paging;
    let operation = remaining.first()?.as_str();
    // Configuration plus root, path and attribute inspection share this budget.
    // The caller's overall deadline remains the upper bound.
    let inspection_deadline = Instant::now() + super::git_probe::PROBE_BUDGET;
    let deadline = deadline
        .unwrap_or(inspection_deadline)
        .min(inspection_deadline);
    if Instant::now() >= deadline {
        return None;
    }
    let declared_home = Path::new(context.home_dir?);
    let declared_cwd = Path::new(context.cwd?);
    if !declared_home.is_absolute() || !declared_cwd.is_absolute() {
        return None;
    }
    let home = fs::canonicalize(declared_home).ok()?;
    let cwd = fs::canonicalize(declared_cwd).ok()?;
    let raw_leading = &arguments[..arguments.len().checked_sub(remaining.len())?];
    if raw_leading
        .windows(2)
        .any(|pair| pair[0] == "-C" && pair[1].starts_with('~'))
    {
        let shell_home = execution_environment
            .and_then(|context| context.home.as_deref())
            .map(Path::new)
            .unwrap_or(declared_home);
        if fs::canonicalize(shell_home).ok().as_deref() != Some(home.as_path()) {
            return None;
        }
    }
    let leading = expand_home_targets(raw_leading, declared_home);
    if !home.is_dir() || !cwd.is_dir() || !clean_environment(execution_environment, &home, &cwd) {
        return None;
    }
    let binary = trusted_command(executable, &home, &cwd, execution_environment)?;
    let mut command = Command::new(&binary);
    command.env_clear();
    #[cfg(windows)]
    for key in ["SYSTEMROOT", "WINDIR"] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    if let Some(directory) =
        execution_environment.and_then(|context| context.xdg_config_home.as_deref())
    {
        command.env("XDG_CONFIG_HOME", directory);
    } else if execution_environment.is_none() {
        if let Some(directory) = std::env::var_os("XDG_CONFIG_HOME") {
            command.env("XDG_CONFIG_HOME", directory);
        }
    }
    if execution_environment.is_some_and(|context| context.git_config_no_system) {
        command.env("GIT_CONFIG_NOSYSTEM", "1");
    }
    let git_home = execution_environment
        .and_then(|context| context.home.as_deref())
        .map(Path::new)
        // Git for Windows must see the original home spelling, not the
        // extended-length prefix produced by std::fs::canonicalize.
        .unwrap_or(declared_home);
    command
        .args(&leading)
        // Git for Windows rejects the `\\?\` prefix from canonicalize.
        // The declared cwd is the path the agent process would use.
        .current_dir(declared_cwd)
        .env("HOME", git_home)
        .env("USERPROFILE", git_home);
    let mut query = super::git_probe::copy_command(&command)?;
    let (status, output) = super::git_probe::output(
        query
        .args([
            "--no-pager",
            "config",
            "--null",
            "--get-regexp",
            "^(core\\.fsmonitor|core\\.pager|pager\\..*|diff\\.external|diff\\..*\\.(command|textconv)|filter\\..*\\.(process|clean|smudge)|log\\.showsignature|gpg\\.program|gpg\\..*\\.program|format\\.pretty|pretty\\..*|grep\\.fallbacktonoindex|extensions\\.partialclone|remote\\..*\\.promisor)$",
        ])
,
        deadline, CONFIG_LIMIT,
    )?;
    if !(status.success() || status.code() == Some(1) && output.is_empty()) {
        return None;
    }
    let output = std::str::from_utf8(&output).ok()?;
    let options = remaining
        .iter()
        .skip(1)
        .take_while(|value| value.as_str() != "--");
    // Deliberately conservative: an explicit signature request always needs
    // review, even if a later --no-show-signature would disable it. We do not
    // claim to prove the complete signature-format/helper option grammar.
    if options.clone().any(|value| {
        value.as_str() == "--show-signature"
            || (matches!(operation, "log" | "show") && value.contains("%G"))
            || value.starts_with("--remerge-diff")
            || value == "--diff-merges=remerge"
            || value == "--submodule=diff"
    }) {
        return Some(false);
    }
    let no_external = options
        .clone()
        .filter_map(|value| match value.as_str() {
            "--no-ext-diff" => Some(true),
            "--ext-diff" => Some(false),
            _ => None,
        })
        .last()
        == Some(true);
    let no_textconv = options
        .clone()
        .filter_map(|value| match value.as_str() {
            "--no-textconv" => Some(true),
            "--textconv" => Some(false),
            _ => None,
        })
        .last()
        == Some(true);
    let option_flags = options
        .clone()
        .map(String::as_str)
        .filter(|value| value.starts_with('-'))
        .collect::<Vec<_>>();
    let textconv_runs = !no_textconv && textconv::may_run(operation, &option_flags);
    let mut effective = std::collections::BTreeMap::new();
    for record in output.split('\0').filter(|record| !record.is_empty()) {
        let (key, value) = record.split_once('\n')?;
        effective.insert(key, value);
    }
    let pager_key = format!("pager.{pager_operation}");
    let pager_setting = effective.get(pager_key.as_str()).copied();
    // Like status, hash-object pages only when its own pager.* key says so;
    // config pages by default only for its listing forms.
    let pages_by_default = match operation {
        "status" | "hash-object" | "merge-base" | "ls-tree" | "cat-file" | "show-ref"
        | "for-each-ref" | "rev-list" => false,
        "config" => super::git_config_reads::pages_by_default(&remaining[1..]),
        _ => true,
    };
    let configured_pager = pager_setting.or_else(|| {
        pages_by_default
            .then(|| effective.get("core.pager").copied())
            .flatten()
    });
    let environment_pager = pager::environment_pager_disabled(execution_environment);
    let git_pager_disabled = pager::git_pager_disabled(execution_environment);
    let no_pager = stdout_piped
        || leading
            .iter()
            .any(|argument| matches!(argument.as_str(), "-P" | "--no-pager"));
    let configured_paging =
        !no_pager && configured_pager.map_or(pages_by_default, |value| !disabled_boolean(value));
    let configured_pager_is_cat = configured_pager.is_some_and(|value| value == "cat");
    let paging = configured_paging
        && !configured_pager_is_cat
        && !environment_pager.is_some_and(|disabled| disabled);
    if paging && environment_pager == Some(false) {
        return Some(false);
    }
    // Attribute and index inspection must not trigger lazy partial-clone fetch.
    if effective.iter().any(|(key, value)| {
        (*key == "extensions.partialclone" && !value.is_empty())
            || (key.starts_with("remote.")
                && key.ends_with(".promisor")
                && !disabled_boolean(value))
    }) {
        return Some(false);
    }
    // hash-object cleans only its named files, and only without --no-filters.
    let hashed = (operation == "hash-object")
        .then(|| super::git_hash_object::read_operands(&remaining[1..]))
        .flatten()
        .filter(|_| !super::git_hash_object::filters_disabled(&remaining[1..]));
    let filtered = matches!(operation, "status" | "diff") || hashed.is_some();
    let has_filters = filtered
        && effective
            .iter()
            .any(|(key, value)| key.starts_with("filter.") && !value.is_empty());
    let filters_unused = !has_filters
        || filters::unused(
            &binary,
            &leading,
            declared_cwd,
            git_home,
            execution_environment,
            deadline,
            hashed.as_deref().unwrap_or_default(),
            operation == "status",
        )?;
    for (key, value) in effective {
        let disabled = disabled_boolean(value);
        let unsafe_value = match key {
            "extensions.partialclone" => !value.is_empty(),
            key if key.starts_with("remote.") && key.ends_with(".promisor") => !disabled,
            // Reading the index can start the monitor; grep reads it too.
            "core.fsmonitor" => matches!(operation, "status" | "diff" | "grep") && !disabled,
            "core.pager" => {
                configured_paging
                    && !git_pager_disabled
                    && pager_setting.is_none_or(enabled_boolean)
                    && !value.is_empty()
                    && value != "cat"
            }
            key if key.starts_with("pager.") => {
                key == pager_key
                    && !git_pager_disabled
                    && !disabled
                    && !value.is_empty()
                    && value != "cat"
                    && if enabled_boolean(value) {
                        paging
                    } else {
                        configured_paging
                    }
            }
            "diff.external" => !no_external && !value.is_empty(),
            key if key.starts_with("diff.") && key.ends_with(".command") => {
                !no_external && !value.is_empty()
            }
            key if key.starts_with("diff.") && key.ends_with(".textconv") => {
                textconv_runs && !value.is_empty()
            }
            key if key.starts_with("filter.") => filtered && !value.is_empty() && !filters_unused,
            "format.pretty" => matches!(operation, "log" | "show") && value.contains("%G"),
            key if key.starts_with("pretty.") => {
                matches!(operation, "log" | "show") && value.contains("%G")
            }
            "log.showsignature" => matches!(operation, "log" | "show") && !disabled,
            // Outside a repository grep would search every file under cwd.
            "grep.fallbacktonoindex" => operation == "grep" && !disabled,
            // A configured verification program (a very common developer
            // setting) runs only when signature verification is requested.
            // Every such request is rejected above: --show-signature,
            // log.showSignature, %G placeholders in the command line,
            // format.pretty or any pretty.* alias. A bare gpg.* definition
            // therefore cannot execute for the remaining reads.
            key if key.starts_with("gpg.") => false,
            _ => return None,
        };
        if unsafe_value {
            return Some(false);
        }
    }
    if operation == "config" {
        return super::git_config_reads::credential_free(&command, &remaining[1..], deadline);
    }
    if !super::git_probe::repository_inert(&command, operation, remaining, deadline)? {
        return Some(false);
    }
    Some(true)
}

/// The probe runs Git without a shell, so a `-C ~/repo` target the shell
/// would expand must be expanded here or the probe inspects nothing.
fn expand_home_targets(leading: &[String], home: &Path) -> Vec<String> {
    let mut expanded = Vec::with_capacity(leading.len());
    let mut directory_next = false;
    for argument in leading {
        let value = if directory_next {
            match argument.strip_prefix('~') {
                Some("") => home.to_string_lossy().into_owned(),
                Some(rest) if rest.starts_with('/') => {
                    format!("{}{rest}", home.to_string_lossy())
                }
                _ => argument.clone(),
            }
        } else {
            argument.clone()
        };
        directory_next = argument == "-C";
        expanded.push(value);
    }
    expanded
}

fn disabled_boolean(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "0" | "false" | "no" | "off"
    )
}

pub(super) fn enabled_boolean(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "true" | "yes" | "on" | "1"
    )
}

pub(super) fn clean_environment(
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
    home: &Path,
    cwd: &Path,
) -> bool {
    let names = match execution_environment {
        Some(context) => {
            let declares_xdg = context
                .environment_names
                .iter()
                .any(|name| name.eq_ignore_ascii_case("XDG_CONFIG_HOME"));
            if declares_xdg != context.xdg_config_home.is_some() {
                return false;
            }
            let declares_no_system = context
                .environment_names
                .iter()
                .any(|name| name.eq_ignore_ascii_case("GIT_CONFIG_NOSYSTEM"));
            if declares_no_system != context.git_config_no_system {
                return false;
            }
            if !context.has_valid_shape()
                || context
                    .library_search_paths
                    .keys()
                    .any(|name| !context.environment_names.contains(name))
            {
                return false;
            }
            context.environment_names.clone()
        }
        None => std::env::vars_os()
            .filter(|(_, value)| !value.is_empty())
            .map(|(name, _)| name.to_string_lossy().into_owned())
            .collect(),
    };
    !names.iter().any(|name| {
        // Unix loader search paths are inert on Windows. Elsewhere a search
        // path the hook stamped is checked entry by entry; every other loader
        // variable, including injection, stays a refusal.
        if super::trusted_location::inert_loader_search_path(name, cfg!(windows))
            || execution_environment.is_some_and(|context| {
                context.library_search_paths.get(name).is_some_and(|value| {
                    super::trusted_location::trusted_library_search_path(value, home, cwd)
                })
            })
        {
            return false;
        }
        let key = name.to_ascii_uppercase();
        key.starts_with("GIT_TRACE")
            || key.starts_with("DYLD_")
            || key.starts_with("LD_")
            || (key.starts_with("GIT_CONFIG")
                && !(key == "GIT_CONFIG_NOSYSTEM"
                    && execution_environment.is_some_and(|context| context.git_config_no_system)))
            || matches!(
                key.as_str(),
                "GIT_DIR"
                    | "GIT_EXTERNAL_DIFF"
                    | "GIT_COMMON_DIR"
                    | "GIT_INDEX_FILE"
                    | "GIT_OBJECT_DIRECTORY"
                    | "GIT_ALTERNATE_OBJECT_DIRECTORIES"
                    | "GIT_NAMESPACE"
                    | "GIT_REPLACE_REF_BASE"
                    | "GIT_SHALLOW_FILE"
                    | "GIT_WORK_TREE"
                    | "GIT_EXEC_PATH"
                    | "GIT_DISCOVERY_ACROSS_FILESYSTEM"
                    | "LD_PRELOAD"
                    | "LD_LIBRARY_PATH"
                    | "DYLD_INSERT_LIBRARIES"
                    | "DYLD_LIBRARY_PATH"
            )
    })
}

pub(super) fn trusted_command(
    executable: &str,
    home: &Path,
    cwd: &Path,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> Option<PathBuf> {
    let supplied = Path::new(executable);
    let path = if supplied.components().count() > 1 {
        fs::canonicalize(if supplied.is_absolute() {
            supplied.to_path_buf()
        } else {
            cwd.join(supplied)
        })
        .ok()?
    } else {
        let mut found = None;
        let path = execution_environment
            .map(|context| std::ffi::OsString::from(&context.path))
            .or_else(|| std::env::var_os("PATH"))?;
        for directory in std::env::split_paths(&path) {
            let directory = if directory.is_absolute() {
                directory
            } else {
                cwd.join(directory)
            };
            let command_name = if cfg!(windows) && supplied.extension().is_none() {
                format!("{executable}.exe")
            } else {
                executable.to_owned()
            };
            let candidate = directory.join(command_name);
            if candidate.is_file() {
                found = Some(fs::canonicalize(candidate).ok()?);
                break;
            }
        }
        found?
    };
    let shim = super::git_session_probe::apple_developer_tools::selection_overridden(
        &path,
        execution_environment,
    );
    (!shim && super::trusted_location::trusted_location(&path, home, cwd)).then_some(path)
}
#[cfg(all(test, unix))]
#[path = "git_config_home_tests.rs"]
mod home_tests;
