//! `local_cli_identify` — the unlisted CLIs a command launches.
//!
//! Custom-extension grants bind the identity derived here. A command names a
//! CLI only as one exact top-level invocation: a package-runner target with
//! content-hashed local-bin evidence (or a registry fetch, which never carries
//! a persistent allow), a verified script entrypoint, or a verified executable
//! that no built-in extension owns. Compound commands also name the scripts
//! each segment sources or launches.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use guard_command::command_model::{parse_shell_command, CanonicalCommand, CommandSegment};
use guard_contracts::{LocalCliIdentitySourceV1, LocalCliIdentityV1, UnlistedCliV1};
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::context_digest_local_cli::{local_cli_identity, python_path_name, python_whitespace};
use crate::context_digest_package_scripts::invocation_is_safe;
use crate::custom_extension_suggestion::is_common_tool_name;
use crate::native_exact_action_op::context::{Ctx, Engines, ResidentEngines};
use crate::native_exact_action_op::runner_bin::{
    package_name_pattern, read_manifest, runner_local_bin, runner_target, Manifest,
    LOCAL_BIN_RUNNERS,
};

const MAX_BUDGET_MS: u64 = 5_000;
const DEADLINE_EXCEEDED: &str = "native_local_cli_identify_deadline";
const PROGRAM_UNAVAILABLE: &str = "native_local_cli_identify_program_unavailable";
const REGISTRY_PACKAGE_PATH_CLASS: &str = "registry-package";
/// Runners that fetch a missing package from the registry instead of failing.
const REGISTRY_FETCH_RUNNERS: [&str; 3] = ["npx", "bunx", "pnpx"];
const MAX_MANIFEST_ANCESTORS: usize = 32;
const DEPENDENCY_SECTIONS: [&str; 3] = ["dependencies", "devDependencies", "optionalDependencies"];
const INTERPRETER_NAMES: [&str; 22] = [
    "ash",
    "bash",
    "bun",
    "dash",
    "deno",
    "ksh",
    "lua",
    "node",
    "nodejs",
    "osascript",
    "perl",
    "php",
    "powershell",
    "pwsh",
    "python",
    "python3",
    "ruby",
    "rscript",
    "sh",
    "ts-node",
    "tsx",
    "zsh",
];
const RESERVED_TOOL_NAMES: [&str; 3] = ["hol-guard", "hol_guard", "guard"];
const PACKAGE_SCRIPT_KINDS: [&str; 1] = ["bun-package-script"];
const INLINE_KINDS: [&str; 4] = ["python-c", "python-m", "node-eval", "inline-script"];
const SOURCE_BUILTINS: [&str; 2] = [".", "source"];
const INLINE_FLAGS: [&str; 2] = ["-c", "-lc"];
const SHELL_INTERPRETERS: [&str; 6] = ["ash", "bash", "dash", "ksh", "sh", "zsh"];
const SHELL_SCRIPT_SUFFIXES: [&str; 5] = [".bash", ".ksh", ".rc", ".sh", ".zsh"];

pub(crate) struct Request<'a> {
    pub(crate) command_text: &'a str,
    pub(crate) cwd: &'a str,
    pub(crate) home_dir: Option<&'a str>,
    pub(crate) user_home: &'a str,
    pub(crate) compound: bool,
    pub(crate) env: &'a BTreeMap<String, String>,
    pub(crate) budget_ms: u64,
}

type Outcome<T> = Result<T, &'static str>;

pub(crate) fn identify(request: &Request<'_>) -> Outcome<Vec<UnlistedCliV1>> {
    identify_with(
        request,
        &ResidentEngines { guard_home: None },
        owned_executables()?,
    )
}

fn identify_with(
    request: &Request<'_>,
    engines: &dyn Engines,
    owned: &HashSet<String>,
) -> Outcome<Vec<UnlistedCliV1>> {
    let deadline = Instant::now() + Duration::from_millis(request.budget_ms.min(MAX_BUDGET_MS));
    let ctx = Ctx {
        home: request.home_dir,
        env: request.env,
        deadline,
        engines,
    };
    let scope = Scope {
        ctx: &ctx,
        cwd: request.cwd,
        user_home: request.user_home,
        owned,
    };
    let mut found = Vec::new();
    push_unique(&mut found, scope.identify(request.command_text)?);
    if request.compound {
        if let Some(model) = scope.parse(request.command_text) {
            let mut allow_relative = true;
            for segment in &model.segments {
                if executable_name(segment.executable.as_deref()).as_deref() == Some("cd") {
                    allow_relative = false;
                }
                push_unique(&mut found, scope.segment_identity(segment, allow_relative)?);
            }
        }
    }
    // A step that ran out of time may have answered "not proven"; never
    // return an identity set the deadline could have shaped.
    scope.check()?;
    Ok(found)
}

fn push_unique(found: &mut Vec<UnlistedCliV1>, identity: Option<UnlistedCliV1>) {
    if let Some(identity) = identity {
        if !found.iter().any(|seen| seen.cli_id == identity.cli_id) {
            found.push(identity);
        }
    }
}

struct Scope<'a> {
    ctx: &'a Ctx<'a>,
    cwd: &'a str,
    user_home: &'a str,
    owned: &'a HashSet<String>,
}

struct RunnerInvocation {
    runner: &'static str,
    target: String,
    package_name: String,
    local_bin: Option<Value>,
    direct_dependency: bool,
}

impl Scope<'_> {
    fn check(&self) -> Outcome<()> {
        if Instant::now() >= self.ctx.deadline {
            return Err(DEADLINE_EXCEEDED);
        }
        Ok(())
    }

    fn parse(&self, command_text: &str) -> Option<CanonicalCommand> {
        let stripped = command_text.trim_matches(python_whitespace);
        if stripped.trim().is_empty() {
            return None;
        }
        Some(parse_shell_command(
            stripped,
            Some(Path::new(self.cwd)),
            self.ctx.home.map(Path::new),
            "posix",
            "shell_string",
            "guard-shell",
            true,
        ))
    }

    /// `identify_unlisted_cli`: the CLI one safe invocation launches.
    fn identify(&self, command_text: &str) -> Outcome<Option<UnlistedCliV1>> {
        self.check()?;
        let Some(model) = self.parse(command_text) else {
            return Ok(None);
        };
        if !invocation_is_safe(&model) {
            return Ok(None);
        }
        let segment = &model.segments[0];
        let Some(executable) = segment.executable.as_deref() else {
            return Ok(None);
        };
        if runner_name(executable).is_some() {
            // `pnpm run <script>` and other non-launch forms keep the launch path.
            if let Some(identity) = self.runner_identity(&model.raw_text, segment, executable)? {
                return Ok(Some(identity));
            }
        }
        let engines = self.ctx.engines;
        let launch = engines.launch_identity(
            executable,
            &segment.arguments,
            self.cwd,
            self.ctx.home,
            self.ctx.env,
        );
        if !engines.launch_reusable(&launch) {
            return Ok(None);
        }
        let (Some(resolved @ Value::Object(_)), Some(entrypoint @ Value::Object(_))) =
            (launch.get("executable"), launch.get("entrypoint"))
        else {
            return Ok(None);
        };
        let Some(exe_name) = executable_name(Some(executable)) else {
            return Ok(None);
        };
        if let Some(script) = script_identity(entrypoint, Some(&exe_name))? {
            return Ok(Some(script));
        }
        if is_interpreter_name(&exe_name)
            || is_common_tool_name(&exe_name)
            || is_reserved_tool_name(&exe_name)
        {
            return Ok(None);
        }
        if self.owned.contains(&exe_name)
            && !looks_like_script_kind(
                str_field(entrypoint, "kind"),
                str_field(entrypoint, "status"),
            )
        {
            return Ok(None);
        }
        executable_identity(resolved, &exe_name)
    }

    /// `unwrap_local_runner`: the CLI a package runner launches.
    fn unwrap_runner(
        &self,
        command: &str,
        executable: &str,
        arguments: &[String],
    ) -> Option<RunnerInvocation> {
        let runner = runner_name(executable)?;
        let spec = runner_target(runner, arguments)?;
        let (package_name, version_spec) = match spec.rfind('@') {
            Some(index) if index > 0 => (&spec[..index], &spec[index + 1..]),
            _ => (spec, ""),
        };
        if !package_name_pattern().is_match(package_name) {
            return None;
        }
        let target = package_name.rsplit('/').next().unwrap_or(package_name);
        let local_bin = if version_spec.is_empty() {
            runner_local_bin(command, runner, arguments, self.cwd, self.ctx, false)
        } else {
            None
        };
        if local_bin.is_none() && !REGISTRY_FETCH_RUNNERS.contains(&runner) {
            // pnpm/yarn/npm only launch installed bins; without proof this is not a CLI call.
            return None;
        }
        let package_name = local_bin
            .as_ref()
            .and_then(|bin| bin.get("package_name"))
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
            .unwrap_or(package_name)
            .to_owned();
        let direct_dependency =
            local_bin.is_some() && is_direct_dependency(self.cwd, &package_name);
        Some(RunnerInvocation {
            runner,
            target: target.to_owned(),
            package_name,
            local_bin,
            direct_dependency,
        })
    }

    fn runner_identity(
        &self,
        command: &str,
        segment: &CommandSegment,
        executable: &str,
    ) -> Outcome<Option<UnlistedCliV1>> {
        let Some(invocation) = self.unwrap_runner(command, executable, &segment.arguments) else {
            return Ok(None);
        };
        let name = invocation.target;
        if is_interpreter_name(&name) || is_common_tool_name(&name) || is_reserved_tool_name(&name)
        {
            return Ok(None);
        }
        let Some(local_bin) = invocation.local_bin else {
            let source = LocalCliIdentitySourceV1::RegistryPackage {
                name: name.clone(),
                package_name: invocation.package_name,
            };
            return Ok(local_cli_identity(&source)?.map(|identity| UnlistedCliV1 {
                example_label: format!("{} {name}", invocation.runner),
                path_class: Some(REGISTRY_PACKAGE_PATH_CLASS.to_owned()),
                runner: Some(invocation.runner.to_owned()),
                ..unlisted(identity, &name, "executable", None, source)
            }));
        };
        let mut evidence = Map::new();
        for key in ["resolved_path", "content_hash", "installed_version"] {
            if let Some(value @ Value::String(_)) = local_bin.get(key) {
                evidence.insert(key.to_owned(), value.clone());
            }
        }
        if let Some(Value::Object(bin_target)) = local_bin.get("bin_target") {
            // A `.bin` shim only launches this script, so it binds the grant too.
            let hash = bin_target.get("content_hash").and_then(Value::as_str);
            evidence.insert(
                "bin_target_content_hash".to_owned(),
                Value::String(hash.unwrap_or_default().to_owned()),
            );
        }
        let source = LocalCliIdentitySourceV1::RunnerLocalBin {
            name: name.clone(),
            package_name: invocation.package_name,
            local_bin: Value::Object(evidence),
        };
        let path_class = if invocation.direct_dependency {
            "project-tool"
        } else {
            "package-store"
        };
        Ok(local_cli_identity(&source)?.map(|identity| UnlistedCliV1 {
            path_class: Some(path_class.to_owned()),
            runner: Some(invocation.runner.to_owned()),
            ..unlisted(
                identity,
                &name,
                "executable",
                nonempty(local_bin.get("resolved_path")),
                source,
            )
        }))
    }

    /// `_identity_from_segment`: a script one compound segment sources or runs.
    fn segment_identity(
        &self,
        segment: &CommandSegment,
        allow_relative: bool,
    ) -> Outcome<Option<UnlistedCliV1>> {
        if segment.path_overridden || !segment.wrapper_chain.is_empty() {
            return Ok(None);
        }
        let Some(exe) = executable_name(segment.executable.as_deref()) else {
            return Ok(None);
        };
        if SOURCE_BUILTINS.contains(&exe.as_str()) && !segment.arguments.is_empty() {
            let Some(script) = self.existing_file(&segment.arguments[0], allow_relative) else {
                return Ok(None);
            };
            return self.identify(&format!("bash {}", shlex_quote(&script)));
        }
        if SHELL_INTERPRETERS.contains(&exe.as_str()) {
            if segment
                .arguments
                .iter()
                .any(|argument| INLINE_FLAGS.contains(&argument.as_str()))
            {
                return Ok(None);
            }
            if let Some(argument) = segment.arguments.iter().find(|arg| !arg.starts_with('-')) {
                let Some(script) = self.existing_file(argument, allow_relative) else {
                    return Ok(None);
                };
                if !SHELL_SCRIPT_SUFFIXES.contains(&python_suffix(&script).to_lowercase().as_str())
                {
                    return Ok(None);
                }
                return self.identify(&format!("{exe} {}", shlex_quote(&script)));
            }
        }
        let Some(executable) = segment.executable.as_deref() else {
            return Ok(None);
        };
        if let Some(runner) = runner_name(executable) {
            // Runner bins resolve from the working directory; skip after a `cd`.
            if !allow_relative
                || !segment.environment_names.is_empty()
                || runner_target(runner, &segment.arguments).is_none()
            {
                return Ok(None);
            }
            let joined: Vec<String> = std::iter::once(executable)
                .chain(segment.arguments.iter().map(String::as_str))
                .map(shlex_quote)
                .collect();
            return self.identify(&joined.join(" "));
        }
        let Some(script) = self.existing_file(executable, allow_relative) else {
            return Ok(None);
        };
        self.identify(&shlex_quote(&script))
    }

    /// `_resolve_existing_file`: the real path of an existing regular file.
    fn existing_file(&self, value: &str, allow_relative: bool) -> Option<String> {
        let value = value.trim_matches(python_whitespace);
        if value.is_empty() {
            return None;
        }
        let home = self.ctx.home.unwrap_or(self.user_home);
        let path = match value.strip_prefix("~/") {
            Some(rest) => Path::new(home).join(rest),
            None => PathBuf::from(value),
        };
        let path = if path.is_absolute() {
            path
        } else if allow_relative {
            Path::new(self.cwd).join(path)
        } else {
            return None;
        };
        let resolved = std::fs::canonicalize(path).ok()?;
        if !resolved.is_file() {
            return None;
        }
        let resolved = resolved.into_os_string().into_string().ok()?;
        #[cfg(windows)]
        let resolved = resolved
            .strip_prefix(r"\\?\")
            .map_or(resolved.clone(), str::to_owned);
        Some(resolved)
    }
}

fn unlisted(
    identity: LocalCliIdentityV1,
    name: &str,
    kind: &str,
    source_path: Option<String>,
    identity_source: LocalCliIdentitySourceV1,
) -> UnlistedCliV1 {
    UnlistedCliV1 {
        cli_id: identity.cli_id,
        name: name.to_owned(),
        kind: kind.to_owned(),
        identity_hash: identity.identity_hash,
        example_label: name.to_owned(),
        interpreter_name: None,
        source_path,
        path_class: None,
        runner: None,
        identity_source,
    }
}

fn script_identity(
    entrypoint: &Value,
    interpreter: Option<&str>,
) -> Outcome<Option<UnlistedCliV1>> {
    if !looks_like_script_kind(
        str_field(entrypoint, "kind"),
        str_field(entrypoint, "status"),
    ) {
        return Ok(None);
    }
    let source = LocalCliIdentitySourceV1::Script {
        entrypoint: entrypoint.clone(),
    };
    let Some(identity) = local_cli_identity(&source)? else {
        return Ok(None);
    };
    let name = identity.name.clone();
    let example_label = match interpreter {
        Some(interpreter) if !interpreter.is_empty() => format!("{interpreter} {name}"),
        _ => name.clone(),
    };
    Ok(Some(UnlistedCliV1 {
        example_label,
        interpreter_name: interpreter.map(str::to_owned),
        ..unlisted(
            identity,
            &name,
            "script",
            nonempty(entrypoint.get("path")),
            source,
        )
    }))
}

fn executable_identity(executable: &Value, exe_name: &str) -> Outcome<Option<UnlistedCliV1>> {
    let source = LocalCliIdentitySourceV1::Executable {
        executable: executable.clone(),
        name: exe_name.to_owned(),
    };
    let source_path = nonempty(executable.get("path"));
    Ok(local_cli_identity(&source)?
        .map(|identity| unlisted(identity, exe_name, "executable", source_path, source)))
}

/// `runner_name`: the package runner an executable names, if any.
fn runner_name(executable: &str) -> Option<&'static str> {
    let mut base = python_path_name(&executable.replace('\\', "/")).to_lowercase();
    if base.ends_with(".cmd") || base.ends_with(".exe") {
        base.truncate(base.len() - 4);
    }
    LOCAL_BIN_RUNNERS
        .iter()
        .copied()
        .find(|runner| *runner == base)
}

/// `is_direct_dependency`: the nearest `package.json` declares the package.
fn is_direct_dependency(cwd: &str, package_name: &str) -> bool {
    for directory in Path::new(cwd).ancestors().take(MAX_MANIFEST_ANCESTORS) {
        match read_manifest(&directory.join("package.json").to_string_lossy()) {
            Manifest::Absent => {}
            Manifest::Data(Value::Object(manifest)) => {
                return DEPENDENCY_SECTIONS.iter().any(|section| {
                    matches!(manifest.get(*section), Some(Value::Object(deps)) if deps.contains_key(package_name))
                });
            }
            _ => return false,
        }
    }
    false
}

fn looks_like_script_kind(kind: &str, status: &str) -> bool {
    if status != "verified" || PACKAGE_SCRIPT_KINDS.contains(&kind) || INLINE_KINDS.contains(&kind)
    {
        return false;
    }
    kind.ends_with("-script") || kind == "direct-script"
}

fn strip_windows_suffix(name: &str) -> String {
    let mut base = name.to_lowercase();
    if base.ends_with(".exe") || base.ends_with(".cmd") {
        base.truncate(base.len() - 4);
    }
    base
}

fn is_interpreter_name(name: &str) -> bool {
    let base = strip_windows_suffix(name);
    INTERPRETER_NAMES.contains(&base.as_str()) || base.starts_with("python3.")
}

fn is_reserved_tool_name(name: &str) -> bool {
    RESERVED_TOOL_NAMES
        .contains(&strip_windows_suffix(name.trim_matches(python_whitespace)).as_str())
}

fn str_field<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or_default()
}

fn nonempty(value: Option<&Value>) -> Option<String> {
    let stripped = value?.as_str()?.trim_matches(python_whitespace);
    (!stripped.is_empty()).then(|| stripped.to_owned())
}

/// `PurePath.suffix`.
fn python_suffix(path: &str) -> String {
    let name = python_path_name(path);
    match name.rfind('.') {
        Some(index) if index > 0 && index < name.len() - 1 => name[index..].to_owned(),
        _ => String::new(),
    }
}

/// `shlex.quote`.
fn shlex_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".to_owned();
    }
    if value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "_@%+=:,./-".contains(c))
    {
        return value.to_owned();
    }
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

#[derive(Deserialize)]
struct ProgramExecutables {
    extensions: Vec<ExtensionExecutables>,
    rules: Vec<RuleExecutables>,
}

#[derive(Deserialize)]
struct ExtensionExecutables {
    executables: Vec<String>,
}

#[derive(Deserialize)]
struct RuleExecutables {
    #[serde(default)]
    candidate_executables: Vec<String>,
}

/// Lowercase executable names the packaged built-in extensions already own.
fn owned_executables() -> Outcome<&'static HashSet<String>> {
    static OWNED: OnceLock<Option<HashSet<String>>> = OnceLock::new();
    OWNED
        .get_or_init(|| {
            let bytes = guard_command::native_command_program::packaged_command_program_bytes();
            let program: ProgramExecutables = serde_json::from_slice(bytes).ok()?;
            let extension_names = program.extensions.into_iter().flat_map(|e| e.executables);
            let rule_names = program
                .rules
                .into_iter()
                .flat_map(|rule| rule.candidate_executables);
            Some(
                extension_names
                    .chain(rule_names)
                    .map(|name| name.trim_matches(python_whitespace).to_lowercase())
                    .filter(|name| !name.is_empty())
                    .collect(),
            )
        })
        .as_ref()
        .ok_or(PROGRAM_UNAVAILABLE)
}

#[cfg(test)]
#[path = "local_cli_identify_tests.rs"]
mod tests;

/// `command_tokens.executable_name`: basename after `\\` → `/`, lowercased.
fn executable_name(value: Option<&str>) -> Option<String> {
    let value = value?.replace('\\', "/");
    Some(value.rsplit('/').next().unwrap_or("").to_lowercase())
}
