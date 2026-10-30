//! The native sink for a read-only run: an evaluation (`python -c`, `node
//! -e`, `bun -e`), a Vitest run, a `node --test` run, a package manager's own
//! test script, a local lint, typecheck or build tool, a Git inspection or a
//! pytest run the resident sent to its own profile. A build writes only the
//! directory its plan names; a package test runs as the runner it spells.
//!
//! Guard's own sink runs such a call in three steps: it reads the program
//! the command stands behind, plans the run, and asks the live resident
//! again — for the call as issued and, except for Git and pytest, for the
//! planned argv — before it starts the planned argv under a read-only
//! Seatbelt profile with a private home and temporary directory. This replays those steps for the plain
//! shape, a call with no settings, wrapper or directory change in front of
//! the program: the edge routes nothing else here. Linux keeps Guard's own
//! sink, whose read-only namespace this does not build.
//!
//! Rust owns every verdict: the resident's receipts, the operations' plan.

use serde::Deserialize;

use super::program::{plain_program, Kind};
use super::*;

/// The read-only routes: the reason the resident gives and the profile it
/// requires.
pub(super) type Route = (&'static str, &'static str);

const ROUTES: [Route; 10] = [
    (
        "native_python_eval_readonly_containment_required",
        PYTHON_EVAL_PROFILE,
    ),
    (
        "native_node_eval_readonly_containment_required",
        NODE_EVAL_PROFILE,
    ),
    (
        "native_bun_eval_readonly_containment_required",
        NODE_EVAL_PROFILE,
    ),
    VITEST_ROUTE,
    (
        "native_node_test_readonly_containment_required",
        NODE_TEST_PROFILE,
    ),
    ("native_git_readonly_containment_required", GIT_PROFILE),
    (
        "native_pytest_readonly_containment_required",
        PYTEST_PROFILE,
    ),
    (
        "native_node_tool_readonly_containment_required",
        NODE_TOOL_PROFILE,
    ),
    (
        "native_node_build_output_containment_required",
        NODE_BUILD_PROFILE,
    ),
    (
        "native_package_test_readonly_containment_required",
        PACKAGE_PROFILE,
    ),
];
pub(super) const VITEST_ROUTE: Route = (
    "native_vitest_readonly_containment_required",
    VITEST_PROFILE,
);
const PYTHON_EVAL_PROFILE: &str = "python-eval-readonly-v1";
const NODE_EVAL_PROFILE: &str = "node-eval-readonly-v1";
pub(super) const VITEST_PROFILE: &str = "vitest-readonly-v1";
const NODE_TEST_PROFILE: &str = "node-test-readonly-v1";
const GIT_PROFILE: &str = "git-readonly-v1";
const PYTEST_PROFILE: &str = "pytest-readonly-v2";
const NODE_TOOL_PROFILE: &str = "node-tool-readonly-v1";
const NODE_BUILD_PROFILE: &str = "node-build-output-v1";
const PACKAGE_PROFILE: &str = "package-test-readonly-v1";
const SEATBELT: &str = "macos-seatbelt";
const INVALID_PLAN: &str = "Invalid native restricted launch plan.";

impl Kind {
    fn of(route: Route) -> Self {
        match route.1 {
            VITEST_PROFILE => Self::Vitest,
            NODE_TEST_PROFILE => Self::NodeTest,
            GIT_PROFILE => Self::Git,
            PYTEST_PROFILE => Self::Pytest,
            NODE_TOOL_PROFILE | NODE_BUILD_PROFILE => Self::NodeTool,
            PACKAGE_PROFILE => Self::Package,
            _ => Self::Eval,
        }
    }
}

/// The read-only route `response` requires: a live denial that sends the
/// call to one of these profiles.
pub(crate) fn readonly_route(response: &Map<String, Value>) -> Option<Route> {
    let text = |name: &str| response.get(name).and_then(Value::as_str);
    if text("decision") != Some("deny")
        || text("policy_action") != Some("sandbox-required")
        || response.get("observe_mode") == Some(&Value::Bool(true))
    {
        return None;
    }
    ROUTES.into_iter().find(|(reason, profile)| {
        text("reason_code") == Some(reason) && text("required_execution_profile") == Some(profile)
    })
}

/// Whether the native sink runs this call: a read-only run of the plain
/// shape and of the kind its route names, on the host whose sandbox it
/// builds, with no `cwd` argument for Guard's own sink to turn into a
/// directory change.
pub(crate) fn readonly_shape(response: &Value, original: &Map<String, Value>) -> bool {
    HOST_BACKEND == Some(SEATBELT) && plain_call(response, original)
}

fn plain_call(response: &Value, original: &Map<String, Value>) -> bool {
    let Some(route) = response.as_object().and_then(readonly_route) else {
        return false;
    };
    !original.contains_key("cwd")
        && original
            .get("command")
            .and_then(Value::as_str)
            .and_then(plain_program)
            .is_some_and(|(_, _, kind)| kind == Kind::of(route))
}

/// A profile-bound plan, field for field what the planner answers.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReadonlyPlan {
    pub(super) profile_version: String,
    backend: String,
    backend_executable: String,
    pub(super) workspace: String,
    pub(super) cwd: String,
    executable: String,
    pub(super) command: Vec<String>,
    pub(super) allowed_executables: Vec<String>,
    #[serde(default)]
    read_only_roots: Vec<String>,
    #[serde(default)]
    pub(super) output_roots: Vec<String>,
    #[allow(dead_code)]
    denied_capabilities: Vec<String>,
    /// The account's own Python packages, linked into a pytest run's
    /// private home for reading.
    #[serde(skip)]
    user_site_root: Option<String>,
}

/// Run the read-only call `route` names for `payload` in `workspace`.
pub(super) fn run(
    payload: &Map<String, Value>,
    workspace: &Path,
    authority: &Authority<'_>,
    route: Route,
    signals: &process::Signals,
) -> Outcome<i32> {
    if HOST_BACKEND != Some(SEATBELT) {
        return Err(Failure::unauthorized());
    }
    let command = payload
        .get("tool_input")
        .and_then(|input| input.get("command"))
        .and_then(Value::as_str)
        .ok_or_else(|| Failure::invalid("Invalid restricted execution request."))?;
    let (mut argv, seconds, mut kind) = plain_program(command).ok_or_else(Failure::unauthorized)?;
    if kind != Kind::of(route) {
        return Err(Failure::unauthorized());
    }
    // A package test runs as the runner its script spells, under that
    // runner's route once the call as issued names the package route again.
    let package = kind == Kind::Package;
    if package {
        (argv, kind) = super::program::package_test(&argv, workspace)?;
    }
    let timeout = seconds.map_or(RUN_TIMEOUT_SECONDS, |seconds| {
        seconds.min(RUN_TIMEOUT_SECONDS)
    });
    let home = &authority.arguments.home;
    let (operation, profile) = match kind {
        Kind::Eval => ("prepare_inline", None),
        Kind::Vitest => ("prepare_vitest", Some(VITEST_PROFILE)),
        Kind::NodeTest => ("prepare_node", Some(NODE_TEST_PROFILE)),
        Kind::Git => ("prepare_git", Some(GIT_PROFILE)),
        Kind::Pytest => ("prepare", Some(PYTEST_PROFILE)),
        Kind::NodeTool => ("prepare_node_tool", Some(route.1)),
        Kind::Package => return Err(Failure::unauthorized()),
    };
    let mut plan = prepare(operation, &argv, workspace, home)?;
    if profile.is_some_and(|profile| plan.profile_version != profile) {
        return Err(Failure::new(SANDBOX_UNAVAILABLE, INVALID_PLAN));
    }
    let underlying;
    let (payload, route) = if package {
        authorize_route(authority, payload, route)?;
        underlying = with_command(payload, &argv, None);
        let route = if kind == Kind::Vitest {
            VITEST_ROUTE
        } else {
            ROUTES[4]
        };
        (&underlying, route)
    } else {
        (payload, route)
    };
    match kind {
        Kind::Vitest => {
            return super::vitest::run(payload, workspace, authority, plan, timeout, signals)
        }
        Kind::Eval if (reason_for(&plan, &argv), plan.profile_version.as_str()) != route => {
            return Err(Failure::unauthorized());
        }
        _ => {}
    }
    // Asked again after planning, so the decision follows every file the
    // planner read; then for the argv the plan runs. Guard's own sink asks
    // nothing more for a Git inspection, whose plan proves its executable,
    // or for pytest, whose planner admits only a pytest executable.
    authorize_route(authority, payload, route)?;
    if !matches!(kind, Kind::Git | Kind::Pytest) {
        authorize_route(
            authority,
            &with_command(payload, &plan.command, None),
            route,
        )?;
    }
    if plan.profile_version == NODE_BUILD_PROFILE {
        return super::node_build::run(payload, workspace, authority, plan, timeout, signals);
    }
    let private = private_root()?;
    signals.clean_up(private.path.clone());
    if kind == Kind::Pytest {
        plan.user_site_root = super::pytest::link_user_site(&private.path)?;
    }
    let mut environment = environment(&plan, &private)?;
    match kind {
        Kind::Eval => {
            environment.insert("PYTHONDONTWRITEBYTECODE".into(), "1".into());
        }
        Kind::NodeTest | Kind::NodeTool => {
            // Node preloads and search paths from the host are not
            // repository test input.
            environment.remove("NODE_OPTIONS");
            environment.remove("NODE_PATH");
        }
        Kind::Git => {
            environment.remove("PYTHONPATH");
            environment.remove("VIRTUAL_ENV");
            let source = json!({ "source": environment });
            environment = serde_json::from_value(native("git_environment", source)?)
                .map_err(|_| unavailable("invalid_reply"))?;
        }
        Kind::Pytest => super::pytest::settle(&mut environment, &private.path)?,
        Kind::Vitest | Kind::Package => {}
    }
    launch(
        &plan,
        &private,
        &environment,
        signals,
        timeout,
        process::Notes::Silent,
    )
}

/// `payload` for `command`, asked from `cwd` when one is given.
pub(super) fn with_command(
    payload: &Map<String, Value>,
    command: &[String],
    cwd: Option<&str>,
) -> Map<String, Value> {
    let mut tool_input = payload
        .get("tool_input")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    tool_input.insert(
        "command".to_owned(),
        Value::String(crate::mcp_proxy_shlex::join(command)),
    );
    let mut asked = payload.clone();
    asked.insert("tool_input".to_owned(), Value::Object(tool_input));
    if let Some(cwd) = cwd {
        asked.insert("cwd".to_owned(), Value::String(cwd.to_owned()));
    }
    asked
}

/// The resident's receipt for `asked`, which must name `route` again.
pub(super) fn authorize_route(
    authority: &Authority<'_>,
    asked: &Map<String, Value>,
    route: Route,
) -> Outcome<Map<String, Value>> {
    let receipt = authority
        .authorize(asked)
        .ok_or_else(Failure::unauthorized)?;
    if readonly_route(&receipt) != Some(route) {
        return Err(Failure::unauthorized());
    }
    Ok(receipt)
}

/// The planner's answer for `argv`, checked as Guard's own sink checks it.
fn prepare(
    operation: &str,
    argv: &[String],
    workspace: &Path,
    home: &Path,
) -> Outcome<ReadonlyPlan> {
    let mut command = argv.to_vec();
    if command[0].starts_with('~') {
        command[0] = py_normal(&expand_user(&command[0]));
    }
    let workspace = path_text(workspace)?;
    let mut input = json!({
        "command": command,
        "workspace": workspace,
        "cwd": workspace,
        "home": wire_path(home),
        "platform": HOST_PLATFORM,
        "backend_executable": null,
    });
    if operation == "prepare_git" {
        // Git's trust proof reads the account's home and groups.
        let account = crate::claude_hook_bridge::home_directory()
            .ok_or_else(|| unavailable("account_home"))?;
        let mut groups = crate::edge_git_push::groups().ok_or_else(|| unavailable("groups"))?;
        groups.sort_unstable();
        input["account_home"] = json!(wire_path(&account));
        input["groups"] = json!(groups);
    }
    if operation == "prepare" {
        input["read_only_workspace"] = Value::Bool(true);
    }
    let plan = native(operation, input)?;
    let plan: ReadonlyPlan = serde_json::from_value(plan)
        .map_err(|_| Failure::new(SANDBOX_UNAVAILABLE, INVALID_PLAN))?;
    if !ROUTES
        .iter()
        .any(|(_, profile)| *profile == plan.profile_version)
        || plan.backend != SEATBELT
        || plan.command.is_empty()
        || !plan.allowed_executables.contains(&plan.executable)
        || plan.output_roots.is_empty() == (plan.profile_version == NODE_BUILD_PROFILE)
    {
        return Err(Failure::new(SANDBOX_UNAVAILABLE, INVALID_PLAN));
    }
    Ok(plan)
}

/// The reason Guard's own sink expects for `plan` of `argv`: Bun's own for
/// a Node evaluation the command runs with Bun.
fn reason_for(plan: &ReadonlyPlan, argv: &[String]) -> &'static str {
    let bun = argv
        .first()
        .and_then(|program| Path::new(program).file_name())
        .is_some_and(|name| name == "bun");
    match plan.profile_version.as_str() {
        NODE_EVAL_PROFILE if bun => ROUTES[2].0,
        NODE_EVAL_PROFILE => ROUTES[1].0,
        _ => ROUTES[0].0,
    }
}

/// A private home and temporary directory that go when the run ends.
pub(super) fn private_root() -> Outcome<PrivateRoot> {
    PrivateRoot::create().ok_or_else(|| {
        Failure::new(
            SANDBOX_UNAVAILABLE,
            "The read-only sandbox directory is unavailable.",
        )
    })
}

/// The environment the native filter leaves `plan`'s run.
pub(super) fn environment(
    plan: &ReadonlyPlan,
    private: &PrivateRoot,
) -> Outcome<BTreeMap<String, String>> {
    runner::restricted_environment(
        &plan.workspace,
        &plan.cwd,
        &path_text(&private.path)?,
        &plan.allowed_executables,
        plan.user_site_root.as_deref(),
    )
}

/// Start `plan`'s argv under its read-only profile.
pub(super) fn launch(
    plan: &ReadonlyPlan,
    private: &PrivateRoot,
    environment: &BTreeMap<String, String>,
    signals: &process::Signals,
    timeout: u64,
    notes: process::Notes<'_>,
) -> Outcome<i32> {
    let profile = native(
        "macos_profile",
        json!({
            "profile_version": plan.profile_version,
            "workspace": plan.workspace,
            "cwd": plan.cwd,
            "allowed_executables": plan.allowed_executables,
            "read_only_roots": plan.read_only_roots,
            "output_roots": plan.output_roots,
            "command": plan.command,
            "backend_executable": plan.backend_executable,
            "private_root": path_text(&private.path)?,
            "user_site_root": plan.user_site_root,
        }),
    )?;
    let Value::String(profile) = profile else {
        return Err(unavailable("invalid_reply"));
    };
    let mut backend = vec![
        plan.backend_executable.clone(),
        "-p".to_owned(),
        profile,
        "--".to_owned(),
    ];
    backend.extend(plan.command.iter().cloned());
    process::run_backend(
        &backend,
        environment,
        Path::new(&plan.cwd),
        &private.path,
        signals,
        timeout,
        notes,
    )
}

/// Words a denied write leaves in a program's output.
const WRITE_DENIAL_MARKERS: [&[u8]; 4] = [
    b"eperm",
    b"erofs",
    b"operation not permitted",
    b"read-only file system",
];

/// Whether a run's output names a write the read-only profile denied, as a
/// word of its own.
pub(super) fn names_denied_write(outputs: &[&[u8]]) -> bool {
    outputs.iter().any(|output| {
        let lowered = output.to_ascii_lowercase();
        WRITE_DENIAL_MARKERS.iter().any(|marker| {
            lowered
                .windows(marker.len())
                .enumerate()
                .any(|(start, window)| {
                    window == *marker
                        && !word_byte(start.checked_sub(1).map(|at| lowered[at]))
                        && !word_byte(lowered.get(start + marker.len()).copied())
                })
        })
    })
}

/// Whether `byte` would continue a word, so a marker beside it is only part
/// of a longer name such as `filePermissions`.
fn word_byte(byte: Option<u8>) -> bool {
    byte.is_some_and(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

#[cfg(test)]
#[path = "contained_readonly_sink_tests.rs"]
mod tests;
