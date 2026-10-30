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
//! sandbox with a private home and temporary directory. This replays those
//! steps for the plain shape, a call with no wrapper or directory change in
//! front of the program, and for one with settings in front: the call as
//! issued draws the receipt and the plain run behind the settings runs with
//! the inert ones carried. The edge routes nothing else here. On Linux it
//! runs the Python runs only (`backend`).
//!
//! Rust owns every verdict: the resident's receipts, the operations' plan.

use serde::Deserialize;

use super::program::{carried_program, plain_program, Carried, Kind, Program};
use super::*;

#[path = "contained_readonly_backend.rs"]
mod backend;

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
    response
        .as_object()
        .and_then(readonly_route)
        .is_some_and(backend::host_runs)
        && plain_call(response, original)
}

fn plain_call(response: &Value, original: &Map<String, Value>) -> bool {
    let Some(route) = response.as_object().and_then(readonly_route) else {
        return false;
    };
    !original.contains_key("cwd")
        && original
            .get("command")
            .and_then(Value::as_str)
            .and_then(program)
            .is_some_and(|(_, (_, _, kind))| kind == Kind::of(route))
}

/// The read-only run `command` starts, with the settings carried in front
/// of it when there are any.
fn program(command: &str) -> Option<(Option<Carried>, Program)> {
    match plain_program(command) {
        Some(program) => Some((None, program)),
        None => carried_program(command).map(|(carried, program)| (Some(carried), program)),
    }
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
    /// The inert settings carried in front of the program, exported to the
    /// run's source environment before the native filter reads it.
    #[serde(skip)]
    pub(super) settings: Vec<(String, String)>,
}

/// Run the read-only call `route` names for `payload` in `workspace`.
pub(super) fn run(
    payload: &Map<String, Value>,
    workspace: &Path,
    authority: &Authority<'_>,
    route: Route,
    signals: &process::Signals,
) -> Outcome<i32> {
    if !backend::host_runs(route) {
        return Err(Failure::unauthorized());
    }
    let command = payload
        .get("tool_input")
        .and_then(|input| input.get("command"))
        .and_then(Value::as_str)
        .ok_or_else(|| Failure::invalid("Invalid restricted execution request."))?;
    let (carried, (mut argv, seconds, mut kind)) =
        program(command).ok_or_else(Failure::unauthorized)?;
    if kind != Kind::of(route) {
        return Err(Failure::unauthorized());
    }
    // Settings in front of the program: like a wrapper, the call as issued
    // draws the receipt, then the command behind them is asked and run as
    // the plain run it is, with the inert settings carried into its
    // environment.
    let behind;
    let (payload, settings) = match carried {
        Some(Carried {
            settings,
            behind: words,
        }) => {
            authorize_route(authority, payload, route)?;
            behind = with_command(payload, &words, None);
            (&behind, settings)
        }
        None => (payload, Vec::new()),
    };
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
    plan.settings = settings;
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
        || HOST_BACKEND != Some(plan.backend.as_str())
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
        &plan.settings,
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
    let backend = backend::argv(plan, private)?;
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

#[path = "contained_readonly_write_denial.rs"]
mod write_denial;
pub(super) use write_denial::names_denied_write;

#[cfg(test)]
#[path = "contained_readonly_sink_tests.rs"]
mod tests;
