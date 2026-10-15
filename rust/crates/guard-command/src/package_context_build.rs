//! Build side of the package execution context.
//!
//! Port of the retired `package_execution_context.py::build_package_execution_context`
//! and its `_inputs` / `_configuration` helpers. The resident reads the
//! repository, executable, dependency and configuration inputs itself (the
//! client only supplies the process facts it used to read from its interpreter)
//! and returns the same component digests the Python builder produced.
//!
//! Every digest and every native projection goes through [`Ports`], the seam the
//! parity replay (`tests/package_context_vectors.rs`) uses to compare the ordered
//! hook calls against vectors recorded from the Python implementation.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::codex_output_py::{py_strip, PyPath};
use crate::hook_adapter_value::{OMap, OValue};
use crate::package_execution_context::{
    PackageExecutionContextComponent, PACKAGE_EXECUTION_CONTEXT_VERSION,
};

mod configuration;
mod configuration_names;
mod dependency;
mod executable;
mod fs;
mod ports;
mod repository;

pub use ports::{NativePorts, Ports};

use fs::{ContextFiles, Fs, ResolveError};

const SUPPORTED_PORTABLE_MANAGERS: &[&str] = &[
    "bun", "bunx", "bundle", "bundler", "cargo", "composer", "gem", "go", "gradle", "gradlew",
    "mvn", "mvnw", "npm", "npx", "pip", "pip3", "pipenv", "pipx", "pnpm", "poetry", "uv", "uvx",
    "yarn",
];

/// Why a build stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildError {
    /// The Python code let an unexpected exception escape: the whole build
    /// fails closed instead of producing a context.
    Fatal(String),
    /// `ContextUnavailableError`: a portable context cannot be proven.
    Unavailable(&'static str),
}

pub(crate) type Built<T> = Result<T, BuildError>;

/// The request facts of one build. The process facts stand in for the client
/// interpreter state the Python builder read implicitly.
#[derive(Debug, Clone)]
pub struct BuildInput<'a> {
    pub workspace_dir: &'a str,
    pub metadata: &'a serde_json::Map<String, Value>,
    pub executable: Option<&'a str>,
    pub executable_args: &'a [String],
    pub environment: &'a BTreeMap<String, String>,
    pub process_cwd: &'a str,
    pub process_home: &'a str,
    pub process_home_env: Option<&'a str>,
    pub process_path: Option<&'a str>,
}

/// `PackageExecutionContext` without the evidence projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltContext {
    pub digest: String,
    pub portable: bool,
    pub components: Vec<PackageExecutionContextComponent>,
    pub non_portable_reason: Option<String>,
}

pub(crate) fn text(value: &str) -> OValue {
    OValue::Str(value.to_owned())
}

pub(crate) fn object(pairs: Vec<(&str, OValue)>) -> OValue {
    let mut map = OMap::new();
    for (key, value) in pairs {
        map.insert(key, value);
    }
    OValue::Map(map)
}

/// `_string_value`: stripped, non-empty strings only.
pub(crate) fn string_value(value: Option<&Value>) -> Option<String> {
    let stripped = py_strip(value?.as_str()?);
    (!stripped.is_empty()).then(|| stripped.to_owned())
}

/// `_string_items`: stripped non-empty strings of a list.
pub(crate) fn string_items(value: Option<&Value>) -> Vec<String> {
    let Some(Value::Array(items)) = value else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| item.as_str())
        .map(py_strip)
        .filter(|item| !item.is_empty())
        .map(str::to_owned)
        .collect()
}

fn is_global_request(metadata: &serde_json::Map<String, Value>) -> bool {
    string_items(metadata.get("flags")).iter().any(|flag| {
        matches!(flag.as_str(), "-g" | "--global" | "--location=global")
            || flag.starts_with("--global=")
    })
}

fn component(
    ports: &mut dyn Ports,
    name: &str,
    material: &OValue,
) -> PackageExecutionContextComponent {
    PackageExecutionContextComponent {
        name: name.to_owned(),
        digest: ports.digest_material(&material.canonical_json()),
    }
}

fn resolve_workspace(fs: &Fs, workspace_dir: &str) -> Built<String> {
    let expanded = fs.expanduser(workspace_dir)?;
    fs.resolve(&expanded, false).map_err(|error| match error {
        ResolveError::Os | ResolveError::Loop(_) => error.into_fatal(workspace_dir),
    })
}

/// Build the context with the production native ports.
pub fn build_package_execution_context(input: &BuildInput<'_>) -> Result<BuiltContext, BuildError> {
    build_with_ports(input, &mut NativePorts)
}

/// Build the context over an explicit port set (the parity replay uses this).
pub fn build_with_ports(
    input: &BuildInput<'_>,
    ports: &mut dyn Ports,
) -> Result<BuiltContext, BuildError> {
    let fs = Fs::new(
        input.process_cwd,
        input.process_home,
        input.process_home_env,
    );
    let workspace = resolve_workspace(&fs, input.workspace_dir)?;
    let metadata = input.metadata;
    let manager =
        string_value(metadata.get("package_manager")).unwrap_or_else(|| "unknown".to_owned());
    let mut files = ContextFiles::default();
    let mut components: Vec<PackageExecutionContextComponent> = Vec::new();
    let mut first_failure: Option<String> = None;

    let repository = repository::repository_material(&fs, &mut files, &workspace)?;
    if let Some(reason) = repository.failure {
        first_failure = Some(reason.to_owned());
    }
    components.push(component(
        ports,
        "repository_identity",
        &repository.material,
    ));
    let workspace_identity = repository::workspace_material(
        &workspace,
        repository.root.as_deref(),
        repository.failure.is_none(),
    );
    components.push(component(ports, "workspace_identity", &workspace_identity));

    if !SUPPORTED_PORTABLE_MANAGERS.contains(&manager.as_str()) {
        first_failure = first_failure.or_else(|| Some("unsupported_package_manager".to_owned()));
    }
    if is_global_request(metadata) {
        first_failure = first_failure.or_else(|| Some("global_package_request".to_owned()));
    }

    let requested_executable = input
        .executable
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .or_else(|| string_value(metadata.get("package_executable")));
    let executable_input = executable::ExecutableInput {
        workspace: &workspace,
        repository_root: repository.root.as_deref(),
        manager: &manager,
        executable: requested_executable.as_deref(),
        arguments: input.executable_args,
        environment: input.environment,
        fallback_path: input.process_path,
    };
    let (executable_identity, executable_failure) =
        executable::executable_material(&fs, &mut files, ports, &executable_input)?;
    if let Some(reason) = executable_failure {
        first_failure = first_failure.or_else(|| Some(reason.to_owned()));
    }
    components.push(component(
        ports,
        "package_manager_executable",
        &executable_identity,
    ));

    let (dependency_identity, dependency_failure) =
        dependency::dependency_material(&fs, &mut files, &workspace, metadata)?;
    if let Some(reason) = dependency_failure {
        first_failure = first_failure.or_else(|| Some(reason.to_owned()));
    }
    components.push(component(
        ports,
        "manifests_and_lockfiles",
        &dependency_identity,
    ));

    let configuration = match configuration::configuration_material(
        &fs,
        &mut files,
        ports,
        &configuration::ConfigurationInput {
            workspace: &workspace,
            repository_root: repository.root.as_deref(),
            manager: &manager,
            environment: input.environment,
        },
    ) {
        Ok(configuration) => configuration,
        Err(BuildError::Unavailable(reason)) => {
            first_failure = first_failure.or_else(|| Some(reason.to_owned()));
            configuration::Configuration::unavailable(reason)
        }
        Err(fatal) => return Err(fatal),
    };
    components.push(component(
        ports,
        "registry_and_proxy_configuration",
        &configuration.registry,
    ));
    components.push(component(
        ports,
        "workspace_configuration",
        &configuration.workspace,
    ));
    components.push(component(
        ports,
        "lifecycle_hooks_overrides_and_patches",
        &configuration.hooks,
    ));

    let values =
        ports.environment_values(&manager, input.environment, &configuration.referenced)?;
    let mut variables = OMap::new();
    for (name, value) in values {
        variables.insert(&name, value.map_or(OValue::Null, OValue::Str));
    }
    let environment_identity = object(vec![("variables", OValue::Map(variables))]);
    components.push(component(
        ports,
        "environment_policy",
        &environment_identity,
    ));

    let portable = first_failure.is_none();
    if !portable {
        components.push(component(
            ports,
            "exact_workspace",
            &object(vec![("path", text(&workspace))]),
        ));
    }
    let listing = OValue::List(
        components
            .iter()
            .map(|item| {
                object(vec![
                    ("digest", text(&item.digest)),
                    ("name", text(&item.name)),
                ])
            })
            .collect(),
    );
    let summary = object(vec![
        ("components", listing),
        ("portable", OValue::Bool(portable)),
        (
            "version",
            OValue::Int(PACKAGE_EXECUTION_CONTEXT_VERSION.to_string()),
        ),
    ]);
    let digest = ports.digest_material(&summary.canonical_json());
    Ok(BuiltContext {
        digest,
        portable,
        components,
        non_portable_reason: first_failure,
    })
}

/// `Path.name` of an arbitrary string.
pub(crate) fn path_name(path: &str) -> String {
    PyPath::new(path).name().to_owned()
}
