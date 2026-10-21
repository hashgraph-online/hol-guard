//! Native hooks the build calls: digests, environment projection and launch
//! identity. Production uses the in-process implementations; the parity replay
//! substitutes recorded answers and checks the ordered call log.

use std::collections::BTreeMap;
use std::path::Path;

use crate::launch_identity_common::sha256_hex;
use serde_json::{Map, Value};

use crate::launch_identity::{build_runtime_launch_identity, runtime_launch_identity_is_reusable};
use crate::package_context_environment::environment_policy_values;

use super::Built;

/// The seam between the pure build and the native projections it depends on.
pub trait Ports {
    /// `context_sha256_digest`: digest of an already canonical JSON text.
    fn digest_material(&mut self, canonical_text: &str) -> String;
    /// `context_opaque_digest`: digest of raw UTF-8 material.
    fn opaque_digest(&mut self, material: &str) -> String;
    /// `context_package_environment_values`.
    fn environment_values(
        &mut self,
        manager: &str,
        environment: &BTreeMap<String, String>,
        referenced_names: &[String],
    ) -> Built<BTreeMap<String, Option<String>>>;
    /// `build_runtime_launch_identity` with a structured, direct executable.
    fn launch_identity(
        &mut self,
        requested: &str,
        arguments: &[String],
        search_path: Option<&str>,
        cwd: &str,
        environment: &BTreeMap<String, String>,
    ) -> Value;
    /// `runtime_launch_identity_is_reusable`.
    fn launch_identity_reusable(&mut self, identity: &Value) -> bool;
}

/// Production ports.
pub struct NativePorts;

impl Ports for NativePorts {
    fn digest_material(&mut self, canonical_text: &str) -> String {
        sha256_hex(canonical_text.as_bytes())
    }

    fn opaque_digest(&mut self, material: &str) -> String {
        sha256_hex(material.as_bytes())
    }

    fn environment_values(
        &mut self,
        manager: &str,
        environment: &BTreeMap<String, String>,
        referenced_names: &[String],
    ) -> Built<BTreeMap<String, Option<String>>> {
        Ok(environment_policy_values(
            manager,
            environment,
            referenced_names,
        ))
    }

    fn launch_identity(
        &mut self,
        requested: &str,
        arguments: &[String],
        search_path: Option<&str>,
        cwd: &str,
        environment: &BTreeMap<String, String>,
    ) -> Value {
        let args: Vec<Value> = arguments.iter().cloned().map(Value::String).collect();
        let env: Map<String, Value> = environment
            .iter()
            .map(|(key, value)| (key.clone(), Value::String(value.clone())))
            .collect();
        build_runtime_launch_identity(
            &Value::String(requested.to_owned()),
            &args,
            true,
            true,
            search_path,
            Some(Path::new(cwd)),
            None,
            Some(&Value::Object(env)),
        )
    }

    fn launch_identity_reusable(&mut self, identity: &Value) -> bool {
        runtime_launch_identity_is_reusable(identity)
    }
}
