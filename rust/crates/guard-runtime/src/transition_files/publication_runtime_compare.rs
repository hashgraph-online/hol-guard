//! The comparisons of a read-only native-runtime inspection, ported from
//! `inspect_codex_repair_native_runtime`.
//!
//! The caller locates and spawns the runtime and sends what it saw as facts;
//! the runtime decides whether the probe succeeded, whether the runtime's own
//! capabilities match the bundled manifest and the package, and whether the
//! executable's generation changed while it was inspected.

use serde_json::Value;

use super::publication::Call;
use super::python_equal::python_equal;
use super::{Fault, Step};

const INSPECTION_FAILED: Fault = Fault::Transition("authority_repair_native_inspection_failed");
const PROTOCOL: Fault = Fault::Transition("native_protocol_mismatch");
const MANIFEST: Fault = Fault::Transition("native_manifest_capabilities_mismatch");
const VERSION: Fault = Fault::Transition("native_version_mismatch");
const GENERATION: Fault = Fault::Transition("native_runtime_generation_changed");

fn field<'a>(value: Option<&'a Value>, key: &str) -> Option<&'a Value> {
    value
        .and_then(Value::as_object)
        .and_then(|map| map.get(key))
}

fn differs(left: Option<&Value>, right: Option<&Value>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => !python_equal(left, right),
        _ => true,
    }
}

fn truthy(call: &Call<'_>, key: &str) -> bool {
    !matches!(
        call.args.get(key),
        None | Some(Value::Null) | Some(Value::Bool(false))
    )
}

/// `publication_runtime_compare`, by `stage`:
/// - `probe`: `returncode`, `timed_out`, `containment_failed` and
///   `output_limit_exceeded` of the capabilities probe; anything but a clean
///   zero exit is `authority_repair_native_inspection_failed`.
/// - `capabilities`: the decoded `capabilities` (`protocol_version`,
///   `runtime_version`, `rule_digest`, `build_sha`, or null) must carry the
///   expected `protocol`, and match the bundled `manifest`
///   (`package_version`, `rule_digest`, `source_sha`) when there is one.
/// - `version`: in `auto` `mode` a runtime whose version differs from the
///   installed package's `version` (when known) is refused.
/// - `generation`: the `before` and `after` stat tuples must be equal, and
///   `after` must exist.
pub(super) fn compare_op(call: &mut Call<'_>) -> Step<Value> {
    match call.text("stage")? {
        "probe" => {
            let clean = call.args.get("returncode").and_then(Value::as_i64) == Some(0)
                && !truthy(call, "timed_out")
                && !truthy(call, "containment_failed")
                && !truthy(call, "output_limit_exceeded");
            if clean {
                Ok(Value::Null)
            } else {
                Err(INSPECTION_FAILED)
            }
        }
        "capabilities" => {
            let capabilities = call
                .args
                .get("capabilities")
                .filter(|value| !value.is_null());
            let capabilities = capabilities.ok_or(PROTOCOL)?;
            if differs(
                field(Some(capabilities), "protocol_version"),
                call.args.get("protocol"),
            ) {
                return Err(PROTOCOL);
            }
            let manifest = call.args.get("manifest").filter(|value| !value.is_null());
            if let Some(manifest) = manifest {
                let pairs = [
                    ("runtime_version", "package_version"),
                    ("rule_digest", "rule_digest"),
                    ("build_sha", "source_sha"),
                ];
                if pairs.iter().any(|(left, right)| {
                    differs(
                        field(Some(capabilities), left),
                        field(Some(manifest), right),
                    )
                }) {
                    return Err(MANIFEST);
                }
            }
            Ok(Value::Null)
        }
        "version" => {
            let known = call.args.get("version").filter(|value| !value.is_null());
            let auto = call.args.get("mode").and_then(Value::as_str) == Some("auto");
            match known {
                Some(version)
                    if auto && differs(call.args.get("runtime_version"), Some(version)) =>
                {
                    Err(VERSION)
                }
                _ => Ok(Value::Null),
            }
        }
        "generation" => {
            let before = call.args.get("before").filter(|value| !value.is_null());
            let after = call.args.get("after").filter(|value| !value.is_null());
            match (before, after) {
                (Some(before), Some(after)) if python_equal(before, after) => Ok(Value::Null),
                _ => Err(GENERATION),
            }
        }
        _ => Err(Fault::Transition("files_invalid")),
    }
}
