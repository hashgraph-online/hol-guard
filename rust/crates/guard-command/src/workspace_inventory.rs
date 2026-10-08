//! Pure workspace-inventory / SBOM projection helpers ported from
//! `src/codex_plugin_scanner/guard/local_supply_chain.py` (RTM-019/026).
//!
//! Covered oracle surface:
//!   `_merge_inventory_item` (:3574), `_inventory_key` (:3597),
//!   `_split_namespace_name` (:3602), `_target_from_inventory_item` (:3610),
//!   `_inventory_from_sbom_text` (:3654, pure dispatch over an already-parsed
//!   JSON `Value`), `_inventory_from_cyclonedx` (:3674),
//!   `_inventory_from_spdx` (:3693), `_inventory_item_from_sbom_component`
//!   (:3724), `_inventory_from_purl` (:3753),
//!   `_target_from_manifest_dependency` (:4461), `_target_for_package_spec`
//!   (:4480), `_package_manager_for_scan` (:4492), plus the constants
//!   `_PACKAGE_MANAGER_BY_ECOSYSTEM`, `_ECOSYSTEM_BY_MANIFEST`,
//!   `_ECOSYSTEM_BY_LOCKFILE`, `_ECOSYSTEM_BY_PURL`, `_SEVERITY_RANK`.
//!
//! DIVERGENT PRIVATE COPIES — `local_supply_chain.rs` already carries
//! hand-written twins of these functions (do NOT unify blindly):
//!   * `split_namespace_name` (:2795) uses `str::trim`, missing CPython's
//!     0x1c-0x1f strip set.
//!   * `inventory_from_purl` (:2805) splits `remainder` on *every* `?`/`#`
//!     char (`split('?')`) which is equivalent here, but shares no code with
//!     this port and returns a `Map` whose key set is identical only by
//!     inspection.
//!   * `inventory_key` (:2861) uses `string_value`, which returns `None` for
//!     blank strings — the oracle's `str(item[...])` returns `""`. Blank
//!     `ecosystem`/`name` values collide differently.
//!   * `merge_inventory_item` (:2874) clones `ecosystem`/`name`/`namespace`
//!     verbatim; the oracle coerces through `str()`. It also treats
//!     `direct` via `as_bool` only (oracle: full truthiness), and is keyed on
//!     a `BTreeMap` — losing dict insertion order in the returned tuple.
//!   * `target_from_inventory_item` (:2936) — see below; its range-fallback
//!     path diverges on falsy non-None `range` values.
//!   * `inventory_item_from_sbom_component` (:2994) drops empty-string
//!     versions (`string_value`), the oracle keeps `""`.
//!   * `inventory_from_cyclonedx`/`_spdx`/`_sbom_text` (:3041/:3062/:3106)
//!     iterate a `BTreeMap` (sorted) rather than dict order.
//!   * `target_from_manifest_dependency` (:3982) uses `str::trim` instead of
//!     Python `str.strip()` (0x1c-0x1f escapes).
//!   * `target_for_package_spec`/`package_manager_for_scan` (:3660/:3671)
//!     share `basename`, which also splits on `\` (not a POSIX separator).
//!   * Constant tables (:136/:154/:174/:195/:209) are `private` mirrors of
//!     the `pub` statics declared here.
//!
//! Ordering contract: Python returns `tuple(dict.values())` in *insertion*
//! order. `InventoryMap` preserves that; the `BTreeMap` copies sort by key.

use std::collections::{BTreeMap, HashMap};
use std::sync::LazyLock;

use serde_json::{Map, Value};

use crate::local_supply_chain::{unquote, LocalSupplyChainError};
use crate::package_intent_common::{
    composer_target, coordinate_target, js_target, python_target, version_target,
    PackageIntentTarget,
};

// ---------------------------------------------------------------------------
// Constants (:154-222) — `pub` mirrors of the private tables in
// `local_supply_chain.rs`.
// ---------------------------------------------------------------------------

/// `_PACKAGE_MANAGER_BY_ECOSYSTEM` (:154).
pub static PACKAGE_MANAGER_BY_ECOSYSTEM: LazyLock<BTreeMap<&'static str, &'static str>> =
    LazyLock::new(|| {
        [
            ("npm", "npm"),
            ("pypi", "pip"),
            ("cargo", "cargo"),
            ("go", "go"),
            ("maven", "maven"),
            ("packagist", "composer"),
            ("rubygems", "bundle"),
            ("docker", "docker"),
            ("system", "system"),
            ("unsupported", "unsupported"),
        ]
        .into_iter()
        .collect()
    });

/// `_ECOSYSTEM_BY_MANIFEST` (:166).
pub static ECOSYSTEM_BY_MANIFEST: LazyLock<BTreeMap<&'static str, &'static str>> =
    LazyLock::new(|| {
        [
            ("package.json", "npm"),
            ("requirements.txt", "pypi"),
            ("constraints.txt", "pypi"),
            ("pyproject.toml", "pypi"),
            ("Pipfile", "pypi"),
            ("Cargo.toml", "cargo"),
            ("go.mod", "go"),
            ("pom.xml", "maven"),
            ("build.gradle", "maven"),
            ("build.gradle.kts", "maven"),
            ("composer.json", "packagist"),
            ("Gemfile", "rubygems"),
        ]
        .into_iter()
        .collect()
    });

/// `_ECOSYSTEM_BY_LOCKFILE` (:190).
pub static ECOSYSTEM_BY_LOCKFILE: LazyLock<BTreeMap<&'static str, &'static str>> =
    LazyLock::new(|| {
        [
            ("package-lock.json", "npm"),
            ("pnpm-lock.yaml", "npm"),
            ("yarn.lock", "npm"),
            ("bun.lock", "npm"),
            ("bun.lockb", "npm"),
            ("poetry.lock", "pypi"),
            ("uv.lock", "pypi"),
            ("Pipfile.lock", "pypi"),
            ("Cargo.lock", "cargo"),
            ("go.sum", "go"),
            ("gradle.lockfile", "maven"),
            ("composer.lock", "packagist"),
            ("Gemfile.lock", "rubygems"),
        ]
        .into_iter()
        .collect()
    });

/// `_ECOSYSTEM_BY_PURL` (:205).
pub static ECOSYSTEM_BY_PURL: LazyLock<BTreeMap<&'static str, &'static str>> =
    LazyLock::new(|| {
        [
            ("cargo", "cargo"),
            ("composer", "packagist"),
            ("gem", "rubygems"),
            ("golang", "go"),
            ("maven", "maven"),
            ("npm", "npm"),
            ("pypi", "pypi"),
        ]
        .into_iter()
        .collect()
    });

/// `_SEVERITY_RANK` (:214).
pub static SEVERITY_RANK: LazyLock<BTreeMap<&'static str, i64>> = LazyLock::new(|| {
    [
        ("unknown", 0),
        ("low", 1),
        ("medium", 2),
        ("high", 3),
        ("critical", 4),
    ]
    .into_iter()
    .collect()
});

// ---------------------------------------------------------------------------
// Python primitive fidelity helpers.
// ---------------------------------------------------------------------------

/// CPython `str.strip()` whitespace set: ASCII controls 0x09-0x0d and
/// 0x1c-0x1f plus every Unicode code point whose `isspace` is true. Rust's
/// `trim` misses 0x1c-0x1f.
fn is_python_space(ch: char) -> bool {
    matches!(
        ch,
        '\u{09}'..='\u{0d}'
            | ' '
            | '\u{1c}'..='\u{1f}'
            | '\u{85}'
            | '\u{a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'..='\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
    )
}

fn python_strip(text: &str) -> &str {
    text.trim_matches(is_python_space)
}

/// CPython truthiness for JSON-shaped values (`bool(value)`).
fn python_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i != 0
            } else if let Some(u) = n.as_u64() {
                u != 0
            } else {
                // f64; NaN is truthy in Python like any non-zero float.
                n.as_f64() != Some(0.0)
            }
        }
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// CPython `str(value)` for JSON scalars. Compound values are rendered as
/// their JSON text — a documented approximation of `str(list)`/`str(dict)`,
/// which only surfaces for malformed inventory input.
fn py_str(value: &Value) -> String {
    match value {
        Value::Null => "None".to_string(),
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// `Path(path).name` on POSIX — splits on `/` only and strips trailing
/// separators. Divergence vs the `local_supply_chain.rs` `basename` helper:
/// that copy also treats `\` as a separator (not a POSIX separator).
fn path_name(path: &str) -> &str {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return "";
    }
    trimmed.rsplit('/').next().unwrap_or(trimmed)
}

// ---------------------------------------------------------------------------
// Inventory map — Python `dict` semantics: insertion order + overwrite.
// ---------------------------------------------------------------------------

/// `(ecosystem, namespace, name)` dedup key produced by `inventory_key`.
pub type InventoryKey = (String, Option<String>, String);

/// Insertion-ordered map from `InventoryKey` to the merged inventory item —
/// a faithful stand-in for the oracle's `dict[tuple, dict]`.
#[derive(Debug, Default)]
pub struct InventoryMap {
    order: Vec<InventoryKey>,
    index: HashMap<InventoryKey, usize>,
    items: Vec<Map<String, Value>>,
}

impl InventoryMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// `tuple(inventory_map.values())` in insertion order.
    pub fn into_values(self) -> Vec<Map<String, Value>> {
        self.items
    }
}

/// `_inventory_key` (:3597). `str()`-coerces `ecosystem`/`name`; `namespace`
/// is kept only when it is a string.
pub fn inventory_key(item: &Map<String, Value>) -> InventoryKey {
    let namespace = match item.get("namespace") {
        Some(Value::String(s)) => Some(s.clone()),
        _ => None,
    };
    (
        item.get("ecosystem").map(py_str).unwrap_or_default(),
        namespace,
        item.get("name").map(py_str).unwrap_or_default(),
    )
}

/// `_merge_inventory_item` (:3574). First writer wins the slot; later items
/// OR `direct` and fill `range`/`version` only when the stored value is
/// `None` (null *or absent*).
pub fn merge_inventory_item(inventory_map: &mut InventoryMap, item: &Map<String, Value>) {
    let key = inventory_key(item);
    match inventory_map.index.get(&key) {
        None => {
            let mut entry = Map::new();
            entry.insert(
                "ecosystem".into(),
                Value::String(item.get("ecosystem").map(py_str).unwrap_or_default()),
            );
            entry.insert(
                "namespace".into(),
                item.get("namespace").cloned().unwrap_or(Value::Null),
            );
            entry.insert(
                "name".into(),
                Value::String(item.get("name").map(py_str).unwrap_or_default()),
            );
            entry.insert(
                "direct".into(),
                Value::Bool(item.get("direct").map(python_truthy).unwrap_or(false)),
            );
            entry.insert(
                "range".into(),
                item.get("range").cloned().unwrap_or(Value::Null),
            );
            entry.insert(
                "version".into(),
                item.get("version").cloned().unwrap_or(Value::Null),
            );
            inventory_map
                .index
                .insert(key.clone(), inventory_map.items.len());
            inventory_map.order.push(key);
            inventory_map.items.push(entry);
        }
        Some(&slot) => {
            let existing = &mut inventory_map.items[slot];
            let existing_direct = existing.get("direct").map(python_truthy).unwrap_or(false);
            let item_direct = item.get("direct").map(python_truthy).unwrap_or(false);
            existing.insert("direct".into(), Value::Bool(existing_direct || item_direct));
            if matches!(existing.get("range"), None | Some(Value::Null))
                && !matches!(item.get("range"), None | Some(Value::Null))
            {
                existing.insert("range".into(), item["range"].clone());
            }
            if matches!(existing.get("version"), None | Some(Value::Null))
                && !matches!(item.get("version"), None | Some(Value::Null))
            {
                existing.insert("version".into(), item["version"].clone());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Name splitting + target projection.
// ---------------------------------------------------------------------------

/// `_split_namespace_name` (:3602) — npm `@scope/name` handling only.
pub fn split_namespace_name(package_name: &str) -> (Option<String>, String) {
    let cleaned = python_strip(package_name);
    if cleaned.starts_with('@') && cleaned.contains('/') {
        let (namespace, name) = cleaned.split_once('/').unwrap_or((cleaned, ""));
        return (Some(namespace.to_string()), name.to_string());
    }
    (None, cleaned.to_string())
}

/// `_target_from_inventory_item` (:3610). The suffix is `str(version)` when
/// `version` is a string, else `str(version_range or "")` — meaning a falsy
/// non-None `range` (`""`, `0`, `[]`, `False`) becomes `""`, never `"None"`.
pub fn target_from_inventory_item(item: &Map<String, Value>) -> PackageIntentTarget {
    let qualified_name = match item.get("namespace") {
        Some(Value::String(ns)) => {
            format!("{ns}/{}", item.get("name").map(py_str).unwrap_or_default())
        }
        _ => item.get("name").map(py_str).unwrap_or_default(),
    };
    let suffix = match item.get("version") {
        Some(Value::String(v)) => v.clone(),
        _ => match item.get("range") {
            Some(range) if python_truthy(range) => py_str(range),
            _ => String::new(),
        },
    };
    let ecosystem = item.get("ecosystem").map(py_str).unwrap_or_default();
    match ecosystem.as_str() {
        "npm" => {
            let spec = if suffix.is_empty() {
                qualified_name
            } else {
                format!("{qualified_name}@{suffix}")
            };
            js_target(&spec)
        }
        "pypi" => {
            let spec = if suffix.is_empty() {
                qualified_name
            } else {
                format!("{qualified_name}{suffix}")
            };
            python_target(&spec, false, None, Vec::new())
        }
        "maven" => {
            let spec = if suffix.is_empty() {
                qualified_name
            } else {
                format!("{qualified_name}:{suffix}")
            };
            coordinate_target(&ecosystem, &spec)
        }
        "packagist" => {
            let spec = if suffix.is_empty() {
                qualified_name
            } else {
                format!("{qualified_name}:{suffix}")
            };
            composer_target(&spec)
        }
        _ => {
            let spec = if suffix.is_empty() {
                qualified_name
            } else {
                format!("{qualified_name}@{suffix}")
            };
            version_target(&ecosystem, &spec, None)
        }
    }
}

// ---------------------------------------------------------------------------
// SBOM projection.
// ---------------------------------------------------------------------------

/// `_inventory_from_sbom_text` (:3654) — pure dispatch over an already-parsed
/// JSON `Value` (`json.loads` is the caller's job). Error strings are
/// verbatim oracle `ValueError` messages.
pub fn inventory_from_sbom_payload(
    payload: &Value,
) -> Result<Vec<Map<String, Value>>, LocalSupplyChainError> {
    let Some(payload) = payload.as_object() else {
        return Err(LocalSupplyChainError::Runtime(
            "SBOM payload must be an object".to_string(),
        ));
    };
    if payload.get("bomFormat").and_then(Value::as_str) == Some("CycloneDX") {
        return Ok(inventory_from_cyclonedx(payload));
    }
    if payload
        .get("spdxVersion")
        .map(python_truthy)
        .unwrap_or(false)
    {
        return Ok(inventory_from_spdx(payload));
    }
    Err(LocalSupplyChainError::Runtime(
        "Unsupported SBOM format".to_string(),
    ))
}

/// `_inventory_from_cyclonedx` (:3674).
pub fn inventory_from_cyclonedx(payload: &Map<String, Value>) -> Vec<Map<String, Value>> {
    let Some(Value::Array(components)) = payload.get("components") else {
        return Vec::new();
    };
    let mut inventory = InventoryMap::new();
    for component in components {
        let Some(component) = component.as_object() else {
            continue;
        };
        let item = inventory_item_from_sbom_component(
            component.get("name"),
            component.get("version"),
            component.get("purl").and_then(Value::as_str),
        );
        if let Some(item) = item {
            merge_inventory_item(&mut inventory, &item);
        }
    }
    inventory.into_values()
}

/// `_inventory_from_spdx` (:3693). First truthy `purl`-typed
/// `referenceLocator` wins per package.
pub fn inventory_from_spdx(payload: &Map<String, Value>) -> Vec<Map<String, Value>> {
    let Some(Value::Array(packages)) = payload.get("packages") else {
        return Vec::new();
    };
    let mut inventory = InventoryMap::new();
    for package in packages {
        let Some(package) = package.as_object() else {
            continue;
        };
        let mut purl: Option<&str> = None;
        if let Some(Value::Array(external_refs)) = package.get("externalRefs") {
            for external_ref in external_refs {
                let Some(external_ref) = external_ref.as_object() else {
                    continue;
                };
                let ref_type = match external_ref.get("referenceType") {
                    Some(Value::String(s)) => s.to_lowercase(),
                    Some(v) => py_str(v).to_lowercase(),
                    None => String::new(),
                };
                if ref_type != "purl" {
                    continue;
                }
                if let Some(locator) = external_ref.get("referenceLocator").and_then(Value::as_str)
                {
                    if !locator.is_empty() {
                        purl = Some(locator);
                        break;
                    }
                }
            }
        }
        let item = inventory_item_from_sbom_component(
            package.get("name"),
            package.get("versionInfo"),
            purl,
        );
        if let Some(item) = item {
            merge_inventory_item(&mut inventory, &item);
        }
    }
    inventory.into_values()
}

/// `_inventory_item_from_sbom_component` (:3724). `purl` must already be
/// `Some` only when the raw value was a string (`isinstance(purl, str)`).
/// A whitespace-only `version` keeps `""` (the oracle strips but does not
/// `or None` it).
pub fn inventory_item_from_sbom_component(
    name: Option<&Value>,
    version: Option<&Value>,
    purl: Option<&str>,
) -> Option<Map<String, Value>> {
    let purl_values = inventory_from_purl(purl);
    if purl_values.is_none() && !matches!(name, Some(Value::String(_))) {
        return None;
    }
    let ecosystem = match &purl_values {
        Some(map) => map.get("ecosystem").cloned().unwrap_or(Value::Null),
        None => Value::String("unsupported".to_string()),
    };
    let namespace = match &purl_values {
        Some(map) => map.get("namespace").cloned().unwrap_or(Value::Null),
        None => Value::Null,
    };
    let package_name = match &purl_values {
        Some(map) => map.get("name").cloned().unwrap_or(Value::Null),
        None => Value::String(
            name.map(py_str)
                .map(|s| python_strip(&s).to_string())
                .unwrap_or_default(),
        ),
    };
    let package_version = match &purl_values {
        Some(map) => map.get("version").cloned().unwrap_or(Value::Null),
        None => match version {
            Some(Value::String(v)) => Value::String(python_strip(v).to_string()),
            _ => Value::Null,
        },
    };
    if !python_truthy(&package_name) {
        return None;
    }
    let mut item = Map::new();
    item.insert("ecosystem".into(), ecosystem);
    item.insert("namespace".into(), namespace);
    item.insert("name".into(), package_name);
    item.insert("direct".into(), Value::Bool(false));
    item.insert("range".into(), Value::Null);
    item.insert("version".into(), package_version);
    Some(item)
}

/// `_inventory_from_purl` (:3753) — `pkg:type/path@version` projection with
/// `urllib.parse.unquote` on each decoded segment.
pub fn inventory_from_purl(purl: Option<&str>) -> Option<Map<String, Value>> {
    let purl = purl?;
    if !purl.starts_with("pkg:") {
        return None;
    }
    let without_prefix = &purl[4..];
    let (package_type, remainder) = match without_prefix.split_once('/') {
        Some((t, r)) => (t, r),
        None => (without_prefix, ""),
    };
    let ecosystem = ECOSYSTEM_BY_PURL.get(package_type)?;
    if remainder.is_empty() {
        return None;
    }
    let package_ref = remainder
        .split('?')
        .next()
        .unwrap_or("")
        .split('#')
        .next()
        .unwrap_or("");
    let (package_path, package_version) = match package_ref.split_once('@') {
        Some((p, v)) => (p, v),
        None => (package_ref, ""),
    };
    if package_path.is_empty() {
        return None;
    }
    let (namespace, name) = if package_path.contains('/') {
        let (ns, n) = package_path.rsplit_once('/').unwrap_or((package_path, ""));
        (
            if ns.is_empty() {
                Value::Null
            } else {
                Value::String(unquote(ns))
            },
            Value::String(unquote(n)),
        )
    } else {
        (Value::Null, Value::String(unquote(package_path)))
    };
    let mut out = Map::new();
    out.insert("ecosystem".into(), Value::String((*ecosystem).to_string()));
    out.insert("namespace".into(), namespace);
    out.insert("name".into(), name);
    out.insert(
        "version".into(),
        if package_version.is_empty() {
            Value::Null
        } else {
            Value::String(unquote(package_version))
        },
    );
    Some(out)
}

// ---------------------------------------------------------------------------
// Manifest-dependency target + scan package-manager selection.
// ---------------------------------------------------------------------------

/// `_target_from_manifest_dependency` (:4461). pypi joins `name`+`version`
/// with no separator (PEP-440 specifier text such as `>=4`).
pub fn target_from_manifest_dependency(
    ecosystem: &str,
    package_name: &str,
    version: &str,
) -> PackageIntentTarget {
    let clean_name = python_strip(package_name);
    let clean_version = python_strip(version);
    match ecosystem {
        "npm" => {
            let spec = if clean_version.is_empty() {
                clean_name.to_string()
            } else {
                format!("{clean_name}@{clean_version}")
            };
            js_target(&spec)
        }
        "pypi" => {
            let spec = if clean_version.is_empty() {
                clean_name.to_string()
            } else {
                format!("{clean_name}{clean_version}")
            };
            python_target(&spec, false, None, Vec::new())
        }
        "maven" => {
            let spec = if clean_version.is_empty() {
                clean_name.to_string()
            } else {
                format!("{clean_name}:{clean_version}")
            };
            coordinate_target(ecosystem, &spec)
        }
        "packagist" => {
            let spec = if clean_version.is_empty() {
                clean_name.to_string()
            } else {
                format!("{clean_name}:{clean_version}")
            };
            composer_target(&spec)
        }
        _ => {
            let spec = if clean_version.is_empty() {
                clean_name.to_string()
            } else {
                format!("{clean_name}@{clean_version}")
            };
            version_target(ecosystem, &spec, None)
        }
    }
}

/// `_target_for_package_spec` (:4480).
pub fn target_for_package_spec(ecosystem: &str, package_spec: &str) -> PackageIntentTarget {
    match ecosystem {
        "npm" => js_target(package_spec),
        "pypi" => python_target(package_spec, false, None, Vec::new()),
        "maven" => coordinate_target(ecosystem, package_spec),
        "packagist" => composer_target(package_spec),
        _ => version_target(ecosystem, package_spec, None),
    }
}

/// `_package_manager_for_scan` (:4492) — first recognized manifest basename
/// wins; falls back to `"workspace"`.
pub fn package_manager_for_scan(manifest_paths: &[String]) -> String {
    for manifest_path in manifest_paths {
        if let Some(ecosystem) = ECOSYSTEM_BY_MANIFEST.get(path_name(manifest_path)) {
            return PACKAGE_MANAGER_BY_ECOSYSTEM
                .get(*ecosystem)
                .map(|value| (*value).to_string())
                .unwrap_or_else(|| (*ecosystem).to_string());
        }
    }
    "workspace".to_string()
}

// ---------------------------------------------------------------------------
// Oracle parity tests — golden vectors generated by `gen_golden.py` against
// `codex_plugin_scanner.guard.local_supply_chain` on this checkout.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct Case {
        function: String,
        input: Value,
        output: Value,
    }

    fn load_cases() -> Vec<Case> {
        let raw = include_str!("../testdata/workspace_inventory_oracle.json");
        serde_json::from_str::<Vec<Value>>(raw)
            .expect("oracle corpus parses")
            .into_iter()
            .map(|row| Case {
                function: row["fn"].as_str().expect("fn name").to_string(),
                input: row["input"].clone(),
                output: row["output"].clone(),
            })
            .collect()
    }

    fn case_map(input: &Value) -> Map<String, Value> {
        input.as_object().expect("item is object").clone()
    }

    #[test]
    fn split_namespace_name_matches_oracle() {
        for case in load_cases() {
            if case.function != "split_namespace_name" {
                continue;
            }
            let (ns, name) = split_namespace_name(case.input.as_str().unwrap());
            let expected_ns = case.output[0].as_str().map(str::to_string);
            assert_eq!(ns, expected_ns, "namespace for {:?}", case.input);
            assert_eq!(json!(name), case.output[1], "name for {:?}", case.input);
        }
    }

    #[test]
    fn inventory_from_purl_matches_oracle() {
        for case in load_cases() {
            if case.function != "inventory_from_purl" {
                continue;
            }
            let actual = inventory_from_purl(case.input.as_str())
                .map(Value::Object)
                .unwrap_or(Value::Null);
            assert_eq!(actual, case.output, "purl {:?}", case.input);
        }
    }

    #[test]
    fn merge_inventory_item_matches_oracle() {
        for case in load_cases() {
            if case.function != "merge_inventory_item" {
                continue;
            }
            let mut map = InventoryMap::new();
            for item in case.input.as_array().expect("sequence") {
                merge_inventory_item(&mut map, &case_map(item));
            }
            let actual = Value::Array(map.into_values().into_iter().map(Value::Object).collect());
            assert_eq!(actual, case.output, "merge sequence {:?}", case.input);
        }
    }

    #[test]
    fn inventory_key_matches_oracle() {
        for case in load_cases() {
            if case.function != "inventory_key" {
                continue;
            }
            let (eco, ns, name) = inventory_key(&case_map(&case.input));
            let expected = vec![
                json!(eco),
                ns.map(Value::String).unwrap_or(Value::Null),
                json!(name),
            ];
            assert_eq!(json!(expected), case.output, "key for {:?}", case.input);
        }
    }

    #[test]
    fn inventory_item_from_sbom_component_matches_oracle() {
        for case in load_cases() {
            if case.function != "inventory_item_from_sbom_component" {
                continue;
            }
            let kwargs = case.input.as_object().expect("kwargs");
            let actual = inventory_item_from_sbom_component(
                kwargs.get("name"),
                kwargs.get("version"),
                kwargs.get("purl").and_then(Value::as_str),
            )
            .map(Value::Object)
            .unwrap_or(Value::Null);
            assert_eq!(actual, case.output, "kwargs {:?}", case.input);
        }
    }

    #[test]
    fn inventory_from_cyclonedx_matches_oracle() {
        for case in load_cases() {
            if case.function != "inventory_from_cyclonedx" {
                continue;
            }
            let payload = case.input.as_object().expect("payload");
            let actual = Value::Array(
                inventory_from_cyclonedx(payload)
                    .into_iter()
                    .map(Value::Object)
                    .collect(),
            );
            assert_eq!(actual, case.output, "payload {:?}", case.input);
        }
    }

    #[test]
    fn inventory_from_spdx_matches_oracle() {
        for case in load_cases() {
            if case.function != "inventory_from_spdx" {
                continue;
            }
            let payload = case.input.as_object().expect("payload");
            let actual = Value::Array(
                inventory_from_spdx(payload)
                    .into_iter()
                    .map(Value::Object)
                    .collect(),
            );
            assert_eq!(actual, case.output, "payload {:?}", case.input);
        }
    }

    #[test]
    fn inventory_from_sbom_payload_matches_oracle() {
        for case in load_cases() {
            if case.function != "inventory_from_sbom_text" {
                continue;
            }
            match inventory_from_sbom_payload(&case.input) {
                Ok(items) => {
                    let actual = Value::Array(items.into_iter().map(Value::Object).collect());
                    let expected = case.output.get("ok").expect("ok arm").clone();
                    assert_eq!(actual, expected, "payload {:?}", case.input);
                }
                Err(err) => {
                    let expected = case
                        .output
                        .get("err")
                        .unwrap_or_else(|| panic!("expected ok for {:?}", case.input));
                    assert_eq!(
                        &json!(err.to_string()),
                        expected,
                        "err for {:?}",
                        case.input
                    );
                }
            }
        }
    }

    #[test]
    fn target_from_inventory_item_matches_oracle() {
        for case in load_cases() {
            if case.function != "target_from_inventory_item" {
                continue;
            }
            let actual = target_from_inventory_item(&case_map(&case.input)).to_dict();
            assert_eq!(actual, case.output, "item {:?}", case.input);
        }
    }

    #[test]
    fn target_from_manifest_dependency_matches_oracle() {
        for case in load_cases() {
            if case.function != "target_from_manifest_dependency" {
                continue;
            }
            let args = case.input.as_array().expect("args");
            let actual = target_from_manifest_dependency(
                args[0].as_str().unwrap(),
                args[1].as_str().unwrap(),
                args[2].as_str().unwrap(),
            )
            .to_dict();
            assert_eq!(actual, case.output, "args {:?}", case.input);
        }
    }

    #[test]
    fn target_for_package_spec_matches_oracle() {
        for case in load_cases() {
            if case.function != "target_for_package_spec" {
                continue;
            }
            let args = case.input.as_array().expect("args");
            let actual =
                target_for_package_spec(args[0].as_str().unwrap(), args[1].as_str().unwrap())
                    .to_dict();
            assert_eq!(actual, case.output, "args {:?}", case.input);
        }
    }

    #[test]
    fn package_manager_for_scan_matches_oracle() {
        for case in load_cases() {
            if case.function != "package_manager_for_scan" {
                continue;
            }
            let paths: Vec<String> = case
                .input
                .as_array()
                .expect("paths")
                .iter()
                .map(|p| p.as_str().unwrap().to_string())
                .collect();
            let actual = package_manager_for_scan(&paths);
            assert_eq!(json!(actual), case.output, "paths {:?}", case.input);
        }
    }
}
