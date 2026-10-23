//! Inert manifest comparison against this controller generation's embedded
//! Python bootstrap bytes. Filesystem custody and execution remain separate.

use crate::crypto::{is_sha256, sha256};
use crate::{EvidenceError, Result};
use gauntlet_contracts::canonicalize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const MAX_MANIFEST_BYTES: usize = 1024 * 1024;

macro_rules! source {
    ($name:literal) => {
        (
            $name,
            include_bytes!(concat!("../../../../gauntlet/benchmark/", $name, ".py")) as &[u8],
        )
    };
}

const ROOT_MODULES: &[(&str, &[u8])] = &[
    source!("contained_request_file"),
    source!("json_data"),
    source!("product_cell_actor"),
    source!("product_cell_idmap"),
    source!("product_cell_image"),
    source!("product_cell_layout"),
    source!("product_cell_protocol"),
    source!("product_cell_supervisor"),
    source!("product_cell_system"),
    source!("product_cell_task_mounts"),
    source!("product_exec_gate"),
    source!("product_vm_network"),
    source!("product_vm_rootfs"),
    source!("product_vm_seccomp"),
    source!("runtime_bundle"),
    source!("vm_bridge_frames"),
    source!("vm_bridge_io"),
    source!("vm_bridge_rpc"),
];

const PUBLIC_MODULES: &[&str] = &[
    "json_data",
    "product_cell_actor",
    "product_cell_layout",
    "product_cell_protocol",
    "product_exec_gate",
    "product_vm_network",
    "product_vm_seccomp",
    "vm_bridge_frames",
    "vm_bridge_io",
    "vm_bridge_rpc",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateCellManifest {
    pub manifest_sha256: String,
    pub initializer_sha256: String,
    pub files: BTreeMap<String, String>,
}

/// Exact controller-owned bootstrap bytes embedded in this verifier build.
/// Artifact writers may copy these bytes, but still need independent outside
/// pins and a separate whole-directory verification before using the result.
pub fn fixed_private_cell_sources() -> BTreeMap<String, &'static [u8]> {
    let mut sources = BTreeMap::new();
    for (folder, modules) in [
        (
            "code",
            ROOT_MODULES
                .iter()
                .map(|(name, _)| *name)
                .collect::<Vec<_>>(),
        ),
        ("public", PUBLIC_MODULES.to_vec()),
    ] {
        for name in modules {
            let bytes = ROOT_MODULES
                .iter()
                .find(|(module, _)| *module == name)
                .expect("fixed public module must also be a root module")
                .1;
            sources.insert(format!("{folder}/ci/gauntlet/benchmark/{name}.py"), bytes);
        }
        for relative in [
            "ci/__init__.py",
            "ci/gauntlet/__init__.py",
            "ci/gauntlet/benchmark/__init__.py",
        ] {
            let bytes: &'static [u8] = if relative == "ci/gauntlet/__init__.py" {
                include_bytes!("../../../../gauntlet/__init__.py")
            } else {
                b""
            };
            sources.insert(format!("{folder}/{relative}"), bytes);
        }
    }
    sources.insert(
        "product_vm.apparmor".to_owned(),
        include_bytes!("../../../../gauntlet/benchmark/product_vm.apparmor"),
    );
    sources.insert(
        "public/product_vm_seccomp_oci_v1.json".to_owned(),
        include_bytes!("../../../../gauntlet/benchmark/product_vm_seccomp_oci_v1.json"),
    );
    sources
}

/// Compare the manifest's exact file set and trusted-source bytes with
/// independently supplied manifest/initializer pins. This does not inspect
/// any artifact directory or authorize a candidate to execute.
pub fn verify_private_cell_manifest(
    raw: &[u8],
    expected_manifest_sha256: &str,
    expected_initializer_sha256: &str,
) -> Result<PrivateCellManifest> {
    if !is_sha256(expected_manifest_sha256) || !is_sha256(expected_initializer_sha256) {
        return Err(EvidenceError::Invalid("invalid private-cell outside pins"));
    }
    if raw.len() > MAX_MANIFEST_BYTES || sha256(raw) != expected_manifest_sha256 {
        return Err(EvidenceError::Invalid(
            "private-cell manifest differs from outside pin",
        ));
    }
    let canonical = canonicalize(raw)
        .map_err(|_| EvidenceError::Invalid("invalid private-cell manifest JSON"))?;
    let value: Value = serde_json::from_slice(&canonical)
        .map_err(|_| EvidenceError::Invalid("invalid private-cell manifest JSON"))?;
    let object =
        value
            .as_object()
            .filter(|object| object.len() == 2)
            .ok_or(EvidenceError::Invalid(
                "invalid private-cell manifest shape",
            ))?;
    if object.get("schema") != Some(&Value::String("product-cell-artifacts.v1".into())) {
        return Err(EvidenceError::Invalid("unsupported private-cell manifest"));
    }
    let declared = object
        .get("files")
        .and_then(Value::as_object)
        .ok_or(EvidenceError::Invalid("private-cell file map missing"))?;
    let fixed = fixed_private_cell_sources();
    let required: BTreeSet<_> = fixed
        .keys()
        .map(String::as_str)
        .chain(["public/actor.py", "public/initializer"])
        .collect();
    if declared.keys().map(String::as_str).collect::<BTreeSet<_>>() != required {
        return Err(EvidenceError::Invalid(
            "private-cell file set differs from fixed bootstrap",
        ));
    }
    let mut files = BTreeMap::new();
    for (path, value) in declared {
        let pin = value
            .as_str()
            .filter(|pin| is_sha256(pin))
            .ok_or(EvidenceError::Invalid("invalid private-cell file digest"))?;
        if fixed.get(path).is_some_and(|bytes| sha256(bytes) != pin) {
            return Err(EvidenceError::Invalid(
                "private-cell bootstrap differs from controller source",
            ));
        }
        files.insert(path.clone(), pin.to_owned());
    }
    if files.get("public/initializer").map(String::as_str) != Some(expected_initializer_sha256) {
        return Err(EvidenceError::Invalid(
            "private-cell initializer differs from outside pin",
        ));
    }
    Ok(PrivateCellManifest {
        manifest_sha256: expected_manifest_sha256.to_owned(),
        initializer_sha256: expected_initializer_sha256.to_owned(),
        files,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture() -> (Value, String) {
        let mut files = BTreeMap::new();
        for (path, bytes) in fixed_private_cell_sources() {
            files.insert(path, sha256(bytes));
        }
        let initializer = "a".repeat(64);
        files.insert("public/actor.py".to_owned(), "b".repeat(64));
        files.insert("public/initializer".to_owned(), initializer.clone());
        (
            json!({"schema":"product-cell-artifacts.v1","files":files}),
            initializer,
        )
    }

    #[test]
    fn embedded_bootstrap_source_map_matches_python_generation() {
        let hashes: BTreeMap<_, _> = fixed_private_cell_sources()
            .into_iter()
            .map(|(path, bytes)| (path, sha256(bytes)))
            .collect();
        let raw = serde_json::to_vec(&hashes).unwrap();
        let canonical = canonicalize(&raw).unwrap();
        assert_eq!(
            sha256(&canonical),
            "909592fac5403f683df5673f5f195eac014986e91d50e547b7c214871507ae54"
        );
    }

    fn verify(value: &Value, initializer: &str) -> Result<PrivateCellManifest> {
        let raw = serde_json::to_vec(value).unwrap();
        verify_private_cell_manifest(&raw, &sha256(&raw), initializer)
    }

    #[test]
    fn exact_embedded_bootstrap_and_initializer_are_accepted() {
        let (value, initializer) = fixture();
        let result = verify(&value, &initializer).unwrap();
        assert_eq!(result.files.len(), fixed_private_cell_sources().len() + 2);
        assert_eq!(result.initializer_sha256, initializer);
    }

    #[test]
    fn altered_source_missing_file_and_wrong_initializer_are_refused() {
        let (mut value, initializer) = fixture();
        value["files"]["code/ci/gauntlet/benchmark/product_vm_rootfs.py"] = json!("b".repeat(64));
        assert!(verify(&value, &initializer).is_err());
        let (mut value, initializer) = fixture();
        value["files"]
            .as_object_mut()
            .unwrap()
            .remove("public/actor.py");
        assert!(verify(&value, &initializer).is_err());
        let (value, _) = fixture();
        assert!(verify(&value, &"c".repeat(64)).is_err());
    }

    #[test]
    fn duplicate_manifest_keys_are_refused_even_with_matching_byte_pin() {
        let raw = br#"{"schema":"product-cell-artifacts.v1","schema":"product-cell-artifacts.v1","files":{}}"#;
        assert!(verify_private_cell_manifest(raw, &sha256(raw), &"a".repeat(64)).is_err());
    }
}
