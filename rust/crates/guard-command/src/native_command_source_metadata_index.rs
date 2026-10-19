//! Bounded offline authoring interfaces, never publisher/activation authority.
//! Builder obtains these bytes only from verified bundle metadata or its
//! globally validated development pack stream. Native callers remain untrusted.
use super::packs::objects::{read_blob, ObjectRef, OBJECT_BYTES};
use super::*;
use std::path::PathBuf;

const MAX_ENTRIES: usize = 100_000;
const MAX_TOTAL_BYTES: usize = 128 * 1024 * 1024;
const MAX_VISITED_REFS: usize = 300_000;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Handle {
    directory: PathBuf,
    root: ObjectRef,
    source_context: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Root {
    schema: String,
    engine: String,
    source_context: String,
    count: usize,
    total_bytes: usize,
    pages: usize,
    first: ObjectRef,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Page {
    schema: String,
    entries: Vec<(String, ObjectRef)>,
    next: Option<ObjectRef>,
}

struct Reader<'a> {
    directory: &'a std::path::Path,
    visits: usize,
    bytes: usize,
}

impl Reader<'_> {
    fn value(&mut self, reference: &ObjectRef, page: bool) -> Result<Value, &'static str> {
        if page && (reference.kind != "data" || reference.expanded_length > OBJECT_BYTES) {
            return Err("command_source_metadata_page_bounds_invalid");
        }
        let bytes = read_blob(reference, &mut |sha| {
            self.visits += 1;
            if self.visits > MAX_VISITED_REFS {
                return Err("command_source_metadata_reference_budget_exceeded");
            }
            let path = self.directory.join(format!("{sha}.json"));
            // Reject mutable, linked, symlinked, nonregular or unstable files.
            // read_bounded additionally checks every ancestor before and after.
            let _immutable = guard_secure_fs::open_immutable_blob(&path)
                .map_err(|_| "command_source_metadata_file_invalid")?;
            let read = guard_secure_fs::read_bounded(&path, OBJECT_BYTES)
                .map_err(|_| "command_source_metadata_file_invalid")?;
            if _immutable.identity != read.identity {
                return Err("command_source_metadata_file_invalid");
            }
            self.bytes = self
                .bytes
                .checked_add(read.bytes.len())
                .ok_or("command_source_metadata_byte_budget_exceeded")?;
            // Include concat and index overhead, separately from metadata bytes.
            if self.bytes > MAX_TOTAL_BYTES + 32 * 1024 * 1024 {
                return Err("command_source_metadata_byte_budget_exceeded");
            }
            Ok(read.bytes)
        })?;
        json::decode(&bytes)
    }
}

pub(super) fn read(handle: &Handle) -> Result<Vec<Value>, &'static str> {
    if !handle.directory.is_absolute()
        || guard_secure_fs::contains_symlink_component(&handle.directory)
    {
        return Err("command_source_metadata_directory_invalid");
    }
    let mut reader = Reader {
        directory: &handle.directory,
        visits: 0,
        bytes: 0,
    };
    let root: Root = serde_json::from_value(reader.value(&handle.root, true)?)
        .map_err(|_| "command_source_metadata_root_invalid")?;
    if root.schema != "guard.authoring-metadata.v1"
        || root.engine != env!("GUARD_COMMAND_SOURCE_IMPLEMENTATION")
        || root.source_context != handle.source_context
        || root.source_context.len() != 64
        || !root
            .source_context
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || root.count == 0
        || root.count > MAX_ENTRIES
        || root.total_bytes == 0
        || root.total_bytes > MAX_TOTAL_BYTES
        || root.pages != root.count.div_ceil(64)
    {
        return Err("command_source_metadata_root_invalid");
    }
    let mut result = Vec::with_capacity(root.count);
    let mut next = Some(root.first);
    let mut seen = BTreeSet::new();
    let mut previous = String::new();
    let mut total = 0usize;
    for _ in 0..root.pages {
        let reference = next.take().ok_or("command_source_metadata_page_missing")?;
        if !seen.insert(reference.sha256.clone()) {
            return Err("command_source_metadata_page_duplicate");
        }
        let page: Page = serde_json::from_value(reader.value(&reference, true)?)
            .map_err(|_| "command_source_metadata_page_invalid")?;
        if page.schema != "guard.authoring-metadata-page.v1"
            || page.entries.is_empty()
            || page.entries.len() > 64
        {
            return Err("command_source_metadata_page_invalid");
        }
        for (identity, reference) in page.entries {
            if identity <= previous
                || identity.len() > 256
                || !identity.is_ascii()
                || result.len() >= root.count
            {
                return Err("command_source_metadata_order_invalid");
            }
            total = total
                .checked_add(reference.expanded_length)
                .ok_or("command_source_metadata_byte_budget_exceeded")?;
            if total > root.total_bytes {
                return Err("command_source_metadata_byte_budget_exceeded");
            }
            let entry = reader.value(&reference, false)?;
            if entry["extension_id"] != identity {
                return Err("command_source_metadata_identity_invalid");
            }
            previous = identity;
            result.push(entry);
        }
        next = page.next;
    }
    if next.is_some() || result.len() != root.count || total != root.total_bytes {
        return Err("command_source_metadata_inventory_incomplete");
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde_json::json;
    use std::fs;

    fn store(directory: &std::path::Path, value: &Value) -> ObjectRef {
        let mut output = Vec::new();
        let reference = super::super::packs::objects::ObjectWriter::new(&mut output)
            .json(value)
            .unwrap();
        for line in output
            .split(|b| *b == b'\n')
            .filter(|line| !line.is_empty())
        {
            let row: Value = serde_json::from_slice(line).unwrap();
            let path = directory.join(format!("{}.json", row["sha256"].as_str().unwrap()));
            if !path.exists() {
                fs::write(
                    &path,
                    STANDARD.decode(row["data"].as_str().unwrap()).unwrap(),
                )
                .unwrap();
                let mut permissions = fs::metadata(&path).unwrap().permissions();
                permissions.set_readonly(true);
                fs::set_permissions(path, permissions).unwrap();
            }
        }
        reference
    }

    fn fixture(count: usize) -> (tempfile::TempDir, Handle, Value) {
        let owner = tempfile::tempdir().unwrap();
        let directory = owner.path().canonicalize().unwrap();
        let entries: Vec<_> = (0..count)
            .map(|n| json!({"extension_id":format!("command.test{n:05}")}))
            .collect();
        let rows: Vec<_> = entries
            .iter()
            .map(|entry| json!([entry["extension_id"], store(&directory, entry)]))
            .collect();
        let mut next = Value::Null;
        for chunk in rows.rchunks(64) {
            next = serde_json::to_value(store(
                &directory,
                &json!({"schema":"guard.authoring-metadata-page.v1","entries":chunk,"next":next}),
            ))
            .unwrap();
        }
        let root = json!({"schema":"guard.authoring-metadata.v1","engine":env!("GUARD_COMMAND_SOURCE_IMPLEMENTATION"),
            "source_context":"a".repeat(64),"count":count,"total_bytes":entries.iter().map(|v| serde_json::to_vec(v).unwrap().len()).sum::<usize>(),"pages":count.div_ceil(64),"first":next});
        let handle = Handle {
            root: store(&directory, &root),
            directory,
            source_context: "a".repeat(64),
        };
        (owner, handle, root)
    }

    #[test]
    fn indexed_inventory_rejects_cursor_identity_order_and_bound_mutations() {
        for fault in [
            "hash",
            "duplicate",
            "order",
            "page-count",
            "count",
            "total-budget",
            "total-mismatch",
            "source-context",
            "engine",
            "substitution",
            "early-end",
            "page-items",
            "record-budget",
            "cursor-replay",
        ] {
            let (_owner, mut handle, mut root) = fixture(130);
            match fault {
                "hash" => root["first"]["sha256"] = json!("0".repeat(64)),
                "page-count" => root["pages"] = json!(4),
                "count" => root["count"] = json!(100001),
                "total-budget" => root["total_bytes"] = json!(MAX_TOTAL_BYTES + 1),
                "total-mismatch" => {
                    root["total_bytes"] = json!(root["total_bytes"].as_u64().unwrap() - 1)
                }
                "source-context" => root["source_context"] = json!("0".repeat(64)),
                "engine" => root["engine"] = json!("0".repeat(64)),
                _ => {
                    let path = handle.directory.join(format!(
                        "{}.json",
                        root["first"]["sha256"].as_str().unwrap()
                    ));
                    let mut page: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
                    match fault {
                        "duplicate" => page["entries"][1] = page["entries"][0].clone(),
                        "order" => page["entries"].as_array_mut().unwrap().reverse(),
                        "substitution" => page["entries"][0][1] = page["entries"][1][1].clone(),
                        "early-end" => page["next"] = Value::Null,
                        "page-items" => {
                            page["entries"] = json!(vec![page["entries"][0].clone(); 65])
                        }
                        "record-budget" => {
                            root["total_bytes"] =
                                json!(8 * 1024 * 1024 + root["total_bytes"].as_u64().unwrap());
                            page["entries"][0][1]["expanded_length"] = json!(8 * 1024 * 1024 + 1);
                        }
                        "cursor-replay" => page["next"] = root["first"].clone(),
                        _ => unreachable!(),
                    }
                    root["first"] = serde_json::to_value(store(&handle.directory, &page)).unwrap();
                }
            }
            handle.root = store(&handle.directory, &root);
            assert!(read(&handle).is_err(), "{fault}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn indexed_inventory_rejects_missing_corrupt_linked_mutable_and_nonregular_pages() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        for fault in [
            "missing",
            "corrupt",
            "symlink",
            "hardlink",
            "nonregular",
            "mutable",
        ] {
            let (_owner, handle, root) = fixture(130);
            let path = handle.directory.join(format!(
                "{}.json",
                root["first"]["sha256"].as_str().unwrap()
            ));
            let mut bytes = fs::read(&path).unwrap();
            fs::remove_file(&path).unwrap();
            match fault {
                "missing" => {}
                "corrupt" => {
                    bytes[0] = b'!';
                    fs::write(&path, bytes).unwrap();
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
                }
                "mutable" => {
                    fs::write(&path, bytes).unwrap();
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
                }
                "nonregular" => fs::create_dir(&path).unwrap(),
                kind => {
                    let target = handle.directory.join("target");
                    fs::write(&target, bytes).unwrap();
                    fs::set_permissions(&target, fs::Permissions::from_mode(0o400)).unwrap();
                    if kind == "symlink" {
                        symlink(target, &path).unwrap();
                    } else {
                        fs::hard_link(target, &path).unwrap();
                    }
                }
            }
            assert!(read(&handle).is_err(), "{fault}");
        }
    }

    #[test]
    fn indexed_inventory_assembles_bounded_metadata() {
        let (_owner, mut handle, mut root) = fixture(1);
        let entry = json!({"extension_id":"command.test00000","diagnostic_metadata":vec!["x".repeat(4000);30]});
        let reference = store(&handle.directory, &entry);
        assert_eq!(reference.kind, "concat");
        root["first"] = serde_json::to_value(store(&handle.directory,&json!({"schema":"guard.authoring-metadata-page.v1","entries":[["command.test00000",reference]],"next":null}))).unwrap();
        root["total_bytes"] = json!(serde_json::to_vec(&entry).unwrap().len());
        handle.root = store(&handle.directory, &root);
        assert_eq!(read(&handle).unwrap(), vec![entry]);
    }

    #[test]
    fn global_inactive_metadata_rejection_matrix_and_publisher_boundary_remain_native() {
        use super::super::{baseline::ValidationBase, catalog};
        const EXAMPLE: &[u8] = include_bytes!("../tests/fixtures/command-source-example.v1.json");
        let trust = include_bytes!(concat!(env!("OUT_DIR"), "/trust-class-map.v1.json"));
        let ids = BTreeSet::from(["command.example-cli".to_owned()]);
        let permissions = BTreeSet::from(["command.example-cli.permission.destroy".to_owned()]);
        let pack = catalog::compile_pack(&[EXAMPLE], &[], trust, (&ids, &permissions)).unwrap();
        let mut catalog = serde_json::from_slice::<Value>(
            crate::native_command_catalog::embedded_catalog_bytes(),
        )
        .unwrap()["catalog"]
            .as_array()
            .unwrap()
            .clone();
        for n in 0..2 {
            catalog.push(
                serde_json::from_str(
                    &serde_json::to_string(&pack.catalog[0])
                        .unwrap()
                        .replace("command.example-cli", &format!("command.inactive{n}")),
                )
                .unwrap(),
            );
        }
        ValidationBase {
            catalog: catalog.clone(),
            programs: vec![],
        }
        .prepare(&[EXAMPLE], &[], false)
        .unwrap();
        let last = catalog.len() - 1;
        let previous = last - 1;
        for fault in [
            "ownership",
            "owner-field",
            "dependency",
            "permission-dependency",
            "cycle",
            "conflict",
            "family",
            "mcp",
            "core",
            "alias",
        ] {
            let mut changed = catalog.clone();
            match fault {
                "ownership" => {
                    changed[last]["permissions"][0]["permission_id"] =
                        changed[previous]["permissions"][0]["permission_id"].clone()
                }
                "owner-field" => {
                    changed[last]["permissions"][0]["extension_id"] =
                        changed[previous]["extension_id"].clone()
                }
                "dependency" => changed[last]["dependencies"] = json!(["command.absent"]),
                "permission-dependency" => {
                    changed[last]["permissions"][0]["dependencies"] =
                        json!(["command.absent.permission.destroy"])
                }
                "cycle" => {
                    changed[last]["dependencies"] = json!([changed[previous]["extension_id"]]);
                    changed[previous]["dependencies"] = json!([changed[last]["extension_id"]]);
                }
                "conflict" => changed[last]["conflicts"] = json!(["command.absent"]),
                "family" => {
                    changed[last]["permissions"][0]["family"] = json!("shared.family");
                    changed[previous]["permissions"][0]["family"] = json!("shared.family");
                }
                "mcp" => {
                    changed[last]["mcp_launch"] =
                        json!({"kind":"direct-command","command":"same-mcp-target"});
                    changed[previous]["mcp_launch"] = changed[last]["mcp_launch"].clone();
                }
                "core" => changed[0]["description"] = json!("substituted"),
                "alias" => changed[last]["aliases"] = json!(["command.example-cli"]),
                _ => unreachable!(),
            }
            assert!(
                ValidationBase {
                    catalog: changed,
                    programs: vec![]
                }
                .prepare(&[EXAMPLE], &[], false)
                .is_err(),
                "{fault}"
            );
        }
        catalog[last]["trust_class"] = json!("first-party");
        let base = ValidationBase {
            catalog,
            programs: vec![],
        }
        .prepare(&[EXAMPLE], &[], false)
        .unwrap();
        let output =
            catalog::addition::compile_with_base(&[EXAMPLE], &[], trust, Some(base)).unwrap();
        let candidate = output.program["extensions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["extension_id"] == "command.example-cli")
            .unwrap();
        assert_eq!(candidate["trust_class"], "external");
        assert_eq!(candidate["publisher"]["id"], "community");
    }

    #[test]
    fn reference_visit_budget_is_independent_of_hash_validity_and_file_io() {
        let directory = tempfile::tempdir().unwrap();
        let mut reader = Reader {
            directory: directory.path(),
            visits: MAX_VISITED_REFS,
            bytes: 0,
        };
        let reference = ObjectRef {
            sha256: "0".repeat(64),
            length: 2,
            expanded_length: 2,
            kind: "data".to_owned(),
        };
        assert_eq!(
            reader.value(&reference, true).unwrap_err(),
            "command_source_metadata_reference_budget_exceeded"
        );
    }
}
