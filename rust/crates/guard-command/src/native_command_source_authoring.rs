//! Offline authoring planning. The transport adapter supplies bytes from its
//! fixed verified release; this operation grants no publisher or runtime trust.
use super::packs::objects::{read_blob, ObjectRef, ObjectWriter};
use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use std::io::{BufRead, Read, Write};
#[path = "native_command_source_authoring_transport.rs"]
mod transport;

pub(crate) struct Exchange<R, W> {
    input: R,
    output: W,
    visits: usize,
    bytes: usize,
    source: Option<String>,
    byte_limit: usize,
    fetched: BTreeMap<String, Vec<u8>>,
}
impl<R: BufRead, W: Write> Exchange<R, W> {
    pub(crate) fn installed(input: R, output: W, source: String, byte_limit: usize) -> Self {
        Self {
            input,
            output,
            visits: 0,
            bytes: 0,
            source: Some(source),
            byte_limit,
            fetched: BTreeMap::new(),
        }
    }
    pub(crate) fn bind_installed(&mut self, source: String, byte_limit: usize) {
        self.source = Some(source);
        self.byte_limit = byte_limit;
    }
    pub(crate) fn line_bytes(&mut self) -> Result<Vec<u8>, &'static str> {
        let mut bytes = Vec::new();
        self.input
            .by_ref()
            .take((MAX_SOURCE_INPUT_BYTES + 1) as u64)
            .read_until(b'\n', &mut bytes)
            .map_err(|_| "authoring_transport_read_failed")?;
        if bytes.len() > MAX_SOURCE_INPUT_BYTES || bytes.last() != Some(&b'\n') {
            return Err("authoring_transport_record_invalid");
        }
        Ok(bytes)
    }
    fn line(&mut self) -> Result<Value, &'static str> {
        json::decode(&self.line_bytes()?)
    }
    pub(crate) fn event(&mut self, value: &Value) -> Result<(), &'static str> {
        serde_json::to_writer(&mut self.output, value)
            .map_err(|_| "authoring_transport_write_failed")?;
        self.output
            .write_all(b"\n")
            .and_then(|_| self.output.flush())
            .map_err(|_| "authoring_transport_write_failed")
    }
    fn fetch(&mut self, reference: &Value) -> Result<Vec<u8>, &'static str> {
        self.visits += 1;
        if self.visits > 300_000 {
            return Err("authoring_transport_reference_budget_exceeded");
        }
        if let Some(source) = &self.source {
            if !reference["location"]["tag"]
                .as_str()
                .is_some_and(|tag| tag.starts_with(&format!("extension-data-{source}-0.0-")))
            {
                return Err("installed compatibility metadata source invalid");
            }
            if let Some(bytes) = reference["sha256"]
                .as_str()
                .and_then(|sha| self.fetched.get(sha))
            {
                return Ok(bytes.clone());
            }
        }
        self.event(&serde_json::json!({"kind":"fetch", "reference":reference}))?;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Response {
            data: String,
        }
        let response: Response = serde_json::from_slice(&self.line_bytes()?)
            .map_err(|_| "authoring_transport_response_invalid")?;
        let bytes = STANDARD
            .decode(response.data)
            .map_err(|_| "authoring_transport_response_invalid")?;
        if bytes.len() > 65536 {
            return Err("authoring_transport_response_invalid");
        }
        self.bytes += bytes.len();
        if self.bytes > self.byte_limit {
            return Err(if self.source.is_some() {
                "installed compatibility metadata exceeds byte budget"
            } else {
                "authoring_transport_byte_budget_exceeded"
            });
        }
        if self.source.is_some() {
            self.fetched.insert(
                reference["sha256"]
                    .as_str()
                    .ok_or("authoring_reference_invalid")?
                    .to_owned(),
                bytes.clone(),
            );
        }
        Ok(bytes)
    }
    fn value(&mut self, reference: &Value) -> Result<Value, &'static str> {
        if reference.get("location").is_some() {
            return json::decode_value(
                &self.located(reference, 0)?,
                json::MAX_PROGRAM_OBJECT_MEMBERS,
            );
        }
        let object: ObjectRef =
            serde_json::from_value(reference.clone()).map_err(|_| "authoring_reference_invalid")?;
        let bytes = read_blob(&object, &mut |sha| {
            let mut target = serde_json::json!({"sha256":sha});
            if sha == object.sha256 {
                target = reference.clone();
            }
            self.fetch(&target)
        })?;
        json::decode_value(&bytes, json::MAX_PROGRAM_OBJECT_MEMBERS)
    }
    pub(crate) fn located(
        &mut self,
        reference: &Value,
        depth: usize,
    ) -> Result<Vec<u8>, &'static str> {
        if depth > 4 {
            return Err("authoring_reference_depth_invalid");
        }
        let mut raw = reference.clone();
        raw.as_object_mut()
            .ok_or("authoring_reference_invalid")?
            .remove("location");
        let object: ObjectRef =
            serde_json::from_value(raw).map_err(|_| "authoring_reference_invalid")?;
        if !transport::location_valid(&reference["location"], &object.sha256, "object") {
            return Err("authoring_location_invalid");
        }
        let expanded = object.expanded_length;
        if expanded == 0
            || expanded > 8 * 1024 * 1024
            || !matches!(object.kind.as_str(), "data" | "concat")
        {
            return Err("authoring_reference_invalid");
        }
        let data_ref = ObjectRef {
            kind: "data".to_owned(),
            expanded_length: object.length,
            ..object.clone()
        };
        let bytes = read_blob(&data_ref, &mut |_| self.fetch(reference))?;
        if object.kind == "data" {
            if bytes.len() != expanded {
                return Err("authoring_reference_length_invalid");
            }
            return Ok(bytes);
        }
        let value = json::decode(&bytes)?;
        let parts = value["parts"]
            .as_array()
            .filter(|v| !v.is_empty() && v.len() <= 64)
            .ok_or("authoring_concat_invalid")?;
        if value["schema"] != "guard.delivery-concat.v2"
            || value.as_object().is_none_or(|v| v.len() != 2)
        {
            return Err("authoring_concat_invalid");
        }
        let mut result = Vec::new();
        for part in parts {
            let part = self.located(part, depth + 1)?;
            if result.len() + part.len() > expanded {
                return Err("authoring_reference_length_invalid");
            }
            result.extend(part);
        }
        if result.len() != expanded {
            return Err("authoring_reference_length_invalid");
        }
        Ok(result)
    }
}

fn references(entry: &Value, owners: &BTreeMap<String, String>) -> BTreeSet<String> {
    let mut result = BTreeSet::new();
    if let Some(values) = entry["dependencies"].as_array() {
        result.extend(values.iter().filter_map(Value::as_str).map(str::to_owned));
    }
    if let Some(permissions) = entry["permissions"].as_array() {
        for permission in permissions {
            for field in ["dependencies", "implied_permissions"] {
                if let Some(values) = permission[field].as_array() {
                    result.extend(
                        values
                            .iter()
                            .filter_map(Value::as_str)
                            .filter_map(|id| owners.get(id))
                            .cloned(),
                    );
                }
            }
        }
    }
    result
}

fn selection(catalog: &[Value], request: &Value) -> Result<BTreeSet<String>, &'static str> {
    let mut by_id = BTreeMap::new();
    let mut owners = BTreeMap::new();
    for entry in catalog {
        let id = entry["extension_id"]
            .as_str()
            .ok_or("command_source_interface_invalid")?;
        if by_id.insert(id.to_owned(), entry).is_some() {
            return Err("command_source_extension_duplicate");
        }
        for permission in entry["permissions"]
            .as_array()
            .ok_or("command_source_interface_invalid")?
        {
            let permission = permission["permission_id"]
                .as_str()
                .ok_or("command_source_interface_invalid")?;
            if owners
                .insert(permission.to_owned(), id.to_owned())
                .is_some()
            {
                return Err("command_source_permission_duplicate");
            }
        }
    }
    let core: Value =
        serde_json::from_slice(crate::native_command_catalog::embedded_catalog_bytes())
            .map_err(|_| "command_source_packaged_base_invalid")?;
    let core_ids: BTreeSet<_> = core["catalog"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["extension_id"].as_str().unwrap().to_owned())
        .collect();
    let mut selected = core_ids.clone();
    let mut pending = BTreeSet::new();
    for source in request["sources"]
        .as_array()
        .ok_or("command_source_build_contract_invalid")?
    {
        let entry = &source["extension"];
        pending.extend(references(entry, &owners));
        if let Some(id) = entry["extension_id"]
            .as_str()
            .filter(|id| by_id.contains_key(*id))
        {
            pending.insert(id.to_owned());
        }
    }
    if let Some(sources) = request["mcp_sources"].as_array() {
        for source in sources {
            let lowered = mcp::lower(
                &serde_json::to_vec(source).map_err(|_| "command_source_encoding_failed")?,
            )?;
            let id = lowered.document.extension.extension_id;
            if by_id.contains_key(&id) {
                pending.insert(id);
            }
        }
    }
    while let Some(id) = pending.pop_first() {
        if selected.contains(&id) {
            continue;
        }
        if let Some(entry) = by_id.get(&id) {
            selected.insert(id);
            if selected.len() > 512 {
                return Err("command_source_authoring_dependency_budget_exceeded");
            }
            pending.extend(references(entry, &owners));
        }
    }
    Ok(selected.difference(&core_ids).cloned().collect())
}

fn index(catalog: &[Value], context: &str, output: impl Write) -> Result<Value, &'static str> {
    let mut writer = ObjectWriter::new(output);
    let mut entries = BTreeMap::new();
    let mut total = 0usize;
    for entry in catalog {
        let id = entry["extension_id"]
            .as_str()
            .ok_or("command_source_interface_invalid")?;
        let reference = writer.json(entry)?;
        total += reference.expanded_length;
        if total > 128 * 1024 * 1024 || entries.insert(id.to_owned(), reference).is_some() {
            return Err("command_source_metadata_inventory_invalid");
        }
    }
    let rows: Vec<_> = entries.into_iter().collect();
    let mut next = None;
    for chunk in rows.rchunks(64) {
        next = Some(writer.json(&serde_json::json!({"schema":"guard.authoring-metadata-page.v1", "entries":chunk,"next":next}))?);
    }
    let root = writer.json(&serde_json::json!({"schema":"guard.authoring-metadata.v1", "engine":env!("GUARD_COMMAND_SOURCE_IMPLEMENTATION"),"source_context":context,"count":rows.len(),"total_bytes":total,"pages":rows.len().div_ceil(64),"first":next}))?;
    Ok(serde_json::json!({"root":root,"source_context":context}))
}

pub fn authoring_context() -> Result<Value, &'static str> {
    let mut io = Exchange {
        input: std::io::stdin().lock(),
        output: std::io::stdout().lock(),
        visits: 0,
        bytes: 0,
        source: None,
        byte_limit: 512 * 1024 * 1024,
        fetched: BTreeMap::new(),
    };
    let input = io.line()?;
    let context = input["source_context"]
        .as_str()
        .ok_or("authoring_source_context_invalid")?;
    if context.len() != 64
        || !context
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err("authoring_source_context_invalid");
    }
    let (catalog, manifests) = transport::inventory(&input, &mut io)?;
    // Check every global interface before selecting any policy payload.
    let sources = input["request"]["sources"]
        .as_array()
        .ok_or("command_source_build_contract_invalid")?
        .iter()
        .map(serde_json::to_vec)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "command_source_encoding_failed")?;
    let mcp_sources = input["request"]["mcp_sources"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(serde_json::to_vec)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "command_source_encoding_failed")?;
    let fixture = input["fixture"].as_bool().unwrap_or(false);
    baseline::ValidationBase {
        catalog: catalog.clone(),
        programs: vec![],
    }
    .prepare(
        &sources.iter().map(Vec::as_slice).collect::<Vec<_>>(),
        &mcp_sources.iter().map(Vec::as_slice).collect::<Vec<_>>(),
        fixture,
    )?;
    if let Some(admission) = input.get("admission") {
        return super::admission::with_catalog(admission, &catalog);
    }
    let selected = selection(&catalog, &input["request"])?;
    let mut programs = Vec::new();
    for id in &selected {
        let mut manifest = manifests
            .get(id)
            .ok_or("authoring_selected_manifest_missing")?
            .clone();
        if input["mode"] == "installed" {
            for archive in manifest["archives"]
                .as_array()
                .ok_or("authoring_archives_invalid")?
            {
                io.event(&serde_json::json!({"kind":"archive", "reference":archive}))?;
                if io.line()?["ok"] != true {
                    return Err("authoring_archive_unavailable");
                }
            }
            manifest = io.value(&manifest["manifest"])?;
        }
        let entry = io.value(&manifest["catalog"])?;
        if entry.as_array()
            != Some(&vec![catalog
                .iter()
                .find(|entry| entry["extension_id"] == *id)
                .unwrap()
                .clone()])
        {
            return Err("command_source_interface_program_mismatch");
        }
        let mut program = io.value(&manifest["program"])?;
        for reference in program["nodes"]
            .as_object_mut()
            .ok_or("authoring_program_invalid")?
            .values_mut()
        {
            *reference = io.value(reference)?;
        }
        programs.push(program);
    }
    let handle = index(&catalog, context, &mut io.output)?;
    Ok(
        serde_json::json!({"kind":"context","metadata_index":handle,"programs":programs,"selected":selected}),
    )
}

/// Integrity-only index production for maintainer tooling. This cannot select
/// an installed authority or make its input a trusted release.
pub fn authoring_index() -> Result<Value, &'static str> {
    let mut io = Exchange {
        input: std::io::stdin().lock(),
        output: std::io::stdout().lock(),
        visits: 0,
        bytes: 0,
        source: None,
        byte_limit: 512 * 1024 * 1024,
        fetched: BTreeMap::new(),
    };
    let header = io.line()?;
    let count = header["count"]
        .as_u64()
        .filter(|n| *n > 0 && *n <= 100_000)
        .ok_or("command_source_metadata_count_invalid")?;
    if header["engine"] != env!("GUARD_COMMAND_SOURCE_IMPLEMENTATION") {
        return Err("command_source_metadata_engine_invalid");
    }
    let context = header["source_context"]
        .as_str()
        .ok_or("authoring_source_context_invalid")?;
    let mut catalog = Vec::new();
    let mut bytes = 0;
    for _ in 0..count {
        let entry = io.line()?;
        bytes += serde_json::to_vec(&entry)
            .map_err(|_| "command_source_encoding_failed")?
            .len();
        if bytes > 128 * 1024 * 1024 {
            return Err("command_source_metadata_byte_budget_exceeded");
        }
        catalog.push(entry);
    }
    Ok(
        serde_json::json!({"kind":"index","metadata_index":index(&catalog, context, &mut io.output)?}),
    )
}
