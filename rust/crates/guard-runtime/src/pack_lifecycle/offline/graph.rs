use super::*;

pub(super) struct Graph<'a> {
    directory: &'a Path,
    pub objects: BTreeSet<String>,
    pub archives: BTreeSet<String>,
    pub needs: Vec<Value>,
    pub ingests: Vec<Value>,
    pub total: usize,
    pub unavailable: bool,
    values: BTreeMap<String, Value>,
    requested: BTreeSet<String>,
    requested_bytes: usize,
    expanded_bytes: usize,
}
impl<'a> Graph<'a> {
    pub fn new(directory: &'a Path) -> Self {
        Self {
            directory,
            objects: BTreeSet::new(),
            archives: BTreeSet::new(),
            needs: Vec::new(),
            ingests: Vec::new(),
            total: 0,
            unavailable: false,
            values: BTreeMap::new(),
            requested: BTreeSet::new(),
            requested_bytes: 0,
            expanded_bytes: 0,
        }
    }
    fn charge(&mut self, bytes: usize) -> Result<()> {
        self.total = self.total.checked_add(bytes).ok_or_else(invalid)?;
        if self
            .total
            .checked_add(self.requested_bytes)
            .is_none_or(|n| n > LIMIT)
        {
            return Err("offline_pack_budget_exceeded".into());
        }
        Ok(())
    }
    fn need(&mut self, reference: &Value, kind: &str) -> Result<()> {
        if reference.get("location").is_some() {
            let key = format!("{kind}:{}", reference["sha256"]);
            if self.requested.insert(key) {
                let length = reference["length"].as_u64().ok_or_else(invalid)? as usize;
                self.requested_bytes = self
                    .requested_bytes
                    .checked_add(length)
                    .ok_or_else(invalid)?;
                if self
                    .requested_bytes
                    .checked_add(self.total)
                    .is_none_or(|n| n > LIMIT)
                {
                    return Err("offline_pack_budget_exceeded".into());
                }
                self.needs.push(json!({"kind":kind,"reference":reference}));
            }
        } else {
            self.unavailable = true;
        }
        Ok(())
    }
    pub(super) fn retain_expansion(&mut self, length: usize) -> Result<()> {
        self.expanded_bytes = self
            .expanded_bytes
            .checked_add(length)
            .ok_or_else(invalid)?;
        if self.expanded_bytes > LIMIT {
            return Err("offline_pack_expansion_budget_exceeded".into());
        }
        Ok(())
    }
    pub fn blob(&mut self, reference: &Value, depth: usize) -> Result<Option<Vec<u8>>> {
        let sha = reference["sha256"]
            .as_str()
            .filter(|s| hex(s, 64))
            .ok_or_else(invalid)?;
        let length = reference["length"]
            .as_u64()
            .filter(|n| *n > 0 && *n <= 65536)
            .ok_or_else(invalid)? as usize;
        let expanded = reference["expanded_length"]
            .as_u64()
            .filter(|n| *n > 0 && *n <= 8 * 1024 * 1024)
            .ok_or_else(invalid)? as usize;
        if depth > 4 || !matches!(reference["kind"].as_str(), Some("data" | "concat")) {
            return Err(invalid());
        }
        let path = self.directory.join("objects").join(format!("{sha}.json"));
        if !path.try_exists().map_err(|_| invalid())? {
            self.need(reference, "object")?;
            return Ok(None);
        }
        let bytes = read(&path, 65536)?;
        if bytes.len() != length || hash(&bytes) != sha {
            return Err(invalid());
        }
        if self.objects.insert(sha.into()) {
            self.charge(length)?;
        }
        if reference["kind"] == "data" {
            if length != expanded {
                return Err(invalid());
            }
            return Ok(Some(bytes));
        }
        let value = decode(&bytes)?;
        if !matches!(
            value["schema"].as_str(),
            Some("guard.pack-concat.v1" | "guard.delivery-concat.v2")
        ) {
            return Err(invalid());
        }
        let parts = value["parts"]
            .as_array()
            .filter(|a| !a.is_empty() && a.len() <= 64)
            .ok_or_else(invalid)?;
        let mut output = Vec::new();
        let mut missing = false;
        for part in parts {
            if let Some(bytes) = self.blob(part, depth + 1)? {
                if output.len() + bytes.len() > expanded {
                    return Err(invalid());
                }
                output.extend(bytes);
            } else {
                missing = true;
            }
        }
        if missing {
            return Ok(None);
        }
        if output.len() != expanded {
            return Err(invalid());
        }
        Ok(Some(output))
    }
    fn archive(&mut self, reference: &Value) -> Result<()> {
        let sha = reference["sha256"]
            .as_str()
            .filter(|s| hex(s, 64))
            .ok_or_else(invalid)?;
        let length = reference["length"]
            .as_u64()
            .filter(|n| *n > 0 && *n <= 32 * 1024 * 1024)
            .ok_or_else(invalid)? as usize;
        if self.archives.contains(sha) {
            return Ok(());
        }
        let path = self.directory.join("archives").join(format!("{sha}.zip"));
        if !path.try_exists().map_err(|_| invalid())? {
            self.need(reference, "archive")?;
            return Ok(());
        }
        let bytes = read(&path, 32 * 1024 * 1024)?;
        if bytes.len() != length || hash(&bytes) != sha {
            return Err(invalid());
        }
        let members = archive::members(&bytes)?;
        // Every referenced member must already have been atomically ingested.
        // A crash between transfer and ingest simply requests the archive again.
        let mut missing = Vec::new();
        for (id, begin, size) in members {
            let path = self.directory.join("objects").join(format!("{id}.json"));
            if !path.try_exists().map_err(|_| invalid())? {
                missing.push(json!([id, begin, size]));
                continue;
            }
            if read(&path, 65536)? != bytes[begin..begin + size] {
                return Err(invalid());
            }
            if self.objects.insert(id) {
                self.charge(size)?;
            }
        }
        if !missing.is_empty() {
            self.ingests.push(json!({"sha256":sha,"members":missing}));
        }
        self.archives.insert(sha.into());
        self.charge(length)
    }
    pub fn walk(&mut self, value: &Value, depth: usize) -> Result<()> {
        if depth > 96 {
            return Err(invalid());
        }
        if value.get("sha256").is_some() && value.get("expanded_length").is_some() {
            let sha = value["sha256"].as_str().ok_or_else(invalid)?.to_owned();
            // Verify each reference's declared bounds, even when its object was seen.
            if let Some(bytes) = self.blob(value, 0)? {
                if self.values.contains_key(&sha) {
                    return Ok(());
                }
                // Shared chunks can otherwise amplify a small transfer into
                // unbounded distinct decoded concatenations retained in memory.
                self.retain_expansion(bytes.len())?;
                let decoded = decode(&bytes)?;
                self.values.insert(sha, decoded.clone());
                self.walk(&decoded, depth + 1)?;
            }
            return Ok(());
        }
        match value {
            Value::Array(rows) => {
                for row in rows {
                    self.walk(row, depth + 1)?;
                }
            }
            Value::Object(map) => {
                // Populate policy objects before following unlocated native refs.
                if let Some(archives) = map.get("archives") {
                    for archive in archives
                        .as_array()
                        .filter(|a| !a.is_empty() && a.len() <= 64)
                        .ok_or_else(invalid)?
                    {
                        self.archive(archive)?;
                    }
                }
                for (key, child) in map {
                    if key != "archives" {
                        self.walk(child, depth + 1)?;
                    }
                }
            }
            _ => (),
        }
        Ok(())
    }
    fn value(&self, reference: &Value) -> Result<&Value> {
        self.values
            .get(reference["sha256"].as_str().ok_or_else(invalid)?)
            .ok_or_else(invalid)
    }
    pub(super) fn index(
        &self,
        reference: &Value,
        count: usize,
        prefix: &str,
        ids: &mut BTreeMap<String, Value>,
    ) -> Result<()> {
        if count == 0 || count > 1048576 || prefix.len() > 64 {
            return Err(invalid());
        }
        let page = self.value(reference)?;
        if page["schema"] != "guard.pack-index.v1" || page["prefix"] != prefix {
            return Err(invalid());
        }
        if page["kind"] == "leaf" {
            let rows = page["entries"]
                .as_array()
                .filter(|a| a.len() == count && a.len() <= 64)
                .ok_or_else(invalid)?;
            let mut previous = "";
            for row in rows {
                let row = row
                    .as_array()
                    .filter(|a| a.len() == 2)
                    .ok_or_else(invalid)?;
                let id = row[0]
                    .as_str()
                    .filter(|s| !s.is_empty() && s.len() <= 256 && s.is_ascii())
                    .ok_or_else(invalid)?;
                if id <= previous
                    || !hash(id.as_bytes()).starts_with(prefix)
                    || ids.insert(id.into(), row[1].clone()).is_some()
                {
                    return Err(invalid());
                }
                previous = id;
            }
        } else if page["kind"] == "branch" {
            let rows = page["children"]
                .as_array()
                .filter(|a| !a.is_empty() && a.len() <= 16)
                .ok_or_else(invalid)?;
            let mut total = 0;
            let mut previous = "";
            for row in rows {
                let row = row
                    .as_array()
                    .filter(|a| a.len() == 3)
                    .ok_or_else(invalid)?;
                let key = row[0].as_str().ok_or_else(invalid)?;
                let size = row[1]
                    .as_u64()
                    .filter(|n| *n > 0 && *n <= count as u64)
                    .ok_or_else(invalid)? as usize;
                if key <= previous
                    || key.len() != prefix.len() + 1
                    || !key.starts_with(prefix)
                    || !hex(key, key.len())
                {
                    return Err(invalid());
                }
                total += size;
                if total > count {
                    return Err(invalid());
                }
                self.index(&row[2], size, key, ids)?;
                previous = key;
            }
            if total != count {
                return Err(invalid());
            }
        } else {
            return Err(invalid());
        }
        Ok(())
    }
    fn transport(&self, reference: &Value, native: &Value) -> Result<()> {
        let wrapper = self.value(reference)?;
        let mut bound = wrapper["native"].clone();
        bound
            .as_object_mut()
            .ok_or_else(invalid)?
            .remove("location");
        if wrapper["schema"] != "guard.policy-transport.v2" || bound != *native {
            return Err(invalid());
        }
        let page = self.value(native)?;
        if wrapper["kind"] != page["kind"] {
            return Err(invalid());
        }
        let leaf = page["kind"] == "leaf";
        let rows = wrapper[if leaf { "records" } else { "children" }]
            .as_array()
            .ok_or_else(invalid)?;
        let native_rows = page[if leaf { "entries" } else { "children" }]
            .as_array()
            .ok_or_else(invalid)?;
        if rows.len() != native_rows.len() {
            return Err(invalid());
        }
        for (row, expected) in rows.iter().zip(native_rows) {
            if leaf {
                let record = self.value(&row[1])?;
                if row[0] != expected[0]
                    || record["extension_id"] != row[0]
                    || record["manifest"] != expected[1]
                    || record["schema"] != "guard.policy-delivery.v2"
                {
                    return Err(invalid());
                }
                let manifest = self.value(&expected[1])?;
                let catalog = self.value(&record["catalog_metadata"])?;
                let related = manifest["related_interfaces"]
                    .as_object()
                    .ok_or_else(invalid)?;
                let related = Value::Array(related.keys().cloned().map(Value::String).collect());
                if catalog != self.value(&manifest["catalog"])?
                    || catalog.as_array().is_none_or(|a| a.len() != 1)
                    || manifest["extension_id"] != record["extension_id"]
                    || related != record["related_interfaces"]
                {
                    return Err(invalid());
                }
                for field in ["dependencies", "trust_class", "required", "activation"] {
                    if record[field] != catalog[0][field] {
                        return Err(invalid());
                    }
                }
            } else {
                if row[0] != expected[0] || row[1] != expected[1] {
                    return Err(invalid());
                }
                self.transport(&row[2], &expected[2])?;
            }
        }
        Ok(())
    }
    pub fn validate(&self, root: &Value) -> Result<()> {
        let policy = &root["policy"];
        let release = &policy["root"];
        let count = release["extensions"]
            .as_u64()
            .filter(|n| *n > 0 && *n <= 32768)
            .ok_or_else(invalid)? as usize;
        let mut ids = BTreeMap::new();
        self.index(&release["index"], count, "", &mut ids)?;
        self.transport(&policy["transport"], &release["index"])?;
        for row in [
            Some(&policy["defaults"]),
            Some(&policy["revocations"]),
            root.get("compatibility").map(|c| &c["commands"]),
            root.get("compatibility").map(|c| &c["mcp"]),
        ]
        .into_iter()
        .flatten()
        {
            let count = row["count"].as_u64().ok_or_else(invalid)? as usize;
            if count == 0 {
                if !row["index"].is_null() {
                    return Err(invalid());
                }
            } else {
                self.index(&row["index"], count, "", &mut BTreeMap::new())?;
            }
        }
        let bytes = guard_policy_snapshot::canonical_json_bytes(release).map_err(|_| invalid())?;
        let directory = self.directory;
        // Complete production admission verifies program digests, ancestry of
        // every matcher, ownership, engine, profiles and cross-pack dependencies.
        guard_command::native_command_program::NativeCommandProgram::from_integrity_bound_packs(
            &bytes,
            &hash(&bytes),
            &ids.keys().cloned().collect(),
            guard_command::native_command_program::PackAdmissionBudget::resident(),
            |id| {
                guard_secure_fs::read_bounded(
                    &directory.join("objects").join(format!("{id}.json")),
                    65536,
                )
                .map(|r| r.bytes)
                .map_err(|_| "offline_pack_unavailable")
            },
        )
        .map_err(str::to_owned)?;
        Ok(())
    }
}
