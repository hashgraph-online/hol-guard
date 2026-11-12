//! Only explicit local registration probes Python. Listing reads metadata.
use super::*;
use std::sync::{atomic::AtomicBool, Arc};

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Interpreter {
    pub schema: String,
    pub interpreter_id: String,
    pub python: PathBuf,
    pub python_sha256: String,
    pub facts: InterpreterFacts,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed_python: Option<super::managed_python::ManagedPython>,
}
fn identity(python: &Path, sha256: &str, facts: &InterpreterFacts) -> Result<String, String> {
    let bytes = serde_json::to_vec(&("guard-cigar-interpreter-id.v1", python, sha256, facts))
        .map_err(|_| error("interpreter_invalid"))?;
    Ok(format!("python:{:x}", Sha256::digest(bytes)))
}
impl Interpreter {
    fn validate(&self, home: &Path) -> Result<(), String> {
        if !self.python.is_absolute()
            || self
                .python
                .components()
                .any(|p| matches!(p, std::path::Component::ParentDir))
            || !is_lower_hex(&self.python_sha256, 64)
            || guard_context_assistance::check_interpreter(&self.facts).is_err()
        {
            return Err(error("interpreter_invalid"));
        }
        if self.managed_python.is_some() {
            super::managed_python::resolve(home, self)?;
        } else if self.schema != "guard-cigar-interpreter-installation.v1"
            || self.interpreter_id != identity(&self.python, &self.python_sha256, &self.facts)?
        {
            return Err(error("interpreter_invalid"));
        }
        Ok(())
    }
    pub fn python_bundle(&self) -> Option<guard_context_assistance::PrivatePythonSelection> {
        self.managed_python
            .as_ref()
            .map(|managed| managed.selection.clone())
    }
    pub fn metadata(&self) -> Value {
        json!({"interpreter_id":self.interpreter_id,"python_version":self.facts.version,
            "platform":self.facts.platform,"implementation":self.facts.implementation,"abi":self.facts.abi,
            "managed":self.managed_python.is_some(),
            "build_id":self.managed_python.as_ref().map(|value| &value.selection.binding.build_id)})
    }
}
pub(super) fn load_interpreter(home: &Path, id: &str) -> Result<Interpreter, String> {
    if !valid_id(id) {
        return Err(error("interpreter_invalid"));
    }
    let path = store::directory(home, "interpreters", false)?.join(record_name(id));
    let record: Interpreter = store::private_read(home, &path, 16 * 1024, "cigar_interpreter")?
        .ok_or_else(|| error("interpreter_missing"))?;
    record.validate(home)?;
    if record.interpreter_id != id {
        return Err(error("interpreter_invalid"));
    }
    Ok(record)
}
pub(super) fn interpreters(home: &Path) -> Result<Vec<Value>, String> {
    let path = home.join("context-assistance/interpreters");
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err(error("interpreter_storage_unavailable")),
        Ok(_) => {}
    }
    let mut records = Vec::new();
    let directory = store::directory(home, "interpreters", false)?;
    for (index, entry) in fs::read_dir(directory)
        .map_err(|_| error("interpreter_storage_unavailable"))?
        .take(35)
        .enumerate()
    {
        if index >= 34 {
            return Err(error("interpreter_limit"));
        }
        let entry = entry.map_err(|_| error("interpreter_storage_unavailable"))?;
        if entry.file_name() == "probe-work" {
            continue;
        }
        if entry
            .file_name()
            .to_str()
            .is_some_and(store::temporary_name)
        {
            continue;
        }
        let record: Interpreter =
            store::private_read(home, &entry.path(), 16 * 1024, "cigar_interpreter")?
                .ok_or_else(|| error("interpreter_invalid"))?;
        record.validate(home)?;
        if entry.file_name() != std::ffi::OsStr::new(&record_name(&record.interpreter_id)) {
            return Err(error("interpreter_invalid"));
        }
        records.push(record.metadata());
        if records.len() > 16 {
            return Err(error("interpreter_limit"));
        }
    }
    records.sort_by(|a, b| {
        a["interpreter_id"]
            .as_str()
            .cmp(&b["interpreter_id"].as_str())
    });
    Ok(records)
}
pub(super) fn register_interpreter(home: &Path, python: &Path) -> Result<Interpreter, String> {
    super::worker::policy(home)?;
    super::managed_python::refuse_external_alias(home, python)?;
    let _lease = store::lease(home)?;
    let directory = store::directory(home, "interpreters", true)?;
    let work = directory.join("probe-work");
    crate::resident_state::ensure_private_directory_under(&work, home, true)
        .map_err(|_| error("interpreter_storage_unavailable"))?;
    let verified = guard_context_assistance::probe_interpreter_cancellable(
        python,
        &work,
        Arc::new(AtomicBool::new(false)),
    )
    .map_err(|e| error(e.code()))?;
    let record = Interpreter {
        schema: "guard-cigar-interpreter-installation.v1".into(),
        interpreter_id: identity(verified.path(), verified.sha256(), verified.facts())?,
        python: verified.path().to_path_buf(),
        python_sha256: verified.sha256().into(),
        facts: verified.facts().clone(),
        managed_python: None,
    };
    if let Ok(existing) = load_interpreter(home, &record.interpreter_id) {
        return Ok(existing);
    }
    let path = directory.join(record_name(&record.interpreter_id));
    if fs::symlink_metadata(&path).is_ok() {
        return Err(error("interpreter_invalid"));
    }
    if interpreters(home)?.len() >= 16 {
        return Err(error("interpreter_limit"));
    }
    let bytes = serde_json::to_vec(&record).map_err(|_| error("interpreter_invalid"))?;
    persist_private_bytes(&path, &bytes, 16 * 1024, "cigar_interpreter", home)
        .map_err(|_| error("interpreter_write_failed"))?;
    load_interpreter(home, &record.interpreter_id)
}
