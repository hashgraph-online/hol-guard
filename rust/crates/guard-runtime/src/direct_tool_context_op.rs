//! Resident-owned local tool recognition; one admitted request builds the context.
use std::collections::BTreeMap;
use std::path::Path;

use guard_command::direct_vitest::{self, DirectToolAuthority};
use guard_contracts::{
    DirectToolV1, RequestContextBuildV1, RequestContextDirectFactsV1, RequestContextDirectToolV1,
    RequestContextRequestV1, RequestContextTrustedToolV1, MAX_REQUEST_CONTEXT_PATH_BYTES,
    MAX_REQUEST_CONTEXT_SCRIPT_BYTES,
};
use serde_json::{json, Value};

use crate::git_execution_safety_binary as binary;
use crate::request_context_op::Budget;

pub(crate) struct Authority<'a> {
    pub(crate) facts: &'a RequestContextDirectFactsV1,
    pub(crate) budget: &'a Budget,
}

impl DirectToolAuthority for Authority<'_> {
    fn environment(&self) -> &BTreeMap<String, String> {
        &self.facts.environment
    }
    fn temp_directory(&self) -> &Path {
        Path::new(&self.facts.temp_dir)
    }
    fn within_budget(&self) -> bool {
        self.budget.check().is_ok()
    }
    fn deadline(&self) -> Option<std::time::Instant> {
        Some(self.budget.deadline())
    }
    fn executable_file(&self, path: &Path) -> bool {
        // The legacy runner proof checks stat execute bits. PATH lookup uses
        // the shared native access check separately, as shutil.which did.
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            path.metadata()
                .is_ok_and(|metadata| metadata.is_file() && metadata.mode() & 0o111 != 0)
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            false
        }
    }
    fn trusted_path(&self, path: &Path, cwd: &Path) -> bool {
        self.within_budget()
            && binary::binary_path_is_trusted(
                path,
                cwd,
                Path::new(&self.facts.caller_home),
                &self.facts.groups,
            )
    }
    fn trusted_command(&self, command: &str, cwd: &Path, _home: &Path) -> bool {
        if !self.within_budget() {
            return false;
        }
        let Some(found) = binary::which_for_cwd(
            command,
            cwd,
            &self.facts.environment,
            Path::new(&self.facts.caller_home),
        ) else {
            return false;
        };
        let Ok(resolved) = found.canonicalize() else {
            return false;
        };
        if self.trusted_path(&resolved, cwd) {
            return true;
        }
        if command != "bun" {
            return false;
        }
        crate::direct_tool_managed_bun::trusted(self.facts, &resolved, cwd, self.budget)
    }
}

pub(crate) fn admit(
    facts: &RequestContextDirectFactsV1,
    budget: &Budget,
) -> Result<(), &'static str> {
    budget.check()?;
    for value in [
        &facts.cwd,
        &facts.home_dir,
        &facts.caller_home,
        &facts.temp_dir,
        &facts.launcher.python_executable,
        &facts.launcher.interpreter,
        &facts.launcher.import_root,
    ] {
        if value.is_empty()
            || value.len() > MAX_REQUEST_CONTEXT_PATH_BYTES
            || value.contains(['\0', '\n', '\r'])
            || !Path::new(value).is_absolute()
        {
            return Err("native_request_context_direct_path_invalid");
        }
    }
    if facts.groups.len() > 1024 || facts.environment.len() > 512 {
        return Err("native_request_context_direct_facts_too_large");
    }
    let mut bytes = 0usize;
    for (key, value) in &facts.environment {
        bytes = bytes.saturating_add(key.len()).saturating_add(value.len());
        if key.is_empty()
            || key.contains(['\0', '='])
            || value.contains('\0')
            || key.len() > 256
            || value.len() > 64 * 1024
            || bytes > 128 * 1024
        {
            return Err("native_request_context_direct_environment_invalid");
        }
    }
    Ok(())
}

pub(crate) fn direct(
    request: &RequestContextRequestV1,
    body: &RequestContextDirectToolV1,
    budget: &Budget,
) -> Result<Value, &'static str> {
    admit(&body.facts, budget)?;
    if body.script.len() > MAX_REQUEST_CONTEXT_SCRIPT_BYTES || body.script.contains('\0') {
        return Err("native_request_context_script_too_large");
    }
    let authority = Authority {
        facts: &body.facts,
        budget,
    };
    let cwd = Some(Path::new(&body.facts.cwd));
    let home = Path::new(&body.facts.home_dir);
    let context = match body.tool {
        DirectToolV1::Vitest => direct_vitest::direct_local_vitest_execution_context(
            &body.script,
            cwd,
            home,
            &authority,
        ),
        DirectToolV1::Typescript => direct_vitest::direct_local_typescript_execution_context(
            &body.script,
            cwd,
            home,
            &authority,
        ),
    };
    budget.check()?;
    let context = match context {
        None => Value::Null,
        Some(context) => {
            let shell = crate::request_context_shell::context_report(&context, budget)?;
            let build = RequestContextBuildV1 {
                cwd: Some(body.facts.cwd.clone()),
                home_dir: Some(body.facts.home_dir.clone()),
                workspace: context
                    .workspace_root
                    .as_ref()
                    .map(|p| p.to_string_lossy().into_owned()),
                script: Some(body.script.clone()),
                ..Default::default()
            };
            crate::request_context_op::build_with_shell_report(request, &build, shell, budget)?
        }
    };
    Ok(json!({"kind": "direct_tool", "accepted": !context.is_null(), "context": context}))
}

pub(crate) fn trusted(
    body: &RequestContextTrustedToolV1,
    budget: &Budget,
) -> Result<Value, &'static str> {
    admit(&body.facts, budget)?;
    if body.command.is_empty()
        || body.command.len() > MAX_REQUEST_CONTEXT_PATH_BYTES
        || body.command.contains('\0')
    {
        return Err("native_request_context_direct_command_invalid");
    }
    let authority = Authority {
        facts: &body.facts,
        budget,
    };
    let trusted = authority.trusted_command(
        &body.command,
        Path::new(&body.facts.cwd),
        Path::new(&body.facts.home_dir),
    );
    budget.check()?;
    Ok(json!({"kind": "trusted_tool", "trusted": trusted}))
}
