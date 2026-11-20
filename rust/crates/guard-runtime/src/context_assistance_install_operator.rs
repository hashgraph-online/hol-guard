//! Explicit advanced local setup; not reachable from paired/browser requests.
use super::*;
use std::collections::BTreeMap;

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum OperatorAction {
    ConfigureCatalogFeed {
        feed: super::super::catalog::feed::Feed,
    },
    ConfigureCatalogTrust {
        authority: super::super::catalog::Authority,
    },
    ImportCatalog {
        file: PathBuf,
    },
    RegisterInterpreter {
        python: PathBuf,
    },
    ImportInterpreterArchive {
        build_id: String,
        platform: String,
        file: PathBuf,
    },
    ImportWheels {
        build_id: String,
        platform: String,
        files: BTreeMap<String, PathBuf>,
    },
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    guard_home: PathBuf,
    operator_approved: bool,
    operation: OperatorAction,
}
pub(crate) fn run_operator_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(64 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| error("request_unreadable"))?;
    if bytes.len() > 64 * 1024 {
        return Err(error("request_too_large"));
    }
    let request: Request = crate::strict_json_value(&bytes).and_then(|value| {
        crate::strict_json::from_value(value).map_err(|_| error("install_operator_request_invalid"))
    })?;
    let result = (|| {
        if request.schema != "guard-cigar-install-operator.v1"
            || !request.operator_approved
            || !request.guard_home.is_absolute()
            || request
                .guard_home
                .components()
                .any(|p| matches!(p, std::path::Component::ParentDir))
        {
            return Err(error("install_operator_approval_required"));
        }
        match request.operation {
            OperatorAction::ConfigureCatalogFeed { feed } => {
                super::super::catalog::feed::configure(&request.guard_home, feed)
            }
            OperatorAction::ConfigureCatalogTrust { authority } => {
                super::super::catalog::configure(&request.guard_home, authority)
            }
            OperatorAction::ImportCatalog { file } => {
                let data = guard_secure_fs::read_stable(
                    &file,
                    guard_cigar_release::MAX_ENVELOPE_BYTES,
                    false,
                )
                .map_err(|_| error("cigar_catalog_import_unreadable"))?;
                super::super::catalog::import(&request.guard_home, &data.bytes)
            }
            OperatorAction::RegisterInterpreter { python } => Ok(
                json!({"interpreter":interpreters::register_interpreter(&request.guard_home, &python)?.metadata(),"activation_granted":false}),
            ),
            OperatorAction::ImportInterpreterArchive {
                build_id,
                platform,
                file,
            } => {
                let catalog = super::super::catalog::fresh(&request.guard_home)?;
                catalog.check_python(&build_id)?;
                let build = catalog
                    .catalog
                    .prepare_interpreter(&build_id, &platform)
                    .map_err(|e| error(e.code()))?;
                python_cache::import(&request.guard_home, &build, &file)?;
                Ok(json!({"build_id":build_id,"artifacts_cached":true,"activation_granted":false}))
            }
            OperatorAction::ImportWheels {
                build_id,
                platform,
                files,
            } => {
                let catalog = super::super::catalog::fresh(&request.guard_home)?;
                catalog.check_sdk(&build_id)?;
                let release = catalog
                    .catalog
                    .prepare(&build_id, &platform, false)
                    .map_err(|e| error(e.code()))?;
                cache::import(&request.guard_home, &release, &files)?;
                Ok(json!({"build_id":build_id,"artifacts_cached":true,"activation_granted":false}))
            }
        }
    })();
    let value = match result {
        Ok(data) => json!({"ok":true,"data":data}),
        Err(code) => json!({"ok":false,"code":code}),
    };
    serde_json::to_vec(&value).map_err(|_| error("response_invalid"))
}
