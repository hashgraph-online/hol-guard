//! Record result delivery only after verifying the native completion journal.
use crate::policy_store::PolicySnapshotStore;
use guard_contracts::{NativeBashAckRequestV1, NativeBashAckResultV1};

pub(crate) fn evaluate(
    request: &NativeBashAckRequestV1,
    store: &PolicySnapshotStore,
) -> Result<Vec<u8>, String> {
    let request_sha256 = crate::package_authority_op::request_digest_with_limit(request, 16 * 1024)
        .map_err(|_| "native_bash_ack_request_too_large")?;
    store.require_guard_home(&request.guard_home)?;
    store.require_store_path(&request.store_path)?;
    let mut result = NativeBashAckResultV1 {
        schema: "guard-native-bash-ack-result.v1".into(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: "error".into(),
        code: "native_bash_ack_invalid".into(),
        acknowledged: false,
    };
    if request.schema == "guard-native-bash-ack-request.v1"
        && !request.request_id.is_empty()
        && request.request_id.len() <= 256
        && matches!(request.harness.as_str(), "omp" | "pi")
        && (0..=255).contains(&request.exit_code)
    {
        #[cfg(target_os = "macos")]
        {
            use crate::policy_store::policy_store_approval::bash_journal::BashOperationJournal;
            let acknowledged =
                BashOperationJournal::open(store, &request.store_path, &request.base_id, "")
                    .map_err(|_| ())
                    .and_then(|journal| {
                        journal
                            .acknowledge_invocation(
                                &request.harness,
                                &request.project,
                                &request.tool_call_id,
                                request.exit_code,
                            )
                            .map_err(|_| ())
                    });
            if let Ok(acknowledged) = acknowledged {
                result.status = "ok".into();
                result.code = "ok".into();
                result.acknowledged = acknowledged;
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            result.status = "unavailable".into();
            result.code = "bash_execution_binding_unavailable_platform".into();
        }
    }
    crate::encode_response(&result)
}
