use std::cell::OnceCell;

use super::*;

type CloudOutcome = (Option<PackageEvalResult>, Option<Map<String, Value>>);

const INVALID_PAYLOAD: &str = "Guard Cloud sync returned an invalid response payload.";

/// Failure classes of one evaluation POST, mirroring the Python exception
/// hierarchy the evaluator branches on.
enum PostFailure {
    /// `urllib.error.HTTPError`.
    Http(u16),
    /// Other `OSError` (connection failures and timeouts).
    Os(EvalError),
    /// `RuntimeError` / `ValueError` from the transport (invalid payload,
    /// request signing failures).
    Invalid,
}

fn classify_post_failure(error: EvalError) -> PostFailure {
    match error {
        EvalError::HttpStatus(code, _) => PostFailure::Http(code),
        EvalError::Internal(message) if message == INVALID_PAYLOAD => PostFailure::Invalid,
        EvalError::Internal(message) => PostFailure::Os(EvalError::Internal(message)),
        EvalError::Validation(_) | EvalError::NotFound(_) => PostFailure::Invalid,
    }
}

/// `str(value or default)` for a JSON field.
fn string_or(map: &Map<String, Value>, key: &str, default: &str) -> String {
    match map.get(key) {
        Some(Value::String(text)) if !text.is_empty() => text.clone(),
        Some(Value::Null) | Some(Value::Bool(false)) | Some(Value::String(_)) | None => {
            default.to_owned()
        }
        Some(Value::Array(items)) if items.is_empty() => default.to_owned(),
        Some(Value::Object(items)) if items.is_empty() => default.to_owned(),
        Some(Value::Number(number)) if number.as_f64() == Some(0.0) => default.to_owned(),
        Some(other) => other.to_string(),
    }
}

fn dict_items(value: Option<&Value>) -> Vec<Map<String, Value>> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|v| v.as_object().cloned())
                .collect()
        })
        .unwrap_or_default()
}

/// What one evaluation POST (including its 401 refresh retry) produced.
enum Fetched {
    Payload(Map<String, Value>),
    /// An HTTP status that still has to be handled.
    Status(u16),
    /// A finished outcome.
    Done(Box<CloudOutcome>),
}

/// Per-request state of `_evaluate_with_cloud` (:1090-1506).
struct CloudContext<'a> {
    deps: &'a SupplyChainEvalDeps<'a>,
    store: &'a dyn SupplyChainStore,
    artifact: &'a GuardArtifact,
    targets: &'a [Map<String, Value>],
    workspace_dir: Option<&'a Path>,
    workspace_fingerprint: &'a str,
    bundle_meta: Option<&'a BTreeMap<String, String>>,
    bundle_defer_eligible: bool,
    bundle_decision: Option<&'a str>,
    fail_closed: OnceCell<String>,
    entitlement: OnceCell<Map<String, Value>>,
}

impl CloudContext<'_> {
    fn fail_closed_decision(&self) -> &str {
        self.fail_closed
            .get_or_init(|| cloud_fail_closed_decision(self.deps, self.store, self.workspace_dir))
    }

    fn explicitly_unpaid(&self) -> bool {
        let entitlement = self.entitlement.get_or_init(|| {
            self.deps
                .entitlement
                .resolve_package_firewall_entitlement_with_refresh(self.store)
                .unwrap_or_else(|_| {
                    // Unknown entitlement state is protected state.
                    let mut unknown = Map::new();
                    unknown.insert("allowed".into(), Value::Bool(false));
                    unknown.insert(
                        "reason".into(),
                        Value::String("guard_cloud_connect_required".into()),
                    );
                    unknown.insert("tier".into(), Value::String("unknown".into()));
                    unknown
                })
        });
        optional_string(entitlement.get("reason")).is_some_and(|reason| {
            reason
                .trim()
                .eq_ignore_ascii_case("paid_guard_cloud_required")
        })
    }

    fn can_fallback_from_cloud_failure(&self) -> bool {
        if self.bundle_meta.is_some()
            && self.bundle_defer_eligible
            && self.bundle_decision == Some("block")
        {
            return true;
        }
        self.explicitly_unpaid() && self.fail_closed_decision() != "block"
    }

    fn failure_decision(&self) -> String {
        if self.explicitly_unpaid() {
            self.fail_closed_decision().to_owned()
        } else {
            "block".to_owned()
        }
    }

    fn fail_closed(&self, code: &str, message: &str, decision: &str) -> CloudOutcome {
        (
            Some(cloud_fail_closed_evaluation_full(
                self.deps,
                code,
                message,
                self.artifact,
                self.targets,
                self.workspace_dir,
                Some(self.workspace_fingerprint),
                self.bundle_meta,
                decision,
            )),
            None,
        )
    }

    fn handle_os_error(&self, error: &EvalError) -> CloudOutcome {
        if self.deps.guard_sync.is_timeout_error(error) {
            if self.failure_decision() == "block" {
                // A timeout is an availability failure, not a package verdict.
                return self.fail_closed(
                    "cloud_timeout",
                    "Guard Cloud evaluation timed out, so this package request is paused for explicit review.",
                    "ask",
                );
            }
            return (
                None,
                Some(cloud_fallback_reason(
                    "cloud_timeout",
                    "Guard cloud evaluation timed out, so Guard fell back to local intelligence.",
                )),
            );
        }
        let decision = self.failure_decision();
        if decision == "block" {
            return self.fail_closed(
                "cloud_http_error",
                "Guard Cloud evaluation could not be reached, so Guard blocked the install rather than bypassing Cloud package protection.",
                &decision,
            );
        }
        (
            None,
            Some(cloud_fallback_reason(
                "cloud_http_error",
                "Guard Cloud evaluation could not be reached, so Guard used local package intelligence.",
            )),
        )
    }

    fn invalid_response(&self) -> CloudOutcome {
        self.fail_closed(
            "cloud_validation_error",
            "Guard cloud evaluation returned an invalid response, so this package request needs review.",
            &self.failure_decision(),
        )
    }

    /// The pre-request failures of `_resolve_guard_sync_auth_context`.
    fn auth_resolution_failure(&self, error: &EvalError) -> CloudOutcome {
        match error {
            EvalError::Validation(_) => {
                if self.can_fallback_from_cloud_failure() {
                    return (
                        None,
                        Some(cloud_fallback_reason(
                            "cloud_auth_error",
                            "Guard cloud evaluation was not authorized, so Guard used local package intelligence.",
                        )),
                    );
                }
                let mut decision = self.failure_decision();
                if decision == "block" && self.fail_closed_decision() != "block" {
                    // An expired sign-in is a credential-state failure, not a
                    // package verdict: stop the install through the approval queue.
                    decision = "ask".to_owned();
                }
                self.fail_closed(
                    "cloud_auth_error",
                    "Guard cloud evaluation was not authorized, so this package request needs review.",
                    &decision,
                )
            }
            EvalError::NotFound(_) => {
                if self.can_fallback_from_cloud_failure() {
                    let configured = self
                        .deps
                        .store_extras
                        .get_oauth_local_credential_health()
                        .get("configured")
                        .and_then(Value::as_bool)
                        .unwrap_or(false);
                    if configured {
                        return (
                            None,
                            Some(cloud_fallback_reason(
                                "cloud_auth_error",
                                "Guard Cloud credentials were unavailable, so Guard used local package intelligence.",
                            )),
                        );
                    }
                    return (None, None);
                }
                self.fail_closed(
                    "cloud_auth_error",
                    "Guard Cloud credentials were unavailable. Guard blocked this package request rather than bypassing Cloud package protection.",
                    &self.failure_decision(),
                )
            }
            // A trusted-session failure (typically a token refresh error) is
            // availability, not a package verdict: every level routes it to review.
            _ => self.fail_closed(
                "cloud_auth_error",
                "Guard cloud evaluation could not establish a trusted session, so this package request needs review.",
                "ask",
            ),
        }
    }

    fn post(&self, auth_context: &Value, url: &str, data: &[u8]) -> EvalResult<Map<String, Value>> {
        let request = self.deps.guard_sync.guard_sync_request(
            auth_context,
            url,
            "POST",
            Some(data),
            None,
            None,
        )?;
        self.deps.guard_sync.urlopen_json_with_timeout_retry(
            &request,
            TIMEOUT_SECONDS,
            RETRY_TIMEOUT_SECONDS,
        )
    }

    /// POST with the single forced-refresh retry on HTTP 401.
    fn fetch(&self, auth_context: &Value, url: &str, data: &[u8]) -> Fetched {
        let error = match self.post(auth_context, url, data) {
            Ok(payload) => return Fetched::Payload(payload),
            Err(error) => error,
        };
        let status = match classify_post_failure(error) {
            PostFailure::Http(status) => status,
            PostFailure::Os(error) => return Fetched::Done(Box::new(self.handle_os_error(&error))),
            PostFailure::Invalid => return Fetched::Done(Box::new(self.invalid_response())),
        };
        if status != 401 {
            return Fetched::Status(status);
        }
        let Ok(fresh) = self
            .deps
            .guard_sync
            .resolve_guard_sync_auth_context(self.store, false, true)
        else {
            return Fetched::Status(status);
        };
        match self.post(&Value::Object(fresh), url, data) {
            Ok(payload) => Fetched::Payload(payload),
            Err(error) => match classify_post_failure(error) {
                PostFailure::Http(retry_status) => Fetched::Status(retry_status),
                PostFailure::Os(error) => Fetched::Done(Box::new(self.handle_os_error(&error))),
                PostFailure::Invalid => Fetched::Status(status),
            },
        }
    }

    fn http_status_outcome(&self, status: u16) -> CloudOutcome {
        if let Some(failed) = cloud_http_fail_closed_evaluation_full(
            self.deps,
            status,
            self.artifact,
            self.targets,
            self.workspace_dir,
            Some(self.workspace_fingerprint),
            self.bundle_meta,
            &self.failure_decision(),
        ) {
            return (Some(failed), None);
        }
        if status == 401 {
            return (
                None,
                Some(cloud_fallback_reason(
                    "cloud_auth_error",
                    "Guard cloud evaluation was not authorized, so Guard used local package intelligence.",
                )),
            );
        }
        let code = if matches!(status, 400 | 404) {
            "cloud_validation_error"
        } else {
            "cloud_http_error"
        };
        (
            None,
            Some(cloud_fallback_reason(
                code,
                &format!(
                    "Guard cloud evaluation returned HTTP {status}, so Guard fell back to local intelligence."
                ),
            )),
        )
    }

    fn merge_response(&self, payload: &Map<String, Value>) -> CloudOutcome {
        let Some(Value::Array(raw_packages)) = payload.get("packages") else {
            return self.fail_closed(
                "cloud_validation_error",
                "Guard cloud evaluation returned an invalid package payload, so this package request needs review.",
                &self.failure_decision(),
            );
        };
        let packages: Vec<Map<String, Value>> = raw_packages
            .iter()
            .filter_map(Value::as_object)
            .map(package_from_cloud_result)
            .collect();
        let decision = normalize_bundle_action(&string_or(payload, "decision", "monitor"));
        let policy_hash = self
            .bundle_meta
            .and_then(|meta| meta.get("policy_hash").cloned());
        let draft = EvaluationDraft {
            decision: decision.clone(),
            enforcement: string_or(payload, "enforcement", "premium_cloud"),
            entitlement_state: string_or(payload, "entitlementState", "premium"),
            cache_status: string_or(payload, "cacheStatus", "miss"),
            packages,
            reasons: dict_items(payload.get("reasons")),
            matched_rule_id: None,
            exception_id: None,
            refresh_required: false,
            record_monitor_evidence: decision == "monitor",
            bundle_version: self
                .bundle_meta
                .and_then(|meta| meta.get("bundle_version").cloned()),
            policy_version: match payload.get("policyVersion") {
                Some(Value::String(text)) if !text.is_empty() => text.clone(),
                _ => policy_hash.unwrap_or_else(|| "local:none".to_owned()),
            },
            ..Default::default()
        };
        let package_intent_hash = self
            .artifact
            .artifact_id
            .rsplit(':')
            .next()
            .map(str::to_owned)
            .unwrap_or_else(|| self.artifact.artifact_id.clone());
        let mut evaluation = finalize_evaluation(
            self.deps,
            &draft,
            &package_intent_hash,
            Some(self.workspace_fingerprint),
        );
        if let Some(copy) = payload.get("copy").and_then(Value::as_object) {
            let title = optional_string(copy.get("title"));
            let summary = optional_string(copy.get("summary"));
            if title.is_some() || summary.is_some() {
                let updated_summary =
                    summary.unwrap_or_else(|| evaluation.user_copy.summary.clone());
                let mut harness_parts =
                    vec![evaluation.risk_summary.clone(), updated_summary.clone()];
                if let Some(next_step) = evaluation
                    .user_copy
                    .next_step
                    .clone()
                    .filter(|step| !step.is_empty())
                {
                    harness_parts.push(format!("Fix: run `{next_step}`."));
                }
                let candidate = SupplyChainUserCopy {
                    title: title.unwrap_or_else(|| evaluation.user_copy.title.clone()),
                    summary: updated_summary,
                    next_step: evaluation.user_copy.next_step.clone(),
                    dashboard_url: evaluation.user_copy.dashboard_url.clone(),
                    harness_message: harness_parts.join(" "),
                };
                let policy_action = decision_to_guard_action_variant(&evaluation.policy_action);
                evaluation.user_copy = normalize_package_user_copy(&candidate, policy_action);
            }
        }
        (Some(evaluation), None)
    }
}

/// `_evaluate_with_cloud` — POST the evaluation request, walk the
/// entitlement/fail-closed/reconnect ladder and return the cloud evaluation.
/// `(None, reason)` means the caller continues with local/bundle evaluation.
#[allow(clippy::too_many_arguments)]
pub(super) fn evaluate_with_cloud(
    deps: &SupplyChainEvalDeps<'_>,
    store: &dyn SupplyChainStore,
    artifact: &GuardArtifact,
    targets: &[Map<String, Value>],
    workspace_dir: Option<&Path>,
    workspace_id: Option<&str>,
    workspace_fingerprint: Option<&str>,
    bundle_meta: Option<&BTreeMap<String, String>>,
    bundle_defer_eligible: bool,
    bundle_decision: Option<&str>,
) -> CloudOutcome {
    let (Some(workspace_id), Some(workspace_fingerprint)) = (workspace_id, workspace_fingerprint)
    else {
        return (None, None);
    };
    if targets.is_empty() {
        return (None, None);
    }
    let context = CloudContext {
        deps,
        store,
        artifact,
        targets,
        workspace_dir,
        workspace_fingerprint,
        bundle_meta,
        bundle_defer_eligible,
        bundle_decision,
        fail_closed: OnceCell::new(),
        entitlement: OnceCell::new(),
    };
    let auth_context = match deps
        .guard_sync
        .resolve_guard_sync_auth_context(store, false, false)
    {
        Ok(auth_context) => auth_context,
        Err(error) => return context.auth_resolution_failure(&error),
    };
    let Some(sync_url) = optional_string(auth_context.get("sync_url")) else {
        return context.fail_closed(
            "cloud_validation_error",
            "Guard cloud evaluation session was invalid, so this package request needs review.",
            &context.failure_decision(),
        );
    };
    let Ok(sync_url) = deps.guard_sync.validate_guard_sync_url(
        &sync_url,
        optional_string(auth_context.get("issuer")).as_deref(),
    ) else {
        return context.fail_closed(
            "cloud_validation_error",
            "Guard cloud evaluation endpoint was not trusted, so this package request needs review.",
            &context.failure_decision(),
        );
    };
    let evaluate_url = normalized_supply_chain_evaluate_url(deps, &sync_url, workspace_id);
    let policy_version = bundle_meta
        .and_then(|meta| meta.get("policy_hash").cloned())
        .unwrap_or_else(|| "local:none".to_owned());
    let request_payload = build_request_payload(
        deps,
        artifact,
        targets,
        workspace_dir,
        workspace_fingerprint,
        &policy_version,
    );
    let request_data = serde_json::to_vec(&request_payload).unwrap_or_default();
    match context.fetch(&Value::Object(auth_context), &evaluate_url, &request_data) {
        Fetched::Payload(payload) => context.merge_response(&payload),
        Fetched::Status(status) => context.http_status_outcome(status),
        Fetched::Done(outcome) => *outcome,
    }
}
