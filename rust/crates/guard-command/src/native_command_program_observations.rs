//! Preserve complete rule and safe-variant observations with redacted evidence.

use super::*;

impl NativeCommandProgram {
    pub fn observe(
        &self,
        command: &CanonicalCommandV1,
        active_extensions: &BTreeSet<String>,
        deadline: Option<Instant>,
    ) -> Result<NativeCommandObservationBatchV1, &'static str> {
        let compatibility =
            crate::command_compatibility::compatibility_observations(command, deadline)?;
        let mut batch = self.observe_declarative(command, active_extensions, deadline)?;
        for mut matched in compatibility.rule_matches {
            // Safe evidence is both capability- and segment-scoped. A preview
            // in one segment cannot suppress its destructive sibling, and a
            // CLI's help predicate cannot erase a separate capability whose
            // semantics deliberately still require review for trailing help.
            matched.segment_indexes.retain(|segment| {
                !batch.observations.iter().any(|observation| {
                    safe_variant_covers_compatibility(matched.rule_id, &observation.rule_id)
                        && !observation.effective_segment_indexes.contains(segment)
                        && observation.safe_variants.iter().any(|variant| {
                            variant
                                .matcher_evidence
                                .iter()
                                .any(|evidence| evidence.segment_index == *segment)
                        })
                })
            });
            if matched.segment_indexes.is_empty() {
                continue;
            }
            let rule = self
                .rule_indices
                .get(matched.rule_id)
                .map(|index| &self.rules[*index])
                .filter(|rule| rule.matcher.is_none())
                .ok_or("native_command_compatibility_owner_invalid")?;
            let extension = &self.extensions[rule.extension_index];
            if !active_extensions.contains(&extension.extension_id) {
                continue;
            }
            let mut match_classes = vec!["unsafe".to_owned()];
            let uncertainty = if matched.uncertainty {
                vec!["matcher-failure".to_owned()]
            } else {
                Vec::new()
            };
            if matched.uncertainty {
                match_classes.push("uncertainty".to_owned());
            }
            batch.observations.push(NativeCommandObservationV1 {
                extension_id: extension.extension_id.clone(),
                extension_version: extension.version.clone(),
                rule_id: rule.rule_id.clone(),
                rule_version: rule.rule_version.clone(),
                match_class: if matched.uncertainty {
                    "uncertainty"
                } else {
                    "unsafe"
                }
                .into(),
                match_classes,
                matcher_evidence: redact_evidence(command, &matched.segment_indexes)?,
                safe_variants: Vec::new(),
                uncertainty_reasons: uncertainty,
                effective_segment_indexes: matched.segment_indexes,
            });
        }
        for matched in compatibility.permission_matches {
            let extension = self
                .extensions
                .iter()
                .find(|extension| {
                    extension
                        .permissions
                        .iter()
                        .any(|permission| permission.permission_id == matched.permission_id)
                })
                .ok_or("native_command_compatibility_permission_invalid")?;
            if !active_extensions.contains(&extension.extension_id) {
                continue;
            }
            batch
                .permission_observations
                .push(NativeCommandPermissionObservationV1 {
                    mcp_tool: None,
                    extension_id: extension.extension_id.clone(),
                    permission_id: matched.permission_id.to_owned(),
                    matcher_evidence: redact_evidence(command, &matched.segment_indexes)?,
                    uncertainty_reasons: if matched.uncertainty {
                        vec!["matcher-failure".to_owned()]
                    } else {
                        Vec::new()
                    },
                });
        }
        batch
            .observations
            .sort_by_key(|observation| self.rule_indices[&observation.rule_id]);
        let evidence_count = batch
            .observations
            .iter()
            .map(|observation| {
                observation.matcher_evidence.len()
                    + observation
                        .safe_variants
                        .iter()
                        .map(|variant| variant.matcher_evidence.len())
                        .sum::<usize>()
            })
            .sum::<usize>()
            + batch
                .permission_observations
                .iter()
                .map(|observation| observation.matcher_evidence.len())
                .sum::<usize>();
        if evidence_count > MAX_NATIVE_COMMAND_EVIDENCE_ITEMS
            || batch.observations.len() + batch.permission_observations.len()
                > MAX_NATIVE_COMMAND_OBSERVATIONS
        {
            return Err("native_command_evidence_limit_exceeded");
        }
        if deadline.is_some_and(|limit| Instant::now() >= limit) {
            return Err("native_command_deadline_exceeded");
        }
        Ok(batch)
    }

    pub(super) fn observe_declarative(
        &self,
        command: &CanonicalCommandV1,
        active_extensions: &BTreeSet<String>,
        deadline: Option<Instant>,
    ) -> Result<NativeCommandObservationBatchV1, &'static str> {
        let mut state = Evaluation {
            program: self,
            command,
            deadline,
            memo: vec![None; self.nodes.len()],
        };
        let mut observations = Vec::new();
        let mut evidence_items = 0usize;
        for index in self.candidate_rule_indices(command) {
            state.check_deadline()?;
            let rule = &self.rules[index];
            let extension = &self.extensions[rule.extension_index];
            if !active_extensions.contains(&extension.extension_id) {
                continue;
            }
            let Some(matcher) = rule.matcher else {
                continue;
            };
            let mut uncertainty = Vec::new();
            let base = match state.evaluate(matcher) {
                Ok(indices) => indices,
                Err(_) => {
                    uncertainty.push("matcher-failure".to_owned());
                    Arc::from([])
                }
            };
            if base.is_empty() && uncertainty.is_empty() {
                continue;
            }
            let mut variants = Vec::new();
            let mut safe_indexes = BTreeSet::new();
            let mut safe_failure = false;
            if !base.is_empty() {
                for (variant_id, matcher) in &rule.variants {
                    match state.evaluate(*matcher) {
                        Ok(indices) if !indices.is_empty() => {
                            safe_indexes.extend(indices.iter().copied());
                            evidence_items = evidence_items.saturating_add(indices.len());
                            if evidence_items > MAX_NATIVE_COMMAND_EVIDENCE_ITEMS {
                                return Err("native_command_evidence_limit_exceeded");
                            }
                            variants.push(NativeSafeVariantObservationV1 {
                                match_class: "safe-variant".to_owned(),
                                variant_id: variant_id.clone(),
                                matcher_evidence: redact_evidence(command, &indices)?,
                            });
                        }
                        Ok(_) => (),
                        Err(_) => safe_failure = true,
                    }
                }
            }
            if safe_failure && base.iter().any(|index| !safe_indexes.contains(index)) {
                uncertainty.push("matcher-failure".to_owned());
            }
            evidence_items = evidence_items.saturating_add(base.len());
            if evidence_items > MAX_NATIVE_COMMAND_EVIDENCE_ITEMS
                || observations.len() >= MAX_NATIVE_COMMAND_OBSERVATIONS
            {
                return Err("native_command_evidence_limit_exceeded");
            }
            let mut match_classes = if base.is_empty() {
                Vec::new()
            } else {
                vec!["unsafe".to_owned()]
            };
            if !uncertainty.is_empty() {
                match_classes.push("uncertainty".to_owned());
            }
            observations.push(NativeCommandObservationV1 {
                extension_id: extension.extension_id.clone(),
                extension_version: extension.version.clone(),
                rule_id: rule.rule_id.clone(),
                rule_version: rule.rule_version.clone(),
                match_class: if uncertainty.is_empty() {
                    "unsafe"
                } else {
                    "uncertainty"
                }
                .to_owned(),
                match_classes,
                matcher_evidence: redact_evidence(command, &base)?,
                safe_variants: variants,
                uncertainty_reasons: uncertainty,
                effective_segment_indexes: base
                    .iter()
                    .filter(|index| !safe_indexes.contains(index))
                    .copied()
                    .collect(),
            });
        }
        state.check_deadline()?;
        Ok(NativeCommandObservationBatchV1 {
            observations,
            ..Default::default()
        })
    }
}

fn safe_variant_covers_compatibility(compatibility: &str, declarative: &str) -> bool {
    match compatibility {
        "command.git.push" => declarative == "command.git.force-push",
        "command.container-runtime.docker-sensitive" => {
            declarative.starts_with("command.container-runtime.")
        }
        "command.kubernetes-secrets.secret-read" => {
            declarative.starts_with("command.kubernetes-operations.")
        }
        _ => false,
    }
}

fn redact_evidence(
    command: &CanonicalCommandV1,
    indices: &[usize],
) -> Result<Vec<NativeMatcherEvidenceV1>, &'static str> {
    indices
        .iter()
        .map(|index| {
            let segment = command
                .segments
                .get(*index)
                .ok_or("native_command_evidence_index_invalid")?;
            let executable = segment
                .executable
                .as_deref()
                .map(basename)
                .filter(|value| {
                    !value.is_empty()
                        && value.len() <= 128
                        && value.as_bytes()[0].is_ascii_alphanumeric()
                        && value.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric()
                                || matches!(byte, b'.' | b'_' | b'+' | b'-')
                        })
                })
                .map(ToOwned::to_owned);
            Ok(NativeMatcherEvidenceV1 {
                segment_index: *index,
                executable,
                detail: MATCH_DETAIL.to_owned(),
            })
        })
        .collect()
}
