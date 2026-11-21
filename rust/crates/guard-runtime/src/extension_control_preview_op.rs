//! `ExtensionControl` `preview` — the semantic preview of an extension-control
//! authority mutation.
//!
//! The preview describes effective consequences without executing commands
//! and without changing catalog metadata. It resolves the current layers, the
//! proposed layers, and the proposed layers with each changed local target
//! reverted, with the same resolver command evaluation runs, so the dashboard
//! never carries its own copy of policy truth. A target's affected permissions
//! are the ones whose effective state that target alone changes.

mod budget;
mod catalog;
mod layers;

use std::collections::BTreeSet;

use guard_contracts::{
    ExtensionControlPreviewChangedTargetV1, ExtensionControlPreviewExtensionV1,
    ExtensionControlPreviewLockdownV1, ExtensionControlPreviewPermissionV1,
    ExtensionControlPreviewRegistryV1, ExtensionControlPreviewSummaryV1,
    ExtensionControlPreviewTargetRefV1, ExtensionControlPreviewWarningV1,
    ExtensionControlSemanticPreviewV1, NativeExtensionControlLayerV1,
    EXTENSION_CONTROL_SEMANTIC_PREVIEW_SCHEMA,
};

use crate::extension_control_op::{RequestRegistry, TOO_MANY_ITEMS};
use budget::{closure_budget, ReplyBudget};
use catalog::{bounded, sorted_bounded, union_bounded, PreviewCatalog};
use layers::{
    explicit_state, layers_with_target_reverted, local_controls, provenance, resolve_effective,
    Effective, TargetKey,
};

const MAX_CHANGED_TARGETS: usize = 4_096;
const MAX_WARNINGS_PER_TARGET: usize = 64;
const MAX_RELATIONSHIP_IDS: usize = 4_096;

const PERMISSION: &str = "permission";
const ENABLED: &str = "enabled";

/// The preview of replacing `current_layers` with `proposed_layers`.
pub(crate) fn semantic_preview(
    registry: &ExtensionControlPreviewRegistryV1,
    current_layers: &[NativeExtensionControlLayerV1],
    proposed_layers: &[NativeExtensionControlLayerV1],
) -> Result<ExtensionControlSemanticPreviewV1, String> {
    let projection = catalog::resolver_projection(registry);
    let resolver = RequestRegistry::new(&projection)?;
    let catalog = PreviewCatalog::new(registry, &resolver);

    let current_controls = local_controls(current_layers);
    let proposed_controls = local_controls(proposed_layers);
    let target_keys: BTreeSet<&TargetKey> = current_controls
        .keys()
        .chain(proposed_controls.keys())
        .collect();
    let changed_keys: Vec<&TargetKey> = target_keys
        .into_iter()
        .filter(|key| current_controls.get(*key) != proposed_controls.get(*key))
        .take(MAX_CHANGED_TARGETS)
        .collect();

    // A changed target the catalog does not know yields no entry, so it needs
    // no resolution.
    let known_keys: Vec<&TargetKey> = changed_keys
        .iter()
        .copied()
        .filter(|key| is_known(&catalog, key))
        .collect();
    let changed_extension_ids: Vec<String> = known_keys
        .iter()
        .filter(|(kind, _)| kind != PERMISSION)
        .filter_map(|(_, target_id)| catalog.extension(target_id))
        .map(|extension| extension.extension_id.clone())
        .collect();

    // Every catalog permission's closure is resolved once; each resolution
    // below only compares it with its own layers. The work the preview may
    // take is bounded before any of it is done.
    let resolutions = known_keys.len() + 2;
    let closures = catalog
        .closures(
            &changed_extension_ids,
            closure_budget(&catalog, current_layers, proposed_layers, resolutions)?,
        )
        .ok_or_else(|| TOO_MANY_ITEMS.to_owned())?;
    let current = resolve_effective(
        &catalog,
        current_layers,
        &closures.permissions,
        &closures.extensions,
    )?;
    let proposed = resolve_effective(
        &catalog,
        proposed_layers,
        &closures.permissions,
        &closures.extensions,
    )?;

    let context = PreviewContext {
        catalog: &catalog,
        current_layers,
        proposed_layers,
        current: &current,
        proposed: &proposed,
    };
    let mut reply = ReplyBudget::default();
    let mut changed_targets = Vec::new();
    let mut all_affected_permission_ids: BTreeSet<String> = BTreeSet::new();
    let mut all_affected_rule_ids: BTreeSet<String> = BTreeSet::new();
    for key in changed_keys {
        if !is_known(&catalog, key) {
            continue;
        }
        // One reverted resolution at a time: only its marginal effect on this
        // target is kept, so memory does not grow with the changed targets.
        let reverted_layers = layers_with_target_reverted(
            current_layers,
            proposed_layers,
            (key.0.as_str(), key.1.as_str()),
        );
        let reverted = resolve_effective(&catalog, &reverted_layers, &closures.permissions, &[])?;
        let Some(target) = context.changed_target(key, &reverted) else {
            continue;
        };
        reply.admit(&target)?;
        all_affected_permission_ids.extend(target.affected_permission_ids.iter().cloned());
        all_affected_rule_ids.extend(target.affected_rule_ids.iter().cloned());
        changed_targets.push(target);
    }

    let newly_blocked = count_changes(&current, &proposed, true);
    let newly_allowed = count_changes(&current, &proposed, false);
    let lockdown_changed = current.global_lockdown != proposed.global_lockdown;
    Ok(ExtensionControlSemanticPreviewV1 {
        schema_version: EXTENSION_CONTROL_SEMANTIC_PREVIEW_SCHEMA.to_owned(),
        global_lockdown: ExtensionControlPreviewLockdownV1 {
            before: current.global_lockdown,
            after: proposed.global_lockdown,
            changed: lockdown_changed,
        },
        changed_target_count: changed_targets.len() as u64,
        affected_permission_count: all_affected_permission_ids.len() as u64,
        affected_rule_count: all_affected_rule_ids.len() as u64,
        // Approval is also needed when permissions change effective state
        // without a changed target the catalog knows: an unknown target a
        // layer holds or drops blocks every permission while it is present.
        approval_required: !changed_targets.is_empty()
            || lockdown_changed
            || newly_blocked + newly_allowed > 0,
        changed_targets,
        summary: ExtensionControlPreviewSummaryV1 {
            newly_blocked_permissions: newly_blocked,
            newly_allowed_permissions: newly_allowed,
            effective_change_count: newly_blocked + newly_allowed,
        },
    })
}

/// Whether the catalog has an entry for the changed target.
fn is_known(catalog: &PreviewCatalog<'_>, (kind, target_id): &TargetKey) -> bool {
    if kind == PERMISSION {
        catalog.permission(target_id).is_some()
    } else {
        catalog.extension(target_id).is_some()
    }
}

/// Permissions allowed before and not after (`to_blocked`), or the reverse.
fn count_changes(current: &Effective, proposed: &Effective, to_blocked: bool) -> u64 {
    current
        .permission_allowed
        .iter()
        .filter(|(permission_id, before)| {
            let after = proposed.allowed(permission_id);
            if to_blocked {
                **before && !after
            } else {
                !**before && after
            }
        })
        .count() as u64
}

fn effective_word(allowed: bool) -> String {
    let word = if allowed { "allowed" } else { "blocked" };
    word.to_owned()
}

/// Permissions whose effective state differs between the proposed layers and
/// the proposed layers with one target reverted, sorted and bounded.
fn marginal_permission_ids(proposed: &Effective, reverted: &Effective) -> Vec<String> {
    let changed: BTreeSet<&String> = proposed
        .permission_allowed
        .iter()
        .filter(|(permission_id, state)| {
            reverted
                .permission_allowed
                .get(*permission_id)
                .is_some_and(|reverted_state| reverted_state != *state)
        })
        .map(|(permission_id, _)| permission_id)
        .collect();
    bounded(changed.into_iter().cloned())
}

fn warning(code: &str, message: String) -> ExtensionControlPreviewWarningV1 {
    ExtensionControlPreviewWarningV1 {
        code: code.to_owned(),
        target_id: None,
        count: None,
        message,
    }
}

struct PreviewContext<'c> {
    catalog: &'c PreviewCatalog<'c>,
    current_layers: &'c [NativeExtensionControlLayerV1],
    proposed_layers: &'c [NativeExtensionControlLayerV1],
    current: &'c Effective,
    proposed: &'c Effective,
}

impl PreviewContext<'_> {
    fn changed_target(
        &self,
        (kind, target_id): &TargetKey,
        reverted: &Effective,
    ) -> Option<ExtensionControlPreviewChangedTargetV1> {
        let mut affected_permission_ids = marginal_permission_ids(self.proposed, reverted);
        if kind == PERMISSION && !affected_permission_ids.contains(target_id) {
            affected_permission_ids.push(target_id.clone());
            affected_permission_ids.sort();
            affected_permission_ids.truncate(MAX_RELATIONSHIP_IDS);
        }
        let mut target = ExtensionControlPreviewChangedTargetV1 {
            target: ExtensionControlPreviewTargetRefV1 {
                kind: kind.clone(),
                target_id: target_id.clone(),
            },
            extension_id: String::new(),
            label: String::new(),
            before_explicit: explicit_state(self.current_layers, kind, target_id),
            after_explicit: explicit_state(self.proposed_layers, kind, target_id),
            before_effective: String::new(),
            after_effective: String::new(),
            baseline_risk: None,
            baseline_floor: None,
            affected_rule_ids: self
                .catalog
                .rule_ids_for_permissions(&affected_permission_ids),
            affected_extension_ids: self
                .catalog
                .extension_ids_for_permissions(&affected_permission_ids),
            affected_permission_ids,
            dependency_permission_ids: Vec::new(),
            implied_permission_ids: Vec::new(),
            conflict_permission_ids: Vec::new(),
            provenance: provenance(
                self.proposed_layers,
                kind,
                target_id,
                self.proposed.global_lockdown,
            ),
            warnings: Vec::new(),
            extension_name: None,
        };
        if kind == PERMISSION {
            let permission = self.catalog.permission(target_id)?;
            self.fill_permission(&mut target, permission);
        } else {
            let extension = self.catalog.extension(target_id)?;
            self.fill_extension(&mut target, extension);
        }
        Some(target)
    }

    fn fill_permission(
        &self,
        target: &mut ExtensionControlPreviewChangedTargetV1,
        permission: &ExtensionControlPreviewPermissionV1,
    ) {
        target.affected_extension_ids = union_bounded(
            &target.affected_extension_ids,
            std::iter::once(&permission.extension_id),
        );
        target.warnings = self.permission_warnings(target, permission);
        target.extension_id = permission.extension_id.clone();
        target.label = permission.label.clone();
        target.before_effective = effective_word(self.current.allowed(&permission.permission_id));
        target.after_effective = effective_word(self.proposed.allowed(&permission.permission_id));
        target.baseline_risk = Some(permission.risk_tier.clone());
        target.baseline_floor = Some(permission.baseline_floor.clone());
        target.dependency_permission_ids = sorted_bounded(&permission.dependencies);
        target.implied_permission_ids = sorted_bounded(&permission.implied_permissions);
        target.conflict_permission_ids = sorted_bounded(&permission.conflicts);
        target.extension_name = self
            .catalog
            .extension(&permission.extension_id)
            .map(|extension| extension.name.clone());
    }

    fn permission_warnings(
        &self,
        target: &ExtensionControlPreviewChangedTargetV1,
        permission: &ExtensionControlPreviewPermissionV1,
    ) -> Vec<ExtensionControlPreviewWarningV1> {
        let mut warnings = Vec::new();
        if target.after_explicit == ENABLED && !self.proposed.allowed(&permission.permission_id) {
            warnings.push(warning(
                "requested-allow-not-effective",
                "A stronger parent, dependency, lockdown, or managed control still blocks this permission."
                    .to_owned(),
            ));
        }
        for conflict_id in &permission.conflicts {
            let Some(conflict) = self.catalog.permission(conflict_id) else {
                continue;
            };
            if self.proposed.allowed(&conflict.permission_id) {
                warnings.push(ExtensionControlPreviewWarningV1 {
                    target_id: Some(conflict.permission_id.clone()),
                    ..warning(
                        "conflicting-permission-effective",
                        format!(
                            "Conflicting permission {} remains effective.",
                            conflict.label
                        ),
                    )
                });
            }
        }
        let indirect = target
            .affected_permission_ids
            .iter()
            .filter(|permission_id| **permission_id != permission.permission_id)
            .count();
        if indirect > 0 {
            warnings.push(ExtensionControlPreviewWarningV1 {
                count: Some(indirect as u64),
                ..warning(
                    "dependent-permissions-affected",
                    "This target also changes effective behavior for related permissions."
                        .to_owned(),
                )
            });
        }
        warnings.truncate(MAX_WARNINGS_PER_TARGET);
        warnings
    }

    fn fill_extension(
        &self,
        target: &mut ExtensionControlPreviewChangedTargetV1,
        extension: &ExtensionControlPreviewExtensionV1,
    ) {
        let dependency_ids = self
            .catalog
            .extension_dependency_ids(&extension.extension_id);
        target.affected_extension_ids =
            union_bounded(&target.affected_extension_ids, &dependency_ids);
        target.affected_rule_ids = union_bounded(&target.affected_rule_ids, &extension.rule_ids);
        let after_allowed = !self.proposed.blocked_extension(&extension.extension_id);
        if target.after_explicit == ENABLED && !after_allowed {
            target.warnings.push(warning(
                "requested-allow-not-effective",
                "A stronger dependency, lockdown, or managed control still blocks this extension."
                    .to_owned(),
            ));
        }
        target.extension_id = extension.extension_id.clone();
        target.label = extension.name.clone();
        target.before_effective =
            effective_word(!self.current.blocked_extension(&extension.extension_id));
        target.after_effective = effective_word(after_allowed);
    }
}

#[cfg(test)]
#[path = "extension_control_preview_op_tests.rs"]
mod tests;
