//! Literal expressions remain attached to their complete signed selector rows.

use super::{
    integer, AuthorityError, NativePolicyAuthority, PolicySourceKind, ScopedPolicyRequest,
    ScopedPolicyRow,
};
use crate::command_expression::{NativeCommandExpression, NormalizedCommand};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

/// Only the containing authenticated snapshot can confer policy authority.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ScopedCommandExpression {
    decision_id: u64,
    expression: NativeCommandExpression,
}

impl fmt::Debug for ScopedCommandExpression {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ScopedCommandExpression { .. }")
    }
}

impl ScopedCommandExpression {
    pub fn decision_id(&self) -> u64 {
        self.decision_id
    }
}

pub(super) fn validate_bindings(authority: &NativePolicyAuthority) -> Result<(), AuthorityError> {
    if authority.command_expressions().len() > authority.rows().len() {
        return Err(AuthorityError::CommandExpression);
    }
    let mut seen = BTreeSet::new();
    for binding in authority.command_expressions() {
        integer(binding.decision_id, true)?;
        if !seen.insert(binding.decision_id) {
            return Err(AuthorityError::CommandExpression);
        }
        let row = authority
            .rows()
            .iter()
            .find(|row| row.decision_id() == binding.decision_id)
            .ok_or(AuthorityError::CommandExpression)?;
        if row.source_kind() != PolicySourceKind::SignedBundle {
            return Err(AuthorityError::CommandExpression);
        }
    }
    Ok(())
}

impl NativePolicyAuthority {
    pub fn command_expressions(&self) -> &[ScopedCommandExpression] {
        &self.0.command_expressions
    }

    pub(super) fn has_command_expression(&self, decision_id: u64) -> bool {
        self.command_expressions()
            .iter()
            .any(|binding| binding.decision_id == decision_id)
    }

    /// Return every matching expression row after all ordinary AND selectors and
    /// expiry checks. The consumer must join their actions by strictness, not use
    /// generic specificity/recency to discard another expression restriction.
    pub fn matching_command_rows<'a>(
        &'a self,
        request: &ScopedPolicyRequest,
        command: &NormalizedCommand,
        now_ms: u64,
    ) -> Result<Vec<&'a ScopedPolicyRow>, AuthorityError> {
        integer(now_ms, false)?;
        Ok(self
            .command_expressions()
            .iter()
            .filter_map(|binding| {
                let row = self
                    .rows()
                    .iter()
                    .find(|row| row.decision_id() == binding.decision_id)?;
                (super::matching::matches_row(row, request, now_ms)
                    && binding.expression.matches(command))
                .then_some(row)
            })
            .collect())
    }
}

#[cfg(test)]
#[path = "scoped_command_expression_tests.rs"]
mod tests;
