//! Catalog risk classes for a matched rule, read-only.
use super::CompiledNativeCommandControls;

impl CompiledNativeCommandControls {
    /// Risk classes the packaged catalog declares for `rule_id`; `None` when the
    /// identity is unknown, which callers must treat as unproven.
    pub(crate) fn rule_risk_classes(&self, rule_id: &str) -> Option<&[String]> {
        let index = self.rule_indices.get(rule_id)?;
        Some(&self.program.rules[*index].risk_classes)
    }
}
