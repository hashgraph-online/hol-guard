use guard_contracts::{PreToolActionTypeV1, PreToolResultV1};

/// The native action lattice is intentionally typed at the enforcement
/// boundary.  String values remain the wire representation for compatibility
/// with existing hook contracts, but no decision is made by comparing raw
/// strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub(crate) enum ActionFloor {
    Allow,
    Warn,
    Review,
    RequireReapproval,
    SandboxRequired,
    Block,
}

impl ActionFloor {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "allow" => Self::Allow,
            "warn" => Self::Warn,
            "review" => Self::Review,
            "require-reapproval" => Self::RequireReapproval,
            "sandbox-required" => Self::SandboxRequired,
            "block" => Self::Block,
            _ => return None,
        })
    }

    fn is_non_overridable(self) -> bool {
        matches!(self, Self::SandboxRequired | Self::Block)
    }

    fn decision(self) -> &'static str {
        if matches!(self, Self::Allow | Self::Warn) {
            "allow"
        } else {
            "deny"
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ActionFloorMatrix {
    policy: ActionFloor,
    minimum: ActionFloor,
}

impl ActionFloorMatrix {
    fn from_result(result: &PreToolResultV1) -> Result<Self, String> {
        Ok(Self {
            policy: ActionFloor::parse(&result.policy_action)
                .ok_or_else(|| "native_policy_action_invalid".to_owned())?,
            minimum: ActionFloor::parse(&result.minimum_action)
                .ok_or_else(|| "native_policy_action_invalid".to_owned())?,
        })
    }

    fn validate(self, result: &PreToolResultV1) -> Result<(), String> {
        if self.policy < self.minimum
            || (self.policy.is_non_overridable() && self.policy != self.minimum)
            || result.decision != self.minimum.decision()
            || result.explicitly_benign != (self.minimum == ActionFloor::Allow)
        {
            return Err("native_policy_decision_inconsistent".to_owned());
        }
        Ok(())
    }
}

/// Validate the typed relationship between the effective action fields.  The
/// policy action is not a second, weaker authority: it must describe the same
/// or stronger floor, and a terminal policy block must be reflected by the
/// minimum floor before any approval path can inspect the result.
pub(crate) fn validate_pre_tool_result_matrix(result: &PreToolResultV1) -> Result<(), String> {
    let classes = &result.prompt_risk_classes;
    if !classes.is_empty() {
        let mut ordered = classes.clone();
        ordered.sort_unstable();
        ordered.dedup();
        if classes.len() > 6
            || result.action.event != "UserPromptSubmit"
            || result.action.action_type != PreToolActionTypeV1::Prompt
            || ordered != *classes
        {
            return Err("native_prompt_risk_classes_invalid".to_owned());
        }
    }
    ActionFloorMatrix::from_result(result)?.validate(result)
}
