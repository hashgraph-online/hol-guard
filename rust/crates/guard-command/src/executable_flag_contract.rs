//! Data contract matching Python's `_ExecutableContractBase`.
//!
//! The trusted compiler emits normalized values. Validation rejects ambiguous
//! inverse pairs and contradictory requirements before interpreting a program.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExecutableFlagContract {
    pub(crate) executables: BTreeSet<String>,
    #[serde(default)]
    pub(crate) required_flags: BTreeSet<String>,
    #[serde(default)]
    pub(crate) forbidden_flags: BTreeSet<String>,
    #[serde(default)]
    pub(crate) allow_leading_options: bool,
    #[serde(default)]
    pub(crate) leading_options_with_values: BTreeSet<String>,
    #[serde(default)]
    pub(crate) interspersed_options_with_values: BTreeSet<String>,
    #[serde(default)]
    pub(crate) interspersed_flags: BTreeSet<String>,
    #[serde(default)]
    pub(crate) options_with_values: BTreeSet<String>,
    #[serde(default)]
    pub(crate) inverse_flag_pairs: BTreeSet<(String, String)>,
    #[serde(default)]
    pub(crate) required_option_values: Vec<(String, BTreeSet<String>)>,
    #[serde(default)]
    pub(crate) required_flags_in_all_arguments: bool,
    #[serde(default)]
    pub(crate) fail_secure_unknown_options: bool,
}

impl ExecutableFlagContract {
    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        if self.executables.is_empty() {
            return Err("native_command_executables_empty");
        }
        if !self.required_flags.is_disjoint(&self.forbidden_flags) {
            return Err("native_command_required_forbidden_flag_conflict");
        }
        let mut inverse_names = BTreeSet::new();
        for (positive, negative) in &self.inverse_flag_pairs {
            if !inverse_names.insert(positive) || !inverse_names.insert(negative) {
                return Err("native_command_inverse_flag_alias_reused");
            }
        }
        let mut required_options = BTreeSet::new();
        for (option, allowed_values) in &self.required_option_values {
            if !required_options.insert(option) {
                return Err("native_command_required_option_duplicated");
            }
            if allowed_values.is_empty() {
                return Err("native_command_required_option_values_empty");
            }
        }
        Ok(())
    }

    pub(crate) fn all_value_options(&self) -> BTreeSet<String> {
        self.options_with_values
            .iter()
            .chain(&self.leading_options_with_values)
            .chain(&self.interspersed_options_with_values)
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contract(value: serde_json::Value) -> ExecutableFlagContract {
        serde_json::from_value(value).expect("valid contract shape")
    }

    #[test]
    fn python_base_defaults_and_value_option_union() {
        let value = contract(serde_json::json!({"executables": ["tool"]}));
        assert_eq!(
            value,
            ExecutableFlagContract {
                executables: BTreeSet::from(["tool".to_owned()]),
                ..Default::default()
            }
        );
        assert_eq!(value.validate(), Ok(()));
        let value = contract(
            serde_json::json!({"executables": ["tool"], "options_with_values": ["--output"], "leading_options_with_values": ["-o", "--output"], "interspersed_options_with_values": ["--config"]}),
        );
        assert_eq!(
            value.all_value_options(),
            BTreeSet::from([
                "--output".to_owned(),
                "-o".to_owned(),
                "--config".to_owned()
            ])
        );
    }

    #[test]
    fn ambiguous_contracts_are_rejected_before_flag_interpretation() {
        for value in [
            serde_json::json!({"executables": []}),
            serde_json::json!({"executables": ["tool"], "required_flags": ["--force"], "forbidden_flags": ["--force"]}),
            serde_json::json!({"executables": ["tool"], "inverse_flag_pairs": [["--force", "--force"]]}),
            serde_json::json!({"executables": ["tool"], "inverse_flag_pairs": [["--force", "--no-force"], ["--force", "-n"]]}),
            serde_json::json!({"executables": ["tool"], "required_option_values": [["--mode", []]]}),
            serde_json::json!({"executables": ["tool"], "required_option_values": [["--mode", ["one"]], ["--mode", ["two"]]]}),
        ] {
            assert!(contract(value).validate().is_err());
        }
        assert!(serde_json::from_value::<ExecutableFlagContract>(
            serde_json::json!({"executables": ["tool"], "unsupported_matcher_semantics": true})
        )
        .is_err());
    }
}
