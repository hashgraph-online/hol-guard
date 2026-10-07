//! Compiler-owned conservative indexes. A hint only selects candidates; the
//! existing native matcher still decides the result. Unknown shapes stay unindexed.
use super::{matcher::SourceMatcher, *};

#[derive(Default)]
pub(super) struct Hints {
    pub executables: BTreeSet<String>,
    pub keywords: BTreeSet<String>,
    pub complete: bool,
}

impl Hints {
    pub fn unindexed(&self) -> bool {
        !self.complete || (self.executables.is_empty() && self.keywords.is_empty())
    }
}

pub(super) fn derive(matcher: &SourceMatcher) -> Hints {
    let mut hints = Hints {
        complete: true,
        ..Hints::default()
    };
    let mut fields: Vec<&str> = Vec::new();
    match matcher.op.as_str() {
        "any.v1" => {
            for child in &matcher.matchers {
                let child = derive(child);
                // Every alternative must contribute a usable candidate hint.
                // Otherwise a command matching only a hintless alternative
                // would never reach the authoritative native matcher.
                hints.complete &= !child.unindexed();
                hints.executables.extend(child.executables);
                hints.keywords.extend(child.keywords);
            }
            return hints;
        }
        "all.v1" | "pipeline.v1" => {
            for child in matcher
                .matchers
                .iter()
                .chain(matcher.producer.iter().map(Box::as_ref))
                .chain(matcher.consumer.iter().map(Box::as_ref))
            {
                let child = derive(child);
                hints.complete &= child.complete;
                hints.executables.extend(child.executables);
                hints.keywords.extend(child.keywords);
            }
            return hints;
        }
        "executable.v1" => {
            fields.extend(["subcommands", "required_flags"]);
            if let Some(pairs) = matcher.config["required_option_values"].as_array() {
                for pair in pairs {
                    if let Some(name) = pair[0].as_str() {
                        hints.keywords.insert(name.to_owned());
                    }
                }
            }
        }
        "arguments.v1" => fields.push("required_arguments"),
        "argument-command.v1" => {
            if let Some(command) = matcher.config["command"].as_str() {
                hints.keywords.insert(command.to_owned());
            }
        }
        "command-sequence.v1" => fields.push("target_commands"),
        "leading-subcommand.v1" | "subcommand-operand-prefix.v1" => fields.push("subcommands"),
        "option-value-key.v1" => fields.push("option_names"),
        "environment-name.v1" => fields.push("environment_names"),
        "php-artisan-script.v1" => {
            hints
                .executables
                .extend(["php", "php.cmd", "php.exe"].map(str::to_owned));
            fields.push("subcommands");
        }
        "leading-operand-count.v1"
        | "trailing-operand-prefix.v1"
        | "trailing-operand-host-target.v1"
        | "trailing-operand-remote-alias.v1"
        | "operand-gated-flags.v1" => {}
        _ => hints.complete = false,
    }
    if hints.complete {
        if let Some(values) = matcher.config["executables"].as_array() {
            hints
                .executables
                .extend(values.iter().filter_map(Value::as_str).map(str::to_owned));
        }
        for field in fields {
            if let Some(values) = matcher.config[field].as_array() {
                hints
                    .keywords
                    .extend(values.iter().filter_map(Value::as_str).map(str::to_owned));
            }
        }
    }
    hints
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn any_with_hintless_alternative_stays_in_unindexed_candidates() {
        let matcher: SourceMatcher = serde_json::from_value(serde_json::json!({
            "op":"any.v1", "config":{}, "producer":null, "consumer":null,
            "matchers":[
                {"op":"executable.v1","config":{"executables":["git"]},
                 "matchers":[],"producer":null,"consumer":null},
                {"op":"trailing-operand-prefix.v1","config":{"prefixes":["ssh://"]},
                 "matchers":[],"producer":null,"consumer":null}
            ]
        }))
        .unwrap();

        let hints = derive(&matcher);
        assert_eq!(hints.executables.len(), 1);
        assert!(hints.executables.contains("git"));
        assert!(hints.unindexed());
    }
}
