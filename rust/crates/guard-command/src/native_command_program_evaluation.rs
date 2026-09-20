//! Per-decision matcher execution with a shared result cache and deadline.

use super::*;

pub(super) struct Evaluation<'a> {
    pub(super) program: &'a NativeCommandProgram,
    pub(super) command: &'a CanonicalCommandV1,
    pub(super) deadline: Option<Instant>,
    pub(super) memo: Vec<Option<MatchResult>>,
}

impl Evaluation<'_> {
    pub(super) fn check_deadline(&self) -> Result<(), &'static str> {
        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            Err("native_command_deadline_exceeded")
        } else {
            Ok(())
        }
    }

    pub(super) fn evaluate(&mut self, index: usize) -> MatchResult {
        self.check_deadline()?;
        if let Some(value) = &self.memo[index] {
            return value.clone();
        }
        let program = self.program;
        let value = match &program.nodes[index].matcher {
            Matcher::Executable(node) => self.executable(node),
            Matcher::Operand(matcher) => matcher
                .match_segments_with_deadline(self.command, self.deadline)
                .map(Arc::from),
            Matcher::Structured(matcher) => matcher
                .match_segments_with_deadline(self.command, self.deadline)
                .map(Arc::from),
            Matcher::CommonCli(matcher) => matcher.match_segments(self.command).map(Arc::from),
            Matcher::Database(matcher) => matcher
                .match_segments_with_deadline(self.command, self.deadline)
                .map(Arc::from),
            Matcher::Specialized(matcher) => matcher
                .match_segments_with_deadline(self.command, self.deadline)
                .map(Arc::from),
            Matcher::Arguments(node) => {
                let empty = BTreeSet::new();
                let mut evidence = Vec::new();
                for (index, segment) in self.command.segments.iter().enumerate() {
                    if executable_matches(segment, &node.executables) {
                        let arguments = segment
                            .arguments
                            .iter()
                            .map(|value| lowercase_for_ascii_comparison(value))
                            .collect::<Vec<_>>();
                        if node.required_arguments.is_subset(
                            &argument_semantics(&arguments, &empty, &BTreeSet::new()).present_flags,
                        ) {
                            evidence.push(index);
                        }
                    }
                }
                Ok(Arc::from(evidence))
            }
            Matcher::Any(children) | Matcher::All(children) => {
                let require_all = matches!(&program.nodes[index].matcher, Matcher::All(_));
                let mut evidence = Vec::new();
                for child in children {
                    let values = self.evaluate(*child)?;
                    if require_all && values.is_empty() {
                        evidence.clear();
                        break;
                    }
                    if evidence.len().saturating_add(values.len())
                        > MAX_NATIVE_COMMAND_EVIDENCE_ITEMS
                    {
                        return Err("native_command_evidence_limit_exceeded");
                    }
                    evidence.extend_from_slice(&values);
                }
                Ok(Arc::from(evidence))
            }
            Matcher::Pipeline(producer, consumer) => {
                let producer = self.evaluate(*producer)?;
                let consumer = self.evaluate(*consumer)?;
                let mut evidence = Vec::new();
                'pairs: for first in producer.iter() {
                    for second in consumer.iter() {
                        let before = &self.command.segments[*first];
                        let after = &self.command.segments[*second];
                        if *second == *first + 1
                            && before.execution_context == after.execution_context
                            && after.pipeline_index == before.pipeline_index + 1
                        {
                            evidence.extend([*first, *second]);
                            break 'pairs;
                        }
                    }
                }
                Ok(Arc::from(evidence))
            }
        };
        self.check_deadline()?;
        self.memo[index] = Some(value.clone());
        value
    }

    fn executable(&self, node: &ExecutableNode) -> MatchResult {
        let contract = &node.contract;
        let mut evidence = Vec::new();
        for (index, segment) in self.command.segments.iter().enumerate() {
            self.check_deadline()?;
            if !executable_matches(segment, &contract.executables) {
                continue;
            }
            let arguments: Vec<_> = segment
                .arguments
                .iter()
                .map(|value| lowercase_for_ascii_comparison(value))
                .collect();
            let filtered = without_options(
                &arguments,
                &contract.interspersed_options_with_values,
                &contract.interspersed_flags,
            );
            let remaining = if contract.allow_leading_options {
                after_leading_options(
                    &filtered,
                    &contract.leading_options_with_values,
                    &contract.interspersed_flags,
                )
            } else {
                filtered.as_slice()
            };
            let matched = node.paths.iter().find(|path| remaining.starts_with(path));
            let matched = matched.or_else(|| {
                contract
                    .fail_secure_unknown_options
                    .then(|| {
                        node.paths.iter().find(|path| {
                            matches_subcommands_conservatively_with_deadline(
                                &arguments,
                                path,
                                &node.all_value_options,
                                &contract.interspersed_flags,
                                self.deadline,
                            )
                        })
                    })
                    .flatten()
            });
            let Some(path) = matched else {
                continue;
            };
            let flag_arguments = if contract.required_flags_in_all_arguments {
                arguments.as_slice()
            } else {
                remaining.get(path.len()..).unwrap_or_default()
            };
            let semantics = argument_semantics(
                flag_arguments,
                &node.all_value_options,
                &contract.inverse_flag_pairs,
            );
            let mut required_present = contract.required_flags.is_subset(&semantics.present_flags)
                && contract
                    .required_option_values
                    .iter()
                    .all(|(option, values)| {
                        semantics
                            .option_value(option)
                            .is_some_and(|value| values.contains(value))
                    });
            if required_present
                && contract.fail_secure_unknown_options
                && contract.required_flags_in_all_arguments
            {
                let mut requirements = contract.required_flags.clone();
                for (positive, negative) in &contract.inverse_flag_pairs {
                    if !requirements.contains(positive) && !requirements.contains(negative) {
                        continue;
                    }
                    requirements.remove(positive);
                    requirements.remove(negative);
                    if let Some(token) = semantics.option_token(positive) {
                        requirements.insert(token.to_owned());
                    }
                }
                requirements.extend(
                    contract
                        .required_option_values
                        .iter()
                        .map(|(option, _)| option.clone()),
                );
                required_present = flags_present_in_all_option_parses_with_deadline(
                    &arguments,
                    &requirements,
                    &node.all_value_options,
                    &node.proof_known_flags,
                    self.deadline,
                );
            }
            if required_present
                && contract
                    .forbidden_flags
                    .is_disjoint(&semantics.present_flags)
            {
                evidence.push(index);
            }
        }
        Ok(Arc::from(evidence))
    }
}

fn after_leading_options<'a>(
    arguments: &'a [String],
    options: &BTreeSet<String>,
    flags: &BTreeSet<String>,
) -> &'a [String] {
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        if argument == "--" {
            return &arguments[index + 1..];
        }
        if !argument.starts_with('-') {
            return &arguments[index..];
        }
        index += known_option_advance(argument, options, flags).unwrap_or(1);
    }
    &[]
}

fn without_options(
    arguments: &[String],
    options: &BTreeSet<String>,
    flags: &BTreeSet<String>,
) -> Vec<String> {
    if options.is_empty() && flags.is_empty() {
        return arguments.to_vec();
    }
    let mut retained = Vec::new();
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        if argument == "--" {
            retained.extend_from_slice(&arguments[index + 1..]);
            break;
        }
        let option_name = argument.split('=').next().unwrap_or(argument);
        if argument.starts_with("--")
            && !options.contains(option_name)
            && !flags.contains(option_name)
        {
            retained.push(argument.clone());
            index += 1;
            continue;
        }
        if let Some(advance) = known_option_advance(argument, options, flags) {
            index += advance;
        } else {
            retained.push(argument.clone());
            index += 1;
        }
    }
    retained
}
