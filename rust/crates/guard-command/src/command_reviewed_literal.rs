//! Exact, bounded literal-invocation evidence for a reviewed safe variant.

use serde::Deserialize;

use crate::CanonicalCommandV1;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReviewedLiteralConfig {
    executable: String,
    arguments: Vec<String>,
    #[serde(skip)]
    expected: String,
}

impl ReviewedLiteralConfig {
    pub(crate) fn validate(mut self) -> Result<Self, &'static str> {
        let Some(expected) = reviewed_literal_spelling(&self.executable, &self.arguments) else {
            return Err("invalid_reviewed_literal_config");
        };
        self.expected = expected;
        Ok(self)
    }

    pub(crate) fn matches(&self, command: &CanonicalCommandV1) -> bool {
        // The skipped provenance bit is set only by the native parser when
        // the parser-trimmed raw text equals the normalized text. External serialized
        // models cannot assert this bit. Exact native parsing also excludes
        // redirections and embedded commands; expected contains no shell syntax.
        if !command.exact_raw_text
            || command.dialect != "posix"
            || command.transport != "shell_string"
            || command.confidence != "exact"
            || command.normalized_text != self.expected
            || !command.wrapper_chain.is_empty()
            || command.path_overridden
            || command.segments.len() != 1
        {
            return false;
        }
        let segment = &command.segments[0];
        segment.executable.as_deref() == Some(self.executable.as_str())
            && segment.tokens.len() == self.arguments.len() + 1
            && segment.tokens.first() == Some(&self.executable)
            && segment.tokens[1..] == self.arguments
            && segment.arguments == self.arguments
            && segment.environment_names.is_empty()
            && segment.wrapper_chain.is_empty()
            && !segment.path_overridden
            && segment.pipeline_index == 0
    }
}

/// The one spelling a reviewed literal invocation is allowed to have, or
/// nothing when it is not written in the grammar at all.
///
/// A configured matcher and an extension under review ask the same question of
/// the same argument vector: a bounded basename, one to sixteen literal tokens,
/// no shell syntax, expansion, wrapper or environment override, and a joined
/// invocation short enough to print as a command example. Review used to ask it
/// of a regular expression in Python, so an author could be told a vector was
/// well written and then watch the compiler refuse the matcher built from it.
pub(crate) fn reviewed_literal_spelling(executable: &str, arguments: &[String]) -> Option<String> {
    if executable.is_empty()
        || executable.len() > 64
        || !executable.is_ascii()
        || !executable.as_bytes()[0].is_ascii_alphanumeric()
        || !executable
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.+-".contains(&byte))
        || !(1..=16).contains(&arguments.len())
        || arguments
            .iter()
            .any(|argument| argument.len() > 64 || !literal_argument(argument))
    {
        return None;
    }
    let expected = std::iter::once(executable)
        .chain(arguments.iter().map(String::as_str))
        .collect::<Vec<_>>()
        .join(" ");
    (expected.len() <= 120).then_some(expected)
}

fn literal_argument(argument: &str) -> bool {
    if argument == "-" || argument == "--" {
        return true;
    }
    if argument.is_empty() || !argument.is_ascii() {
        return false;
    }
    let flag_name = argument
        .strip_prefix("--")
        .or_else(|| argument.strip_prefix('-'));
    if let Some(flag) = flag_name {
        let (name, value) = flag
            .split_once('=')
            .map_or((flag, None), |(name, value)| (name, Some(value)));
        !name.is_empty()
            && name.as_bytes()[0].is_ascii_alphanumeric()
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
            && value.is_none_or(literal_value)
    } else {
        literal_value(argument)
    }
}

fn literal_value(value: &str) -> bool {
    !value.is_empty()
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/@+-".contains(&byte))
}
