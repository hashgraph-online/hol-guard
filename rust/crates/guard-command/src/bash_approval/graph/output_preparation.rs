//! A narrow profile whose report initialization is the first material effect.

use super::{Analysis, OutputEffect, Result, Uncertainty};
use crate::bash_approval::{Operation, Redirect};

fn pure(operation: &Operation, analysis: &Analysis) -> bool {
    match operation.argv[0].as_str() {
        ":" | "true" => true,
        "set" => operation.argv == ["set", "-euo", "pipefail"],
        "source" | "." => {
            let mut sources = analysis
                .sources
                .iter()
                .filter(|source| source.command_start == operation.command_start)
                .peekable();
            sources.peek().is_some()
                && sources.all(|source| {
                    source.analysis.writes.is_empty()
                        && source
                            .analysis
                            .operations
                            .iter()
                            .all(|operation| pure(operation, &source.analysis))
                })
        }
        _ => false,
    }
}

pub(super) fn initial(analysis: &Analysis) -> Option<Redirect> {
    let first = analysis.writes.first()?;
    if !first.top_level {
        return None;
    }
    let index = analysis.operations.iter().position(|operation| {
        operation.command_start == first.statement_start && operation.argv == [":"]
    })?;
    if !analysis.operations[..index]
        .iter()
        .all(|operation| pure(operation, analysis))
    {
        return None;
    }
    Some(first.clone())
}

pub(super) fn validate(
    entry: &str,
    writes: &[OutputEffect],
    initial: Option<&Redirect>,
) -> Result<()> {
    if writes.is_empty() {
        return Ok(());
    }
    let Some(initial) = initial else {
        return Err(Uncertainty {
            reason: "bash_output_timing_unproven",
            line: writes[0].redirect.line,
        });
    };
    if writes
        .iter()
        .any(|effect| effect.source_path != entry || effect.redirect.path != initial.path)
    {
        return Err(Uncertainty {
            reason: "bash_output_timing_unproven",
            line: initial.line,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bash_approval::graph::{build_with_outputs, Code, Executable, Resolver};
    use std::collections::BTreeMap;
    use std::time::{Duration, Instant};

    struct Config(&'static str);
    impl Resolver for Config {
        fn resolve(&self, _: &[String]) -> std::result::Result<Executable, &'static str> {
            Err("bash_helper_unresolved")
        }
        fn resolve_source(&self, _: &str) -> std::result::Result<Code, &'static str> {
            Ok(Code {
                original_path: "/config".into(),
                resolved_path: "/config".into(),
                source: self.0.into(),
            })
        }
    }

    fn run(source: &str, config: &'static str) -> Result<super::super::Graph> {
        build_with_outputs(
            Code {
                original_path: "/entry".into(),
                resolved_path: "/entry".into(),
                source: source.into(),
            },
            &["/entry".into()],
            &BTreeMap::new(),
            &Config(config),
            Instant::now() + Duration::from_secs(1),
            &BTreeMap::from([("/report".into(), 6), ("/other".into(), 7)]),
        )
    }

    #[test]
    fn report_initialization_never_moves_ahead_of_prior_operations() {
        for (source, config) in [
            ("set -euo pipefail; false; : >/report", ""),
            ("printf before; : >/report", ""),
            (". /config; : >/report", "false"),
            (". /config; : >/report", "printf before"),
            (
                "for value in first second; do . /config; done; : >/report",
                "case \"$value\" in first) : ;; second) false ;; esac",
            ),
            (". /config; : >/report", ": >/other"),
            (": >/report | true", ""),
            ("for value in first; do : >/report; done", ""),
            ("printf value >/report", ""),
            (": >/report; : >/other", ""),
        ] {
            assert_eq!(
                run(source, config).unwrap_err().reason,
                "bash_output_timing_unproven",
                "accepted {source}"
            );
        }
    }

    #[test]
    fn literal_configuration_and_infallible_prelude_preserve_initialization() {
        for operator in [">", ">>"] {
            let graph = run(&format!("set -euo pipefail; . /config; true; : {operator}/report; printf '%s' \"$label\" >>/report"), "label=ready").unwrap();
            let initialization = graph.initial_output().unwrap();
            assert_eq!(initialization.path, "/report");
            assert_eq!(initialization.append, operator == ">>");
            assert!(graph.source_for_launch().unwrap().contains(": >&6"));
        }
    }
}
