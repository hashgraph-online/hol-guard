//! Bridge the rich native shell model into the existing monotonic floor algebra.

use std::path::Path;

use crate::canonical_command::CanonicalCommand;
use crate::command_critical_floors::command_critical_floor_factors;
use crate::effect_decision::{
    evaluate_effect_decision, EffectDecisionRequest, GuardAction, EFFECT_DECISION_SCHEMA_VERSION,
};
use crate::{CommandSegmentV1, CommandSpanV1};

pub fn critical_floor_action(
    script: &str,
    cwd: &Path,
    home: &Path,
) -> Result<GuardAction, &'static str> {
    let command = parse_floor_command(script, Some(cwd), Some(home));
    let decision = evaluate_effect_decision(&EffectDecisionRequest {
        factors: command_critical_floor_factors(&command, None, &[]),
        uncertainties: Vec::new(),
        schema_version: EFFECT_DECISION_SCHEMA_VERSION.to_owned(),
    })?;
    Ok(decision.action)
}

pub(crate) fn parse_floor_command(
    script: &str,
    cwd: Option<&Path>,
    home: Option<&Path>,
) -> CanonicalCommand {
    let rich = crate::command_model::parse_shell_command(
        script,
        cwd,
        home,
        "posix",
        "shell_string",
        "guard-shell",
        true,
    );
    CanonicalCommand {
        normalized_text: rich.normalized_text.clone(),
        dialect: rich.dialect.clone(),
        transport: rich.transport.clone(),
        extraction_provenance: rich.extraction_provenance.clone(),
        wrapper_chain: rich.wrapper_chain.clone(),
        segments: rich
            .segments
            .iter()
            .map(|s| CommandSegmentV1 {
                text: s.text.clone(),
                tokens: s.tokens.clone(),
                executable: s.executable.clone(),
                arguments: s.arguments.clone(),
                environment_names: s.environment_names.clone(),
                wrapper_chain: s.wrapper_chain.clone(),
                path_overridden: s.path_overridden,
                execution_context: s.execution_context.clone(),
                pipeline_index: s.pipeline_index,
                span: CommandSpanV1 {
                    source: "normalized".into(),
                    start: s.start,
                    end: s.end,
                },
            })
            .collect(),
        security_identity: rich.security_identity(),
        confidence: rich.confidence.clone(),
        uncertainty_reason: rich.uncertainty_reason.clone(),
        path_overridden: rich.path_overridden(),
    }
}
