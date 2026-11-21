//! Project captured graph observations into the resident subject contract.
//! Required assurance is not proof that the backend has enforced it.

use std::collections::BTreeMap;

use guard_contracts::{
    NativeBashAssuranceV1, NativeBashContextV1, NativeBashSubjectSchemaV1, NativeBashSubjectV1,
    NativeScriptCodeInputV1, NativeScriptInputKindV1, NativeScriptInvocationV1,
    NativeScriptOutputV1,
};
use sha2::{Digest, Sha256};

use super::graph::Graph;

/// Inputs observed by the native owner, never capabilities supplied by a host.
/// `environment` contains only selected behavior-relevant values. A caller
/// cannot substitute the daemon's environment for withheld host observations.
pub struct Observations<'a> {
    pub context: NativeBashContextV1,
    pub argv: &'a [String],
    pub interpreter: NativeScriptCodeInputV1,
    pub environment: &'a BTreeMap<String, String>,
    pub resolved_outputs: &'a BTreeMap<String, String>,
}

pub fn from_graph(
    graph: &Graph,
    observed: Observations<'_>,
) -> Result<NativeBashSubjectV1, &'static str> {
    if observed.interpreter.kind != NativeScriptInputKindV1::Interpreter
        || observed.argv.first() != Some(&graph.entry_path)
    {
        return Err("native_bash_subject_entry_invalid");
    }
    let mut inputs = vec![observed.interpreter];
    for code in &graph.code {
        inputs.push(NativeScriptCodeInputV1 {
            kind: if code.original_path == graph.entry_path {
                NativeScriptInputKindV1::Entry
            } else {
                NativeScriptInputKindV1::Helper
            },
            requested_path: code.original_path.clone(),
            resolved_path: code.resolved_path.clone(),
            content_sha256: code.content_sha256.clone(),
        });
    }
    for code in &graph.sources {
        inputs.push(NativeScriptCodeInputV1 {
            kind: NativeScriptInputKindV1::Source,
            requested_path: code.original_path.clone(),
            resolved_path: code.resolved_path.clone(),
            content_sha256: code.content_sha256.clone(),
        });
    }
    for code in &graph.startup {
        inputs.push(NativeScriptCodeInputV1 {
            kind: NativeScriptInputKindV1::Startup,
            requested_path: code.original_path.clone(),
            resolved_path: code.resolved_path.clone(),
            content_sha256: code.content_sha256.clone(),
        });
    }
    for (path, digest) in &graph.native_images {
        inputs.push(NativeScriptCodeInputV1 {
            kind: NativeScriptInputKindV1::Native,
            requested_path: path.clone(),
            resolved_path: path.clone(),
            content_sha256: digest.clone(),
        });
    }
    for (path, digest) in &graph.brokered_images {
        inputs.push(NativeScriptCodeInputV1 {
            kind: NativeScriptInputKindV1::Native,
            requested_path: path.clone(),
            resolved_path: path.clone(),
            content_sha256: digest.clone(),
        });
    }
    inputs.sort_by(|left, right| {
        (left.kind, &left.requested_path, &left.resolved_path).cmp(&(
            right.kind,
            &right.requested_path,
            &right.resolved_path,
        ))
    });
    let mut outputs = Vec::new();
    for effect in &graph.writes {
        let path = &effect.redirect.path;
        outputs.push(NativeScriptOutputV1 {
            requested_path: path.clone(),
            resolved_path: observed
                .resolved_outputs
                .get(path)
                .ok_or("native_bash_subject_output_unresolved")?
                .clone(),
            append: effect.redirect.append,
        });
    }
    let subject = NativeBashSubjectV1 {
        schema: NativeBashSubjectSchemaV1::V1,
        context: observed.context,
        argv: observed.argv.to_vec(),
        code_inputs: inputs,
        package_bindings: Vec::new(),
        environment_bindings: observed
            .environment
            .iter()
            .map(|(name, value)| (name.clone(), hex::encode(Sha256::digest(value.as_bytes()))))
            .collect(),
        invocations: graph
            .invocations
            .iter()
            .map(|call| NativeScriptInvocationV1 {
                source_path: call.source_path.clone(),
                argv: call.operation.argv.clone(),
                resolved_executable: call.resolved_path.clone(),
            })
            .collect(),
        outputs,
        execution_assurance: if !graph.brokered_images.is_empty() {
            NativeBashAssuranceV1::MacosHardenedBrokerV1
        } else if graph.startup.is_empty() {
            NativeBashAssuranceV1::MacosReadonlyRootFramedOutputsV1
        } else {
            NativeBashAssuranceV1::MacosReadonlyRootHttpReadV1
        },
    };
    subject.validate()?;
    Ok(subject)
}
