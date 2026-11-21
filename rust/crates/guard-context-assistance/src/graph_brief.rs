use super::{ContextBrief, ContextExcerpt, Graph, RuntimeError, Value, View, ViewHandle};
use crate::{ContextDocument, Limits};
use std::collections::BTreeSet;

pub(crate) struct BriefScope<'a> {
    pub(crate) domain: &'a str,
    pub(crate) view_id: &'a str,
    pub(crate) policy_revision: &'a str,
    pub(crate) sources: &'a BTreeSet<String>,
    pub(crate) limits: &'a Limits,
}

fn digest(value: &Value) -> bool {
    value
        .as_str()
        .is_some_and(|s| s.len() == 64 && s.bytes().all(|c| c.is_ascii_hexdigit()))
}

pub(super) fn validate_brief(
    raw: &Value,
    graph: &Graph,
    view: &View,
    handle: &ViewHandle,
) -> Result<ContextBrief, RuntimeError> {
    validate(
        raw,
        &BriefScope {
            domain: &handle.workspace.id,
            view_id: &handle.id,
            policy_revision: &view.policy_revision,
            sources: &view.sources,
            limits: &graph.limits,
        },
        |source, node| graph.sources.get(source)?.documents.get(node),
    )
}

pub(crate) fn validate<'a>(
    raw: &Value,
    scope: &BriefScope<'_>,
    document: impl Fn(&str, &str) -> Option<&'a ContextDocument>,
) -> Result<ContextBrief, RuntimeError> {
    let context = &raw["context"];
    let snapshot = &context["snapshot"];
    let rendered = raw["rendered"]
        .as_str()
        .filter(|s| s.len() <= 256 * 1024)
        .ok_or(RuntimeError::TransportFailed)?;
    let tokens = snapshot["stats"]["rendered_tokens"]
        .as_u64()
        .ok_or(RuntimeError::TransportFailed)?;
    let blocks = snapshot["blocks"]
        .as_array()
        .filter(|b| b.len() <= 16)
        .ok_or(RuntimeError::TransportFailed)?;
    // CIGAR binds a view snapshot's policy revision to its scope digest. The
    // original host policy revision remains in the retained request; compare
    // both, preserving revision strings beyond JavaScript integer precision.
    if !digest(&snapshot["id"])
        || !digest(&context["id"])
        || !digest(&context["scope_id"])
        || tokens > u64::from(scope.limits.context_tokens - scope.limits.reserve_tokens)
        || snapshot["policy_revision"] != context["scope_id"]
        || context["request"]["policy_revision"] != scope.policy_revision
        || snapshot["domain"] != scope.domain
        || context["view"]["id"] != scope.view_id
    {
        return Err(RuntimeError::TransportFailed);
    }
    let mut citations = Vec::new();
    let mut excerpts = Vec::new();
    for block in blocks {
        let mut block_citations = Vec::new();
        for citation in block["citations"]
            .as_array()
            .filter(|items| !items.is_empty() && items.len() <= 64)
            .ok_or(RuntimeError::TransportFailed)?
        {
            let source = citation["source"]
                .as_str()
                .filter(|source| scope.sources.contains(*source))
                .ok_or(RuntimeError::ScopeDenied)?;
            let node = citation["node_id"]
                .as_str()
                .ok_or(RuntimeError::TransportFailed)?;
            let doc = document(source, node).ok_or(RuntimeError::ScopeDenied)?;
            let start = citation["start_line"]
                .as_u64()
                .ok_or(RuntimeError::TransportFailed)?;
            let end = citation["end_line"]
                .as_u64()
                .ok_or(RuntimeError::TransportFailed)?;
            let lines = doc.text.split('\n').count() as u64;
            if start != u64::from(doc.start_line)
                || end < start
                || end >= u64::from(doc.start_line) + lines
                || !digest(&citation["document_digest"])
                || block["text"].as_str() != Some(&doc.text)
            {
                return Err(RuntimeError::ScopeDenied);
            }
            citations.push(citation.clone());
            block_citations.push(citation.clone());
        }
        excerpts.push(ContextExcerpt {
            text: block["text"]
                .as_str()
                .ok_or(RuntimeError::TransportFailed)?
                .into(),
            citations: block_citations,
        });
    }
    Ok(ContextBrief {
        schema: "guard-cigar-context-brief.v1",
        snapshot_id: snapshot["id"]
            .as_str()
            .ok_or(RuntimeError::TransportFailed)?
            .into(),
        policy_revision: scope.policy_revision.into(),
        graph_revision: snapshot["graph_revision"]
            .as_u64()
            .ok_or(RuntimeError::TransportFailed)?,
        rendered: rendered.into(),
        rendered_tokens: tokens,
        citations,
        excerpts,
        data_role: true,
    })
}
