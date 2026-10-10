use super::{
    classify_tool_name, collect_fact_maps, preferred_tool_name, GuardHookPayloadKindV2,
    NativeHookRequestV1, PreToolActionTypeV1, PATH_KEYS,
};

pub(super) fn post_action_type(
    request: &NativeHookRequestV1,
    payload_kind: GuardHookPayloadKindV2,
) -> Result<PreToolActionTypeV1, String> {
    if payload_kind == GuardHookPayloadKindV2::SourceFileRef {
        return Ok(PreToolActionTypeV1::FileRead);
    }
    let mut maps = Vec::new();
    let mut nodes = 0usize;
    collect_fact_maps(&request.payload, 0, &mut nodes, &mut maps)?;
    if let Some(tool) = preferred_tool_name(&maps)? {
        return Ok(classify_tool_name(&tool));
    }
    for record in maps {
        if record.keys().any(|key| {
            matches!(
                key.as_str(),
                "command" | "cmd" | "shell_command" | "shellCommand"
            )
        }) {
            return Ok(PreToolActionTypeV1::Command);
        }
        if record
            .keys()
            .any(|key| matches!(key.as_str(), "package" | "package_name" | "packageName"))
        {
            return Ok(PreToolActionTypeV1::Package);
        }
        if record.keys().any(|key| PATH_KEYS.contains(&key.as_str())) {
            return Ok(PreToolActionTypeV1::FileRead);
        }
        if record
            .keys()
            .any(|key| matches!(key.as_str(), "url" | "uri" | "href" | "endpoint"))
        {
            return Ok(PreToolActionTypeV1::Network);
        }
    }
    Ok(PreToolActionTypeV1::Unknown)
}
