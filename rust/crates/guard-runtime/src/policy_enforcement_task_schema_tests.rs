use super::*;

const BRIEF: &str = "Review how the signed attribution token is created and checked. \
    Name the configuration key that holds the signing key, never a value.";

fn decision(harness: &str, payload: &Value) -> String {
    let mut installed = policy("allow");
    installed
        .risk_actions
        .insert("local_secret_read".into(), "block".into());
    let native = guard_command::pretool::evaluate_pre_tool_envelope(harness, "PreToolUse", payload);
    apply_pre_tool_policy(&snapshot(installed), payload, native)
        .expect("task envelope")
        .decision
}

fn task(schema: Value) -> Value {
    json!({"tool_name": "task", "tool_input": {
        "tasks": [{"id": "Review", "description": "Review", "assignment": BRIEF}],
        "outputSchema": schema,
    }})
}

#[test]
fn result_schema_field_names_are_not_credential_reads() {
    for schema in [
        json!({"type": "object", "properties": {
            "tokenFields": {"type": "array", "items": {"type": "string"}},
            "hmacHash": {"type": "string"},
            "signing_secret_name": {"type": "string"}
        }, "required": ["tokenFields"]}),
        json!({"type": "array", "items": {"type": "object", "properties": {
            "apiKey": {"type": "string"},
            "passwordPolicy": {"type": "object", "properties": {"minLength": {"type": "number"}}}
        }}}),
        json!({"anyOf": [
            {"type": "object", "properties": {"accessToken": {"type": "boolean"}}},
            {"type": "object", "properties": {"credentialsFound": {"type": "boolean"}}}
        ]}),
        json!({"$ref": "#/$defs/Finding", "$defs": {"Finding": {"type": "object",
            "properties": {"authorizationHeader": {"type": "string"}}}}}),
        json!({"type":"object", "if":{"properties":{"apiToken":{"type":"string"}}},
            "then":{"properties":{"password":{"type":"string"}}},
            "else":{"properties":{"accessToken":{"type":"string"}}}}),
        json!({"type":"object", "properties":{
            "publisher_id":{"type":"object", "properties":{"displayName":{"type":"string"}}},
            "artifact_id":{"type":"object", "properties":{"displayName":{"type":"string"}}}}}),
    ] {
        assert_eq!(decision("omp", &task(schema.clone())), "allow", "{schema}");
    }
}

#[test]
fn each_task_may_carry_its_own_result_schema() {
    let payload = json!({"tool_name": "task", "tool_input": {
        "context": BRIEF,
        "tasks": [
            {"id": "A", "description": "A", "assignment": BRIEF, "outputSchema": {
                "type": "object", "properties": {"tokenFields": {"type": "array"}}}},
            {"id": "B", "description": "B", "assignment": BRIEF, "outputSchema": {
                "type": "object", "properties": {"secretStorage": {"type": "string"}}}}
        ]
    }});
    assert_eq!(decision("omp", &payload), "allow");
}

#[test]
fn a_credential_named_property_with_a_value_keeps_the_review() {
    for schema in [
        json!({"type": "object", "properties": {"apiToken": {"type": "string", "default": "abc123"}}}),
        json!({"type": "object", "properties": {"password": {"const": "placeholder"}}}),
        json!({"type": "object", "properties": {"secret": {"enum": ["one", "two"]}}}),
        json!({"type": "object", "properties": {"token": {"type": "string", "examples": ["x"]}}}),
        json!({"type": "object", "properties": {"token": {"type": "object",
            "properties": {"value": {"type": "string", "default": "x"}}}}}),
        // A credential-named property can reference a concrete value stored
        // elsewhere. Keep review instead of trusting unresolved $ref.
        json!({"type":"object", "properties":{"apiToken":{"$ref":"#/$defs/Shared"}},
            "$defs":{"Shared":{"const":"sk-example"}}}),
        json!({"type":"object", "properties":{"password":{"$ref":"#/definitions/Ref"}},
            "definitions":{"Ref":{"default":"example"}}}),
        json!({"type":"object", "properties":{"token":{"$dynamicRef":"#s"}},
            "$defs":{"Shared":{"$dynamicAnchor":"s","const":"secret"}}}),
        // A name map whose entry is a bare value, not a schema.
        json!({"type": "object", "properties": {"apiToken": "abc123"}}),
        // A look-alike inside an example is data, never a schema to trust.
        json!({"type": "object", "examples": [{"properties": {"apiToken": "abc123"}}]}),
        json!({"type": "object", "default": {"properties": {"apiToken": {"type": "string"}}}}),
    ] {
        assert_eq!(decision("omp", &task(schema.clone())), "deny", "{schema}");
    }
}

#[test]
fn credential_named_arguments_outside_a_result_schema_keep_the_review() {
    for payload in [
        json!({"tool_name": "task", "tool_input": {"apiToken": "placeholder",
            "tasks": [{"id": "A", "description": "A", "assignment": BRIEF}]}}),
        json!({"tool_name": "task", "tool_input": {
            "tasks": [{"id": "A", "description": "A", "assignment": BRIEF, "token": "placeholder"}]}}),
        json!({"tool_name": "task", "tool_input": {
            "tasks": [{"id": "A", "description": "A", "assignment": BRIEF}],
            "context": {"secret": "placeholder"}}}),
        // A property map beside the schema, not inside an outputSchema.
        json!({"tool_name": "task", "tool_input": {
            "tasks": [{"id": "A", "description": "A", "assignment": BRIEF}],
            "properties": {"tokenFields": {"type": "array"}}}}),
        // A string schema is not a schema this exemption understands.
        json!({"tool_name": "task", "tool_input": {
            "tasks": [{"id": "A", "description": "A", "assignment": BRIEF}],
            "outputSchema": "{\"properties\":{\"tokenFields\":{}}}", "token": "placeholder"}}),
    ] {
        assert_eq!(decision("omp", &payload), "deny", "{payload}");
    }
}

#[test]
fn the_schema_exemption_is_only_for_the_omp_task_tool() {
    let schema = json!({"type": "object", "properties": {"tokenFields": {"type": "array"}}});
    for (harness, tool) in [
        ("claude-code", "task"),
        ("codex", "task"),
        ("omp", "Task"),
        ("omp", "bash"),
        ("omp", "wait"),
    ] {
        let payload = json!({"tool_name": tool, "tool_input": {
            "tasks": [{"id": "A", "description": "A", "assignment": BRIEF}],
            "outputSchema": schema.clone(),
        }});
        assert_eq!(decision(harness, &payload), "deny", "{harness} {tool}");
    }
}
