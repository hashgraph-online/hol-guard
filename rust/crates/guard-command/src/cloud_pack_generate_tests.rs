//! `generate` drafts a pack that validates once fixtures are filled in.

use crate::cloud_pack_cli::answer;
use serde_json::{json, Value};

const PET_SHOP: &str =
    include_str!("../../../../tests/fixtures/cloud_pack_generate/pet-shop.openapi.json");

fn line(request: Value) -> Value {
    answer(request.to_string().as_bytes())
}

fn generate(request: Value) -> Value {
    let reply = line(request);
    assert_eq!(reply["ok"], json!(true), "{reply}");
    reply
}

fn pet_shop() -> Value {
    let document: Value = serde_json::from_str(PET_SHOP).unwrap();
    generate(json!({ "op": "generate", "providerId": "pet-shop", "openapi": document }))
}

/// The draft with one safe and one risky fixture added to every action.
fn filled(mut pack: Value) -> Value {
    for action in pack["actions"].as_array_mut().unwrap() {
        action["fixtures"] = json!([
            { "name": "safe call", "kind": "safe", "arguments": {}, "expect": {} },
            { "name": "risky call", "kind": "risky", "arguments": {}, "expect": {} },
        ]);
    }
    pack
}

fn action<'a>(pack: &'a Value, id: &str) -> &'a Value {
    pack["actions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|action| action["actionId"] == json!(id))
        .unwrap_or_else(|| panic!("no {id} in {pack}"))
}

#[test]
fn openapi_draft_validates_once_fixtures_are_filled() {
    let reply = pet_shop();
    let pack = reply["pack"].clone();
    let refused = line(json!({ "op": "validate", "pack": pack }));
    assert_eq!(
        refused["error"]["code"],
        json!("cloud_pack_fixtures_missing")
    );
    let accepted = line(json!({ "op": "validate", "pack": filled(pack) }));
    assert_eq!(accepted["ok"], json!(true), "{accepted}");
    assert_eq!(accepted["actions"], json!(5));
}

#[test]
fn openapi_draft_proposes_strict_classes() {
    let reply = pet_shop();
    let pack = &reply["pack"];
    let class = |id: &str| action(pack, id)["facts"]["class"].clone();
    assert_eq!(class("pet-shop.list_pets"), json!("read"));
    assert_eq!(class("pet-shop.get_pet_by_id"), json!("read"));
    assert_eq!(class("pet-shop.add_pet"), json!("update"));
    assert_eq!(class("pet-shop.remove_pet"), json!("delete"));
    assert_eq!(class("pet-shop.place_order"), json!("pay"));
    let remove = action(pack, "pet-shop.remove_pet");
    assert_eq!(
        remove["facts"]["reversibility"],
        json!({ "const": "permanent" })
    );
    assert_eq!(remove["safety"]["effect"], json!("destructive"));
    assert!(action(pack, "pet-shop.list_pets")["facts"]
        .get("reversibility")
        .is_none());
}

#[test]
fn openapi_draft_bounds_arguments_from_the_schema() {
    let reply = pet_shop();
    let pack = &reply["pack"];
    let list = action(pack, "pet-shop.list_pets");
    assert_eq!(
        list["arguments"]["status"]["pattern"],
        json!("^(?:available|pending|sold)$")
    );
    assert_eq!(list["arguments"]["limit"]["maximum"], json!(100));
    assert!(list["arguments"].get("x_request_id").is_none());
    let request = &list["executor"]["request"];
    assert_eq!(request["host"], json!("api.pet-shop.example"));
    assert_eq!(request["path"], json!("/v2/pets"));
    let get = action(pack, "pet-shop.get_pet_by_id");
    assert_eq!(
        get["executor"]["request"]["path"],
        json!("/v2/pets/{pet_id}")
    );
    assert_eq!(get["arguments"]["pet_id"]["minimum"], json!(1));
    let add = action(pack, "pet-shop.add_pet");
    assert_eq!(add["arguments"]["name"]["required"], json!(true));
    assert_eq!(add["arguments"]["name"]["maxLength"], json!(80));
    assert_eq!(add["arguments"]["tags"]["maxItems"], json!(10));
    assert!(add["arguments"].get("owner").is_none());
    assert_eq!(add["safety"]["scopes"], json!(["pets:write"]));
    assert_eq!(pack["auth"]["mode"], json!("oauth2"));
    assert_eq!(
        pack["auth"]["scopes"],
        json!(["orders:write", "pets:read", "pets:write"])
    );
    let notes = reply["notes"].to_string();
    assert!(notes.contains("operation_skipped"), "{notes}");
    assert!(notes.contains("argument_skipped"), "{notes}");
}

#[test]
fn openapi_draft_marks_provider_text_untrusted() {
    let reply = pet_shop();
    let fields = &action(&reply["pack"], "pet-shop.list_pets")["response"]["fields"][0];
    assert_eq!(fields["value"]["list"]["from"], json!(""));
    let name = fields["value"]["list"]["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|field| field["name"] == json!("name"))
        .unwrap();
    assert_eq!(name["untrusted"], json!(true));
}

#[test]
fn mcp_tool_list_drafts_remote_actions() {
    let tools = json!([
        { "name": "list_files", "description": "List files", "inputSchema": {
            "type": "object", "properties": { "folder": { "type": "string" } } } },
        { "name": "delete_file", "inputSchema": { "type": "object", "required": ["path"],
            "properties": { "path": { "type": "string", "maxLength": 512 } } } },
        { "name": "bad name\u{0007}" },
    ]);
    let reply = generate(json!({
        "op": "generate", "providerId": "files", "host": "mcp.files.example",
        "authMode": "oauth2", "mcpTools": tools,
    }));
    let pack = reply["pack"].clone();
    let delete = action(&pack, "files.delete_file");
    assert_eq!(
        delete["executor"],
        json!({ "kind": "remote-mcp", "tool": "delete_file" })
    );
    assert_eq!(delete["facts"]["class"], json!("delete"));
    // The name classifier never proposes below `update`, so an MCP read stays strict.
    assert_eq!(
        action(&pack, "files.list_files")["facts"]["class"],
        json!("update")
    );
    assert!(reply["notes"].to_string().contains("tool_skipped"));
    let accepted = line(json!({ "op": "validate", "pack": filled(pack) }));
    assert_eq!(accepted["ok"], json!(true), "{accepted}");
}

#[test]
fn generate_refuses_sources_it_cannot_pin() {
    let refuse = |request: Value| line(request)["error"]["code"].clone();
    let swagger = json!({ "swagger": "2.0", "paths": {} });
    assert_eq!(
        refuse(json!({ "op": "generate", "providerId": "shop", "openapi": swagger })),
        json!("generate_openapi_unsupported")
    );
    let plain = json!({ "openapi": "3.1.0", "servers": [{ "url": "http://api.shop.example" }], "paths": {} });
    assert_eq!(
        refuse(json!({ "op": "generate", "providerId": "shop", "openapi": plain })),
        json!("generate_openapi_server_invalid")
    );
    assert_eq!(
        refuse(json!({ "op": "generate", "providerId": "shop", "mcpTools": [] })),
        json!("request_invalid")
    );
    assert_eq!(
        refuse(json!({ "op": "generate", "providerId": "Shop!", "mcpTools": [] })),
        json!("request_invalid")
    );
    let empty = json!({ "openapi": "3.1.0", "servers": [{ "url": "https://api.shop.example" }], "paths": {} });
    assert_eq!(
        refuse(json!({ "op": "generate", "providerId": "shop", "openapi": empty })),
        json!("generate_no_actions")
    );
}

#[test]
fn self_referencing_schemas_stay_bounded() {
    let document = json!({
        "openapi": "3.0.0",
        "servers": [{ "url": "https://api.tree.example" }],
        "components": { "schemas": { "Node": { "type": "object", "properties": {
            "label": { "type": "string" },
            "left": { "$ref": "#/components/schemas/Node" },
            "right": { "$ref": "#/components/schemas/Node" } } } } },
        "paths": { "/nodes": { "post": { "operationId": "createNode",
            "requestBody": { "content": { "application/json": {
                "schema": { "$ref": "#/components/schemas/Node" } } } },
            "responses": { "200": { "description": "ok" } } } } }
    });
    let reply = generate(json!({ "op": "generate", "providerId": "tree", "openapi": document }));
    let create = action(&reply["pack"], "tree.create_node");
    assert_eq!(create["arguments"]["label"]["type"], json!("string"));
    assert_eq!(create["facts"]["class"], json!("update"));
}

#[test]
fn exported_text_is_parsed_strictly() {
    let reply = generate(json!({
        "op": "generate", "providerId": "pet-shop", "from": "openapi", "document": PET_SHOP,
    }));
    assert_eq!(reply["pack"], pet_shop()["pack"]);
    let listing = r#"{"tools": [{"name": "send_message"}]}"#;
    let reply = generate(json!({
        "op": "generate", "providerId": "chat", "host": "mcp.chat.example",
        "from": "mcp", "document": listing,
    }));
    assert_eq!(reply["pack"]["actions"][0]["facts"]["class"], json!("send"));
    let duplicate = r#"{"openapi": "3.0.0", "openapi": "3.1.0", "paths": {}}"#;
    let refused = line(json!({
        "op": "generate", "providerId": "shop", "from": "openapi", "document": duplicate,
    }));
    assert_eq!(refused["error"]["code"], json!("generate_document_invalid"));
}
