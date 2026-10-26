//! The bounded-bridge harnesses render a connector setup reason as Python
//! does: the default mode with no approval link, `ask` mode with the link.

use serde_json::Value;

use crate::bounded_hook_bridge_grok_render::{dump_object, to_native};
use crate::bounded_hook_bridge_render::{daemon_response_to_native, Rendered};
use crate::pyjson;

const VECTORS: &str = include_str!("../testdata/bounded_hook_bridge/connector_setup_vectors.json");
const URL: &str = "http://127.0.0.1:4781/approvals/0123456789abcdef";

fn field<'a>(case: &'a Value, key: &str) -> &'a str {
    case[key].as_str().expect("vector field")
}

#[test]
fn every_bridge_harness_renders_both_modes_as_python_does() {
    let cases: Value = serde_json::from_str(VECTORS).expect("vectors");
    for case in cases.as_array().expect("cases") {
        let Ok(response) = pyjson::parse(field(case, "response")) else {
            panic!("vector JSON does not parse: {case}");
        };
        let response = response.as_dict().expect("object");
        let harness = field(case, "harness");
        let exit_code = i32::try_from(case["exit_code"].as_i64().expect("exit")).expect("i32");
        let stdout = if harness == "grok" {
            let (payload, code) = to_native(response, "PreToolUse").expect("grok render");
            assert_eq!(code, exit_code, "{case}");
            dump_object(&payload)
        } else {
            let rendered = daemon_response_to_native(response, harness, "PreToolUse", false);
            let expected = Rendered {
                stdout: field(case, "stdout").to_owned(),
                stderr: field(case, "stderr").to_owned(),
                exit_code,
            };
            assert_eq!(rendered.as_ref(), Some(&expected), "{case}");
            expected.stdout
        };
        assert_eq!(stdout, field(case, "stdout"), "{case}");
        let ask = case["ask"].as_bool().expect("ask");
        assert_eq!(stdout.contains(URL), ask, "{case}");
        assert_eq!(stdout.contains("hol-guard approvals"), ask, "{case}");
    }
}
