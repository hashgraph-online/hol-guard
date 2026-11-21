//! `cli_hook_emit`'s printed document against Python's
//! `_emit_native_hook_json_document` (protect the approval fragments,
//! `_redact_payload(command="hook")`, restore,
//! `_render_redacted_json_payload`). Every expected string was recorded from
//! the Python 3.12 reference with `Path.home()` at `/Users/alice`, so the
//! resident's document must match it byte for byte. The one deliberate
//! departure is a sentinel the answer wrote for itself: Python turned one
//! into a signed fragment, and the resident prints it as written.

use super::printed;
use serde_json::json;

/// A string under a key that is not sensitive, and the JSON Python prints
/// for it: every `_SENSITIVE_STRING_PATTERNS` rule, Python's `\s`, `\b` and
/// IGNORECASE classes, `key=value` assignments, local paths, the approval
/// link and non-ASCII text.
const STRING_VECTORS: &[(&str, &str)] = &[
    ("a -----BEGIN RSA PRIVATE KEY-----\u{a}MII\u{a}x\u{a}-----END RSA PRIVATE KEY----- b -----END RSA PRIVATE KEY-----", r#""a ***** b -----END RSA PRIVATE KEY-----""#),
    ("Authorization: Bearer abc.def, next", r#""Authorization: *****, next""#),
    ("AUTHOR\u{130}ZAT\u{131}ON:\u{3000}tok;rest", r#""AUTHOR\u0130ZAT\u0131ON:\u3000*****;rest""#),
    ("authorization:\u{1c}bearer\u{1f}x y", r#""authorization:\u001c***** y""#),
    ("api-key: v1 API_KEY:v2 apikey:\u{9}v3 ap\u{131} key: v4", r#""api-key: ***** API_KEY:***** apikey:\t***** ap\u0131 key: *****""#),
    ("use sk-abcdefghijklmnopqrstuvwxyz now", r#""use ***** now""#),
    ("sk-proj-abcdefghijklmnopqrst12345", r#""*****""#),
    ("xsk-abcdefghijklmnopqrstuv _sk-abcdefghijklmnopqrstuv", r#""xsk-abcdefghijklmnopqrstuv _sk-abcdefghijklmnopqrstuv""#),
    ("sk-abcdefghijklmnopqrstuvwxyz\u{e9} sk-abc_def-ghijklmnopqrstuv-wxyz\u{e9}", r#""sk-abcdefghijklmnopqrstuvwxyz\u00e9 *****wxyz\u00e9""#),
    ("\u{e9}sk-abcdefghijklmnopqrstuv -sk-abcdefghijklmnopqrst-", r#""\u00e9sk-abcdefghijklmnopqrstuv -*****-""#),
    ("sk-abcdefghij\u{663}klmnopqrstuvwxyz sk-short", r#""sk-abcdefghij\u0663klmnopqrstuvwxyz sk-short""#),
    ("bearer   tok1, BEARER\u{2003}tok2 Bearer\u{1c}tok3 Bea\u{17f}er x bearer\u{85}tok4", r#""bearer   *****, BEARER\u2003***** Bearer\u001c***** Bea\u017fer x bearer\u0085*****""#),
    ("_authToken=abc\u{a}x _authToken = abc def\u{a}npm_token: xyz NPM-TOKEN=abc npm token:q", r#""npm token redacted\nx npm token redacted def\nnpm token redacted npm token redacted npm token redacted""#),
    ("a_authToken=abc \u{e9}NPM token=xx _AUTH\u{212a}EN:\u{a0}v", r#""a_authToken=***** \u00e9NPM token=***** _AUTH\u212aEN:\u00a0v""#),
    ("postgres://u:p@h/db x postgresql://a mysql://b mongodb+srv://c MONGODB://d amqp://e", r#""***** x ***** ***** ***** ***** *****""#),
    ("RED\u{130}S://h red\u{131}s://h xredis://h \u{e9}mysql://h (redis://h)", r#""***** ***** xredis://h \u00e9mysql://h (*****""#),
    ("password=hunter2&next=1 token='a b c' rest AUTH=foo", r#""password=*****&next=1 token=***** rest AUTH=foo""#),
    ("secret=\"unterminated value&x=1", r#""secret=***** value&x=1""#),
    ("api_key=\"x\" token=\"y", r#""api_key=***** token=*****""#),
    ("x=1 secret=\"a password=\"b token=\"c", r#""x=1 secret=*****b token=*****""#),
    ("mytoken= value token= Credential=x\u{3000}y t\u{f6}ken=z ApiKey=k api-key=K", r#""mytoken= value token= Credential=*****\u3000y t\u00f6ken=z ApiKey=***** api-key=*****""#),
    ("token='a&b' q secret='' k my-secret=\u{1c}v", r#""token=***** q secret=***** k my-secret=\u001cv""#),
    ("/Users/alice/project/file.txt", r#""~/project/file.txt""#),
    ("/Users/alice", r#""~""#),
    ("/Users/alicex/y", r#""~/y""#),
    ("see /Users/bob/x and (/home/carol/y) 'C:\\Users\\dave\\z' path=/Users/eve", r#""see ~/x and (~/y) '~\\z' path=~""#),
    ("x/Users/bob C:/Users/frank/a/b [D:\\\\Users\\\\g] {/home/h/i:j}", r#""x/Users/bob ~/a/b [~] {~/i:j}""#),
    ("\u{3000}/home/u/x \u{1c}/home/v `/Users/w`", r#""\u3000~/x \u001c~ `/Users/w`""#),
    ("Open https://guard.example/a?id=1#guard-token=abc.DEF_~%2B-xyz to approve", r#""Open https://guard.example/a?id=1#guard-token=abc.DEF_~%2B-xyz to approve""#),
    ("guard-token=sk-abcdefghijklmnopqrstuvwxyz and token=https://x#guard-token=zz", r#""guard-token=sk-abcdefghijklmnopqrstuvwxyz and token=*****""#),
    ("caf\u{e9} \u{2615} na\u{ef}ve \u{1f600} \u{4e2d}\u{6587}", r#""caf\u00e9 \u2615 na\u00efve \ud83d\ude00 \u4e2d\u6587""#),
];

/// Sensitive keys (safe policy literals kept, `oauth_storage_health` and
/// `authority_error` exempt), every value type, nesting, and the approval
/// fragments the document restores. The answer carries five sentinels of
/// its own, one written in Unicode digits and one shaped like a real mark.
/// None of them carries this document's mark, so each is printed as the
/// answer wrote it instead of becoming a token the answer never held.
const DOCUMENT_INPUT: &str = r#"{"policy_action":"review","api_key":"abc","token":"ALLOW","Auth_Mode":"Strict","secretList":[1,2],"password":{"a":1},"monkey":null,"tokens_used":3,"oauth_storage_health":{"token":"x","state":"Bearer abc"},"authority_error":"token=abc at /Users/alice/.cfg","authority_error_message":"plain","approval_url":"https://g.example/r#guard-token=AAA","approval_token":"https://g.example/r#guard-token=BBB","notes":["https://g.example/r#guard-token=CCC","spoof hgdfrag=efgh0 hgdfrag=efgh\u0661 hgdfrag=efgh99 hgdfrag=efgh\uff12 hgdfrag=efghaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0"],"cl\u00e9":{"nested":[],"empty":{},"deep":[{"k":1.5},[true,false,null]]},"numbers":[1e+100,-0.0,123456789012345678901234567890,0.1]}"#;
const DOCUMENT_EXPECTED: &str = r#"{
  "policy_action": "review",
  "api_key": "*****",
  "token": "ALLOW",
  "Auth_Mode": "Strict",
  "secretList": "*****",
  "password": "*****",
  "monkey": "*****",
  "tokens_used": "*****",
  "oauth_storage_health": {
    "token": "*****",
    "state": "Bearer *****"
  },
  "authority_error": "token=***** at ~/.cfg",
  "authority_error_message": "plain",
  "approval_url": "https://g.example/r#guard-token=AAA",
  "approval_token": "*****",
  "notes": [
    "https://g.example/r#guard-token=CCC",
    "spoof hgdfrag=efgh0 hgdfrag=efgh\u0661 hgdfrag=efgh99 hgdfrag=efgh\uff12 hgdfrag=efghaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0"
  ],
  "cl\u00e9": {
    "nested": [],
    "empty": {},
    "deep": [
      {
        "k": 1.5
      },
      [
        true,
        false,
        null
      ]
    ]
  },
  "numbers": [
    1e+100,
    -0.0,
    123456789012345678901234567890,
    0.1
  ]
}"#;

/// Lone surrogates, in a value, a key and an approval fragment, come back
/// as the escapes Python writes.
const SURROGATE_INPUT: &str = r#"{"m":"a\udcffb","k\udcfe":"guard-token=x\udcfd"}"#;
const SURROGATE_EXPECTED: &str = r#"{
  "m": "a\udcffb",
  "k\udcfe": "guard-token=x\udcfd"
}"#;

#[test]
fn cli_hook_emit_prints_each_string_as_python_redacts_it() {
    for (text, expected) in STRING_VECTORS {
        let response_json = serde_json::to_string(&json!({ "m": text })).expect("answer");
        let answer = printed("codex", "PreToolUse", &response_json, Some("/Users/alice"));
        assert_eq!(
            answer["stdout"].as_str().expect("stdout"),
            format!("{{\n  \"m\": {expected}\n}}"),
            "{text:?}"
        );
    }
}

#[test]
fn cli_hook_emit_prints_the_whole_document_as_python_renders_it() {
    let home = Some("/Users/alice");
    let answer = printed("cursor", "PreToolUse", DOCUMENT_INPUT, home);
    assert_eq!(answer["stdout"], DOCUMENT_EXPECTED);
    // The document is a review, which blocks: Cursor reads that from exit 2.
    assert_eq!(answer["exit_code"], 2);
    assert_eq!(answer["policy_action"], "review");
    let answer = printed("codex", "Stop", SURROGATE_INPUT, home);
    assert_eq!(answer["stdout"], SURROGATE_EXPECTED);
    assert_eq!(printed("codex", "Stop", "{}", home)["stdout"], "{}");
}
