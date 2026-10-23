//! Vectors for the native release-feed projection. The upstream shapes mirror
//! the portal's strict public projections (`guard-release-client-index/v1` and
//! `guard-release-detail/v1`), so a portal change that would reach a
//! dashboard without passing here fails as a reviewed contract break.

use super::*;

const PUBLISHED: &str = "2026-10-14T09:30:00.000Z";
const GENERATED: &str = "2026-10-21T08:00:00.000Z";

fn coverage() -> Value {
    json!({
        "attributionState": "complete",
        "historyCoverage": "complete",
        "verifiedAt": PUBLISHED,
    })
}

fn summary_row() -> Value {
    json!({
        "slug": "v3-53-0",
        "rawTag": "v3.53.0",
        "channel": "stable",
        "train": "3.53",
        "versionLabel": "3.53.0",
        "title": "Guard 3.53.0",
        "publishedAt": PUBLISHED,
        "path": "/guard/releases/v3-53-0",
        "isRecommended": true,
        "coverage": coverage(),
    })
}

fn index_document() -> Value {
    json!({
        "schemaVersion": RELEASE_INDEX_SCHEMA,
        "page": 1,
        "pageSize": 25,
        "total": 1,
        "totalPages": 1,
        "generatedAt": GENERATED,
        "releases": [summary_row()],
    })
}

fn detail_document() -> Value {
    json!({
        "schemaVersion": RELEASE_DETAIL_SCHEMA,
        "slug": "v3-53-0",
        "rawTag": "v3.53.0",
        "channel": "stable",
        "train": "3.53",
        "versionLabel": "3.53.0",
        "title": "Guard 3.53.0",
        "publishedAt": PUBLISHED,
        "summary": "Extension control and dashboard navigation work.",
        "comparison": {
            "available": true,
            "predecessorSlug": "v3-52-0",
            "predecessorRawTag": "v3.52.0",
        },
        "changes": [
            {
                "id": "change-1",
                "kind": "fixed",
                "summary": "Name why a connector scan failed and keep the rest.",
                "evidenceUrl": "https://github.com/hashgraph-online/hol-guard/pull/5535",
            }
        ],
        "roster": [
            {
                "creditId": "33333333-3333-4333-8333-333333333333",
                "githubNumericId": 4242,
                "login": "example-contributor",
                "type": "human",
                "roles": ["author"],
                "verificationMethod": "pull-request-author",
                "evidenceUrl": "https://github.com/hashgraph-online/hol-guard/pull/5535",
            }
        ],
        "coverage": coverage(),
        "assets": [
            {"name": "hol_guard-3.53.0-py3-none-any.whl", "url": "https://github.com/hashgraph-online/hol-guard/releases/download/v3.53.0/wheel"}
        ],
        "sourceNotes": {"scope": "exact_release", "text": "Upstream release notes."},
        "appliedRevisionNumber": 3,
    })
}

fn request(kind: &str, body: &Value) -> ReleaseFeedProjectRequest {
    ReleaseFeedProjectRequest {
        schema: RELEASE_FEED_REQUEST_SCHEMA.to_owned(),
        kind: kind.to_owned(),
        body: serde_json::to_string(body).unwrap(),
    }
}

fn run(request: ReleaseFeedProjectRequest) -> Value {
    let bytes = evaluate_release_feed_project(&request).expect("frame bytes");
    serde_json::from_slice(&bytes).expect("frame json")
}

fn outcome(frame: &Value) -> (&str, Option<&str>) {
    (
        frame
            .get("outcome")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        frame.get("error_code").and_then(Value::as_str),
    )
}

fn projected(frame: &Value) -> Value {
    let body = frame
        .get("body")
        .and_then(Value::as_str)
        .expect("body text");
    serde_json::from_str(body).expect("body json")
}

#[test]
fn projects_a_published_index_page() {
    let frame = run(request("index", &index_document()));
    assert_eq!(outcome(&frame), ("ok", None));
    assert_eq!(frame.get("http_status").and_then(Value::as_i64), Some(200));
    let body = projected(&frame);
    assert_eq!(body["kind"], json!("index"));
    assert_eq!(body["total"], json!(1));
    assert_eq!(body["releases"][0]["rawTag"], json!("v3.53.0"));
    assert_eq!(
        body["releases"][0]["path"],
        json!("/guard/releases/v3-53-0")
    );
}

#[test]
fn drops_upstream_fields_the_dashboard_never_renders() {
    let mut document = index_document();
    document["releases"][0]["internalReviewerEmail"] = json!("someone@example.com");
    document["unexpectedTopLevel"] = json!({"token": "secret"});
    let body = projected(&run(request("index", &document)));
    let row = body["releases"][0].as_object().expect("row object");
    assert!(!row.contains_key("internalReviewerEmail"));
    assert!(body
        .as_object()
        .expect("body")
        .get("unexpectedTopLevel")
        .is_none());
    // The allowlist keeps the projection renderable as the portal grows.
    assert_eq!(row.len(), 10);
}

#[test]
fn rejects_an_index_that_is_not_the_published_archive_schema() {
    let mut document = index_document();
    document["schemaVersion"] = json!("guard-release-client-index/v2");
    assert_eq!(
        outcome(&run(request("index", &document))),
        ("error", Some("release_feed_payload_invalid"))
    );
}

#[test]
fn rejects_more_rows_than_the_page_claims_to_carry() {
    let mut document = index_document();
    let mut second = summary_row();
    second["slug"] = json!("v3-52-0");
    second["rawTag"] = json!("v3.52.0");
    document["releases"] = json!([summary_row(), second]);
    document["pageSize"] = json!(1);
    assert_eq!(
        outcome(&run(request("index", &document))),
        ("error", Some("release_feed_payload_invalid"))
    );
}

#[test]
fn rejects_a_repeated_release_slug() {
    let mut document = index_document();
    document["releases"] = json!([summary_row(), summary_row()]);
    assert_eq!(
        outcome(&run(request("index", &document))),
        ("error", Some("release_feed_payload_invalid"))
    );
}

#[test]
fn rejects_a_release_path_that_leaves_the_releases_tree() {
    for path in [
        "https://evil.example/guard/releases/v3-53-0",
        "//evil.example/guard/releases",
        "/guard/releases/../../admin",
        "/admin/releases/v3-53-0",
    ] {
        let mut document = index_document();
        document["releases"][0]["path"] = json!(path);
        assert_eq!(
            outcome(&run(request("index", &document))),
            ("error", Some("release_feed_payload_invalid")),
            "path {path} must not project"
        );
    }
}

// A title is prose: a release legitimately named "under <1ms" must not take
// the whole archive off the screen. The projection therefore carries angle
// brackets through verbatim, for React to escape as text, and still refuses
// the bidi and control code points that no renderer makes safe.
#[test]
fn carries_a_markup_shaped_title_as_text_but_refuses_control_code_points() {
    let markup = "<img src=x onerror=alert(1)>";
    let mut document = index_document();
    document["releases"][0]["title"] = json!(markup);
    let frame = run(request("index", &document));
    assert_eq!(outcome(&frame), ("ok", None));
    assert_eq!(
        projected(&frame)["releases"][0]["title"],
        json!(markup),
        "the title projects unchanged, so nothing downstream sees an escaped form it would double-escape"
    );

    for hostile in [
        "title\u{202e}reversed",
        "title\u{0000}null",
        "title\u{200b}zero-width",
    ] {
        let mut document = index_document();
        document["releases"][0]["title"] = json!(hostile);
        assert_eq!(
            outcome(&run(request("index", &document))),
            ("error", Some("release_feed_payload_invalid")),
            "a title carrying a control or bidi code point must not project"
        );
    }
}

// The fields that become a URL, an attribute or a key keep the stricter
// plain-text bound: an angle bracket there is never legitimate.
#[test]
fn rejects_markup_in_an_identity_field() {
    for key in ["slug", "rawTag", "versionLabel", "path"] {
        let mut document = index_document();
        document["releases"][0][key] = json!("<img src=x onerror=alert(1)>");
        assert_eq!(
            outcome(&run(request("index", &document))),
            ("error", Some("release_feed_payload_invalid")),
            "{key} must not carry markup"
        );
    }
}

#[test]
fn rejects_a_publication_time_without_a_zone() {
    let mut document = index_document();
    document["releases"][0]["publishedAt"] = json!("2026-10-14T09:30:00");
    assert_eq!(
        outcome(&run(request("index", &document))),
        ("error", Some("release_feed_payload_invalid"))
    );
}

#[test]
fn projects_one_release_detail() {
    let frame = run(request("detail", &detail_document()));
    assert_eq!(outcome(&frame), ("ok", None));
    let body = projected(&frame);
    assert_eq!(body["kind"], json!("detail"));
    assert_eq!(body["comparison"]["predecessorRawTag"], json!("v3.52.0"));
    assert_eq!(body["changes"][0]["kind"], json!("fixed"));
    assert_eq!(body["roster"][0]["login"], json!("example-contributor"));
    assert_eq!(body["assets"].as_array().expect("assets").len(), 1);
    assert_eq!(body["sourceNotes"]["scope"], json!("exact_release"));
}

#[test]
fn renders_a_comparison_that_upstream_could_not_verify() {
    let mut document = detail_document();
    document["comparison"] = json!({"available": false, "reason": "unverified-predecessor"});
    let body = projected(&run(request("detail", &document)));
    assert_eq!(
        body["comparison"],
        json!({
            "available": false,
            "reason": "unverified-predecessor",
        })
    );
}

#[test]
fn keeps_a_change_whose_evidence_link_is_not_openable_but_drops_the_link() {
    for link in [
        json!("http://github.com/hashgraph-online/hol-guard/pull/1"),
        json!("javascript:alert(1)"),
        json!(Value::Null),
    ] {
        let mut document = detail_document();
        document["changes"][0]["evidenceUrl"] = link.clone();
        let body = projected(&run(request("detail", &document)));
        assert_eq!(
            body["changes"][0]["evidenceUrl"],
            json!(Value::Null),
            "link {link}"
        );
        assert_eq!(body["changes"][0]["id"], json!("change-1"));
    }
}

#[test]
fn drops_an_asset_that_is_not_a_plain_https_download() {
    let mut document = detail_document();
    document["assets"] = json!([
        {"name": "wheel", "url": "http://example.com/wheel"},
        {"name": "sdist", "url": "https://example.com/sdist"}
    ]);
    let body = projected(&run(request("detail", &document)));
    let assets = body["assets"].as_array().expect("assets");
    assert_eq!(assets.len(), 1);
    assert_eq!(assets[0]["name"], json!("sdist"));
}

#[test]
fn renders_a_detail_without_the_additive_optional_fields() {
    let mut document = detail_document();
    let object = document.as_object_mut().expect("detail object");
    object.remove("assets");
    object.remove("sourceNotes");
    object.remove("appliedRevisionNumber");
    let body = projected(&run(request("detail", &document)));
    assert_eq!(body["assets"], json!([]));
    assert_eq!(body["sourceNotes"], json!(Value::Null));
}

#[test]
fn rejects_a_roster_entry_without_a_verified_identity() {
    for mutation in [
        ("githubNumericId", json!(0)),
        ("type", json!("maintainer")),
        ("verificationMethod", json!("self-asserted")),
        ("roles", json!([])),
    ] {
        let mut document = detail_document();
        document["roster"][0][mutation.0] = mutation.1.clone();
        assert_eq!(
            outcome(&run(request("detail", &document))),
            ("error", Some("release_feed_payload_invalid")),
            "{} = {}",
            mutation.0,
            mutation.1
        );
    }
}

#[test]
fn rejects_a_request_that_is_not_this_operation() {
    let mut bad_schema = request("index", &index_document());
    bad_schema.schema = "guard-discovery-project-request.v1".to_owned();
    assert_eq!(
        outcome(&run(bad_schema)),
        ("error", Some("release_feed_request_invalid"))
    );

    let mut bad_kind = request("index", &index_document());
    bad_kind.kind = "contributors".to_owned();
    assert_eq!(
        outcome(&run(bad_kind)),
        ("error", Some("release_feed_request_invalid"))
    );

    let mut oversized = request("index", &index_document());
    oversized.body = "x".repeat(MAX_BODY_BYTES + 1);
    let frame = run(oversized);
    assert_eq!(
        outcome(&frame),
        ("error", Some("release_feed_request_invalid"))
    );
    assert_eq!(frame.get("http_status").and_then(Value::as_i64), Some(400));
}

#[test]
fn rejects_a_body_that_is_not_bounded_json() {
    let mut malformed = request("index", &index_document());
    malformed.body = "{\"releases\":".to_owned();
    assert_eq!(
        outcome(&run(malformed)),
        ("error", Some("release_feed_body_invalid"))
    );

    let mut deep = request("index", &index_document());
    let mut nested = json!("leaf");
    for _ in 0..MAX_JSON_DEPTH + 1 {
        nested = json!([nested]);
    }
    deep.body = serde_json::to_string(&nested).unwrap();
    assert_eq!(
        outcome(&run(deep)),
        ("error", Some("release_feed_body_invalid"))
    );
}

#[test]
fn reports_an_unrenderable_upstream_answer_as_an_upstream_failure() {
    let mut document = detail_document();
    document["changes"] = json!("all of them");
    let frame = run(request("detail", &document));
    assert_eq!(
        outcome(&frame),
        ("error", Some("release_feed_payload_invalid"))
    );
    assert_eq!(frame.get("http_status").and_then(Value::as_i64), Some(502));
    assert_eq!(frame.get("body"), Some(&Value::Null));
}

#[test]
fn prose_keeps_the_angle_brackets_release_notes_are_written_with() {
    // "Cut startup to <1ms" is ordinary release prose. Refusing it would
    // reject the whole document and blank the screen over punctuation; the
    // dashboard renders these fields as text and the daemon escapes the body,
    // so the brackets are safe by construction rather than by stripping.
    let mut document = detail_document();
    document["title"] = json!("Hooks answer in <1ms");
    document["summary"] = json!("A prompt that took > 5s now takes < 1s.");
    document["changes"][0]["summary"] = json!("Reject a payload when depth > 8.");
    document["sourceNotes"]["text"] = json!("Upstream notes mentioning <script> in prose.");
    let frame = run(request("detail", &document));
    assert_eq!(outcome(&frame), ("ok", None));
    let body = projected(&frame);
    assert_eq!(body["title"], json!("Hooks answer in <1ms"));
    assert_eq!(
        body["changes"][0]["summary"],
        json!("Reject a payload when depth > 8.")
    );
}

#[test]
fn an_identity_field_still_refuses_markup() {
    // A slug, a tag or a login is a key, not prose: it ends up in URLs and
    // attributes, so it keeps the narrower alphabet.
    for (field, value) in [
        ("rawTag", json!("v3.53.0<script>")),
        ("versionLabel", json!("3.53.0>")),
        ("train", json!("<3.53")),
    ] {
        let mut document = detail_document();
        document[field] = value;
        assert_eq!(
            outcome(&run(request("detail", &document))),
            ("error", Some("release_feed_payload_invalid")),
            "{field} must not project markup"
        );
    }
}

#[test]
fn bidi_and_control_characters_never_reach_the_screen() {
    // A right-to-left override can make one release read as another in a list.
    let mut document = detail_document();
    document["title"] = json!("Guard 3.53.0\u{202e}drowssap");
    assert_eq!(
        outcome(&run(request("detail", &document))),
        ("error", Some("release_feed_payload_invalid"))
    );
}

#[test]
fn an_instant_is_a_whole_timestamp_or_it_is_nothing() {
    for bad in [
        "2026-10-14T09:30:00",             // no zone at all
        "2026-10-14T09:3000.000Z",         // the second separator is missing
        "2026-10-14T09:30:61Z",            // no such second
        "2026-10-14T09:30:0aZ",            // the seconds are not digits
        "2026-10-14T09:30:00.Z",           // a fraction with no digits
        "2026-10-14T09:30:00.1234567890Z", // more fraction than a timestamp carries
        "2026-10-14T09:30:00+24:00",       // no such zone
        "2026-10-14T09:30:00+05:60",       // no such zone minute
        "2026-10-14T09:30:00+0530",        // the zone separator is missing
        "2026-10-14T09:30:00Z ",           // trailing text
    ] {
        let mut document = detail_document();
        document["publishedAt"] = json!(bad);
        assert_eq!(
            outcome(&run(request("detail", &document))),
            ("error", Some("release_feed_payload_invalid")),
            "{bad} must not project"
        );
    }

    for good in [
        "2026-10-14T09:30:00Z",
        "2026-10-14T09:30:00.123456Z",
        "2026-10-14T09:30:00+05:30",
        "2026-10-14T09:30:00.5-08:00",
        // A leap second is a real instant the portal may publish.
        "2026-12-31T23:59:60Z",
    ] {
        let mut document = detail_document();
        document["publishedAt"] = json!(good);
        assert_eq!(
            outcome(&run(request("detail", &document))),
            ("ok", None),
            "{good} must project"
        );
    }
}
