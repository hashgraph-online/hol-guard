use crate::cloud_pack::pack_from_value;
use crate::cloud_pack_request::check_arguments;
use serde_json::{json, Value};

const SLACK: &str = include_str!("../../../../contributions/cloud-actions/slack.json");

fn action_mut<'a>(pack: &'a mut Value, id: &str) -> &'a mut Value {
    pack["actions"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|action| action["actionId"] == id)
        .unwrap()
}

/// The Slack pack with `write` naming `read` as its reconcile read, after `change`.
fn paired(write: &str, read: &str, change: impl FnOnce(&mut Value)) -> Value {
    let mut pack: Value = serde_json::from_str(SLACK).unwrap();
    action_mut(&mut pack, write)["facts"]["reconcileRead"] = json!(read);
    change(&mut pack);
    pack
}

fn refused(pack: Value) -> bool {
    pack_from_value(pack).unwrap_err().code == "cloud_pack_reconcile_read_invalid"
}

#[test]
fn a_write_may_name_a_read_that_takes_its_arguments() {
    let pack = pack_from_value(paired(
        "slack.conversations.unarchive",
        "slack.conversations.history",
        |_| {},
    ))
    .unwrap();
    let write = pack.action("slack.conversations.unarchive").unwrap();
    assert_eq!(
        write.facts.reconcile_read.as_deref(),
        Some("slack.conversations.history")
    );
    // The gateway calls the read with exactly what the write was sent.
    let sent = json!({"channel": "C0123456789"});
    assert!(check_arguments(write, &sent).is_ok());
    let read = pack.action("slack.conversations.history").unwrap();
    assert!(check_arguments(read, &sent).is_ok());
}

#[test]
fn a_reconcile_read_must_be_another_read_in_the_pack() {
    for (write, read) in [
        ("slack.chat.post_message", "slack.chat.post_message"),
        ("slack.chat.post_message", "slack.missing"),
        ("slack.conversations.list", "slack.conversations.history"),
    ] {
        assert!(refused(paired(write, read, |_| {})), "{write} -> {read}");
    }
}

#[test]
fn a_reconcile_read_must_accept_every_argument_the_write_carries() {
    // A post carries `text`, which the history read would refuse as unknown.
    assert!(refused(paired(
        "slack.chat.post_message",
        "slack.conversations.history",
        |_| {}
    )));
}

#[test]
fn a_reconcile_read_must_bound_shared_arguments_the_same_way() {
    let pack = paired(
        "slack.conversations.unarchive",
        "slack.conversations.history",
        |pack| {
            action_mut(pack, "slack.conversations.history")["arguments"]["channel"]["maxLength"] =
                json!(11);
        },
    );
    assert!(refused(pack));
}

#[test]
fn a_reconcile_read_cannot_require_what_the_write_may_omit() {
    let optional = paired(
        "slack.conversations.unarchive",
        "slack.conversations.history",
        |pack| {
            action_mut(pack, "slack.conversations.unarchive")["arguments"]["channel"]["required"] =
                json!(false);
        },
    );
    assert!(refused(optional));
    let extra = paired(
        "slack.conversations.unarchive",
        "slack.conversations.history",
        |pack| {
            action_mut(pack, "slack.conversations.history")["arguments"]["limit"]["required"] =
                json!(true);
        },
    );
    assert!(refused(extra));
}
