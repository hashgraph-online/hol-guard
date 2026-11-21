use crate::cloud_pack::{pack_from_value, parse_pack, PackAction};
use crate::cloud_pack_facts::extract;
use crate::cloud_pack_request::{check_arguments, render};
use guard_contracts::{Fact, FactSelectorV2, FactSubjectV2, Match3, MoneyDirectionV2};
use serde_json::{json, Value};
use std::collections::BTreeMap;

const STRIPE: &str = include_str!("../../../../contributions/cloud-actions/stripe.json");
const ACCOUNT: &str = "acct_1PqA1b2C3d4E5f6G";

fn action(id: &str) -> PackAction {
    parse_pack(STRIPE.as_bytes())
        .unwrap()
        .actions
        .into_iter()
        .find(|action| action.action_id == id)
        .unwrap()
}

fn facts(id: &str, args: Value) -> guard_contracts::ActionFactsV2 {
    let action = action(id);
    let checked = check_arguments(&action, &args).unwrap().clone();
    extract(&action, &checked)
}

/// The Stripe pack with `id` changed by `change`, and the code validation refuses it with.
fn edited(id: &str, change: impl FnOnce(&mut Value)) -> &'static str {
    let mut pack: Value = serde_json::from_str(STRIPE).unwrap();
    let action = pack["actions"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|action| action["actionId"] == id)
        .unwrap();
    change(action);
    pack_from_value(pack).unwrap_err().code
}

fn workspace_limit(facts: &guard_contracts::ActionFactsV2) -> Match3 {
    let selector: FactSelectorV2 = serde_json::from_value(json!({
        "classes": ["pay"],
        "money_directions": ["out"],
        "min_amount_minor": 100_000
    }))
    .unwrap();
    selector.validate().unwrap();
    selector.matches(&FactSubjectV2 {
        provider: "stripe",
        facts,
        session: None,
        windows: &BTreeMap::new(),
    })
}

#[test]
fn a_payout_reports_its_amount_and_uppercased_currency() {
    let facts = facts(
        "stripe.payouts.create",
        json!({"amount": 99_999, "currency": "usd"}),
    );
    let money = facts.money.known().unwrap();
    assert_eq!(money.amount_minor, 99_999);
    assert_eq!(money.currency, "USD");
    assert_eq!(money.direction, MoneyDirectionV2::Out);
}

#[test]
fn a_workspace_money_limit_applies_at_the_exact_amount() {
    for id in ["stripe.payouts.create", "stripe.transfers.create"] {
        // A payout goes to the account's own bank; only a transfer names a destination.
        let call = |amount: u64| {
            let mut args = json!({"amount": amount, "currency": "eur"});
            if id == "stripe.transfers.create" {
                args["destination"] = json!(ACCOUNT);
            }
            facts(id, args)
        };
        let (below, at) = (call(99_999), call(100_000));
        assert_eq!(workspace_limit(&below), Match3::No, "{id}");
        assert_eq!(workspace_limit(&at), Match3::Yes, "{id}");
    }
}

#[test]
fn a_refund_without_a_currency_leaves_money_unknown() {
    let facts = facts(
        "stripe.refunds.create",
        json!({"payment_intent": "pi_3PqA1b2C3d4E5f6G", "amount": 2500}),
    );
    assert_eq!(facts.money, Fact::Unknown);
    assert_eq!(workspace_limit(&facts), Match3::Unknown);
}

#[test]
fn a_price_is_money_in_and_outside_a_money_out_limit() {
    let facts = facts(
        "stripe.prices.create",
        json!({"product": "prod_PqA1b2C3d4E5f6", "unit_amount": 500_000, "currency": "usd"}),
    );
    assert_eq!(facts.money.known().unwrap().direction, MoneyDirectionV2::In);
    assert_eq!(workspace_limit(&facts), Match3::No);
}

#[test]
fn a_form_body_is_percent_encoded_and_labelled() {
    let request = render(
        &action("stripe.transfers.create"),
        &json!({
            "amount": 100_000,
            "currency": "eur",
            "destination": ACCOUNT,
            "description": "Order 1042 & fees=paid"
        }),
    )
    .unwrap();
    assert_eq!(
        request.body.as_deref(),
        Some(
            "amount=100000&currency=eur&destination=acct_1PqA1b2C3d4E5f6G\
             &description=Order+1042+%26+fees%3Dpaid"
        )
    );
    assert!(request.headers.contains(&[
        "content-type".to_owned(),
        "application/x-www-form-urlencoded".to_owned()
    ]));
}

#[test]
fn a_form_field_whose_argument_is_absent_is_left_out() {
    let request = render(
        &action("stripe.refunds.create"),
        &json!({"payment_intent": "pi_3PqA1b2C3d4E5f6G"}),
    )
    .unwrap();
    assert_eq!(
        request.body.as_deref(),
        Some("payment_intent=pi_3PqA1b2C3d4E5f6G")
    );
}

#[test]
fn a_form_refuses_nested_values_and_bad_names() {
    let form = "/executor/request/body/form";
    let nested = edited("stripe.payouts.create", |action| {
        action.pointer_mut(form).unwrap()[0]["value"] = json!({"object": []});
    });
    assert_eq!(nested, "cloud_pack_template_form_invalid");
    let renamed = edited("stripe.payouts.create", |action| {
        action.pointer_mut(form).unwrap()[0]["name"] = json!("amount&currency");
    });
    assert_eq!(renamed, "cloud_pack_template_form_invalid");
    let duplicate = edited("stripe.payouts.create", |action| {
        action.pointer_mut(form).unwrap()[1]["name"] = json!("amount");
    });
    assert_eq!(duplicate, "cloud_pack_template_form_invalid");
}

#[test]
fn a_form_is_only_a_whole_body() {
    let code = edited("stripe.payouts.create", |action| {
        let form = action["executor"]["request"]["body"].take();
        action["executor"]["request"]["body"] = json!({"object": [{"name": "x", "value": form}]});
    });
    assert_eq!(code, "cloud_pack_template_form_invalid");
}

#[test]
fn money_needs_an_integer_amount_and_one_currency_source() {
    let money = "/facts/money";
    let string_amount = edited("stripe.payouts.create", |action| {
        action.pointer_mut(money).unwrap()["amount"] = json!("currency");
    });
    assert_eq!(string_amount, "cloud_pack_money_invalid");
    let both = edited("stripe.payouts.create", |action| {
        action.pointer_mut(money).unwrap()["currency"] = json!("USD");
    });
    assert_eq!(both, "cloud_pack_money_invalid");
    let lowercase = edited("stripe.payouts.create", |action| {
        let spec = action.pointer_mut(money).unwrap().as_object_mut().unwrap();
        spec.remove("currencyArgument");
        spec.insert("currency".into(), json!("usd"));
    });
    assert_eq!(lowercase, "cloud_pack_money_invalid");
    let unbounded = edited("stripe.payouts.create", |action| {
        action["arguments"]["currency"]["maxLength"] = json!(8);
    });
    assert_eq!(unbounded, "cloud_pack_money_invalid");
}

#[test]
fn a_fixed_currency_is_reported_as_given() {
    let mut pack: Value = serde_json::from_str(STRIPE).unwrap();
    let payout = pack["actions"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|action| action["actionId"] == "stripe.payouts.create")
        .unwrap();
    let spec = payout["facts"]["money"].as_object_mut().unwrap();
    spec.remove("currencyArgument");
    spec.insert("currency".into(), json!("GBP"));
    let pack = pack_from_value(pack).unwrap();
    let action = pack.action("stripe.payouts.create").unwrap();
    let args = json!({"amount": 700, "currency": "usd"});
    let facts = extract(action, check_arguments(action, &args).unwrap());
    assert_eq!(facts.money.known().unwrap().currency, "GBP");
}

#[test]
fn a_form_value_may_carry_a_tab() {
    let request = render(
        &action("stripe.payouts.create"),
        &json!({"amount": 500, "currency": "usd", "description": "Order\t1042"}),
    )
    .unwrap();
    assert_eq!(
        request.body.as_deref(),
        Some("amount=500&currency=usd&description=Order%091042")
    );
}

#[test]
fn a_form_stops_once_it_passes_its_limit() {
    let action = action("stripe.payouts.create");
    let crate::cloud_pack::Executor::DeclarativeHttp { request } = &action.executor else {
        panic!("stripe payouts are declarative HTTP");
    };
    let Some(crate::cloud_pack::Template::Form(fields)) = &request.body else {
        panic!("stripe payouts send a form");
    };
    let args = json!({"amount": 500, "currency": "usd", "description": "x".repeat(200)});
    let args = args.as_object().unwrap();
    let whole = crate::cloud_pack_form::render(fields, args, usize::MAX).unwrap();
    assert_eq!(
        crate::cloud_pack_form::render(fields, args, whole.len()).as_deref(),
        Some(whole.as_str())
    );
    assert_eq!(
        crate::cloud_pack_form::render(fields, args, whole.len() - 1),
        None
    );
    assert_eq!(crate::cloud_pack_form::render(fields, args, 10), None);
}

#[test]
fn hubspot_deletes_accept_their_empty_success() {
    const HUBSPOT: &str = include_str!("../../../../contributions/cloud-actions/hubspot.json");
    let pack = parse_pack(HUBSPOT.as_bytes()).unwrap();
    let project = crate::cloud_pack_response::project;
    // HubSpot answers a batch archive, a GDPR erasure and a schema delete
    // with 204 and no body.
    for id in [
        "hubspot.objects.archive",
        "hubspot.contacts.gdpr_delete",
        "hubspot.schemas.delete",
    ] {
        let action = pack.action(id).unwrap();
        assert!(project(action, b"").is_ok(), "{id}");
    }
    let list = pack.action("hubspot.objects.list").unwrap();
    assert_eq!(project(list, b"").unwrap_err(), "response_json_invalid");
}

#[test]
fn a_form_constant_is_limited_in_characters() {
    let with_const = |text: String| {
        let mut pack: Value = serde_json::from_str(STRIPE).unwrap();
        let action = pack["actions"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|action| action["actionId"] == "stripe.payouts.create")
            .unwrap();
        action.pointer_mut("/executor/request/body/form").unwrap()[2]["value"] =
            json!({"const": text});
        pack_from_value(pack)
            .map(|_| ())
            .map_err(|error| error.code)
    };
    assert_eq!(with_const("é".repeat(256)), Ok(()));
    assert_eq!(
        with_const("é".repeat(257)),
        Err("cloud_pack_template_form_invalid")
    );
}
