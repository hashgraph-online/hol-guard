//! Bounded batches avoid restarting the complete closure per missing object.
use super::*;

const MAX_TRANSFER_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ROUNDS: u64 = 8192;
const EXCEEDED: &str = "pack_transfer_budget_exceeded";
const INVALID: &str = "pack_transfer_request_invalid";

fn reference_cost(reference: &Value) -> Option<u64> {
    let length = reference["length"].as_u64()?;
    if reference["kind"] == "concat" {
        // The caller materializes a concatenation's parts in the same transfer.
        length.checked_add(reference["expanded_length"].as_u64()?)
    } else {
        Some(length)
    }
}

fn cost(request: &Value) -> Option<u64> {
    if let Some(reference) = request.get("need") {
        return reference_cost(reference);
    }
    request
        .get("need_archives")?
        .as_array()?
        .iter()
        .try_fold(0u64, |total, archive| {
            total.checked_add(archive["length"].as_u64()?)
        })
}

/// Charge a resumable fetch request against the cumulative transfer budget.
/// Each invocation is stateless, so the caller echoes the returned `budget` into
/// its next request. A request is charged once, when issued, from authenticated
/// reference lengths; a caller that omits the echo only fails its own retry.
pub(crate) fn account(input: &Value, mut response: Value) -> std::result::Result<Value, String> {
    let requests: Vec<&Value> = if let Some(needs) = response.get("needs") {
        needs.as_array().ok_or(INVALID)?.iter().collect()
    } else if response.get("need").is_some() || response.get("need_archives").is_some() {
        vec![&response]
    } else {
        return Ok(response);
    };
    let (mut spent, mut rounds) = match input.get("budget").filter(|b| !b.is_null()) {
        None => (0, 0),
        Some(budget) => (
            budget["spent"].as_u64().ok_or(INVALID)?,
            budget["rounds"].as_u64().ok_or(INVALID)?,
        ),
    };
    rounds = rounds.checked_add(1).ok_or(EXCEEDED)?;
    for request in requests {
        let amount = cost(request).ok_or(INVALID)?;
        spent = spent.checked_add(amount).ok_or(EXCEEDED)?;
    }
    if spent > MAX_TRANSFER_BYTES || rounds > MAX_ROUNDS {
        return Err(EXCEEDED.into());
    }
    response["budget"] = json!({"spent":spent,"rounds":rounds});
    Ok(response)
}

#[derive(Default)]
pub(super) struct Transfers {
    requests: Vec<Value>,
    seen: BTreeSet<String>,
}
impl Transfers {
    pub(super) fn push(&mut self, error: Failure) -> Result<()> {
        let value = match error {
            Failure::Need(reference) => json!({"need":reference}),
            Failure::Archives(archives) => json!({"need_archives":archives}),
            error => return Err(error),
        };
        if self.requests.len() < 32 && self.seen.insert(hash(&encoded(&value)?)) {
            self.requests.push(value);
        }
        Ok(())
    }
    pub(super) fn finish(self) -> Result<()> {
        if self.requests.is_empty() {
            Ok(())
        } else {
            Err(Failure::Batch(self.requests))
        }
    }
}
pub(super) fn prefetch(
    preparation: &mut Preparation<'_>,
    selected: &BTreeSet<String>,
) -> Result<()> {
    let mut transfers = Transfers::default();
    for id in selected {
        if preparation.input["profile"] == "committed-subset"
            && !preparation.committed_selected.contains(id)
        {
            return Err("offline subset cannot activate uncommitted policy".into());
        }
        if let Err(error) = preparation.metadata(id) {
            transfers.push(error)?;
        }
    }
    transfers.finish()?;
    let mut transfers = Transfers::default();
    for id in selected {
        let (record, _) = preparation.details.get(id).ok_or_else(invalid)?;
        if let Err(error) = metadata::revocation(
            preparation.directory,
            &preparation.root,
            id,
            &record["manifest"],
        ) {
            transfers.push(error)?;
            continue;
        }
        let manifest = match proofs::policy_object(
            preparation.directory,
            &record["manifest"],
            &record["archives"],
        ) {
            Ok(value) => value,
            Err(error) => {
                transfers.push(error)?;
                continue;
            }
        };
        for field in ["program", "catalog", "descriptors"] {
            let value = match proofs::policy_object(
                preparation.directory,
                &manifest[field],
                &record["archives"],
            ) {
                Ok(value) => value,
                Err(error) => {
                    transfers.push(error)?;
                    continue;
                }
            };
            if field == "program" {
                for reference in value["nodes"].as_object().ok_or_else(invalid)?.values() {
                    if let Err(error) =
                        proofs::policy_object(preparation.directory, reference, &record["archives"])
                    {
                        transfers.push(error)?;
                        break;
                    }
                }
            }
        }
    }
    transfers.finish()
}
