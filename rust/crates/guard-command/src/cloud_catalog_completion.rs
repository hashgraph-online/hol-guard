//! Native-owned authenticated transport completion, separate from metadata CAS.
//! The HTTP adapter supplies the hash of the credential actually used on TLS.
use super::*;
use ring::hmac;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_PENDING_COMPLETIONS: usize = 8;
const PENDING_COMPLETION_TTL: u64 = 120_000_000;

fn pending(root: &Path, key: &hmac::Key, current_time: u64) -> Result<Vec<Value>> {
    if !root.join("completion-pending.json").try_exists()? {
        return Ok(Vec::new());
    }
    let value = load(root, "completion-pending.json", key)?;
    let records = match &value {
        Value::Array(records) => records.as_slice(),
        // Older clients persisted one authenticated challenge instead of a list.
        Value::Object(_) => std::slice::from_ref(&value),
        _ => return Err(Error::Invalid),
    };
    if records.len() > MAX_PENDING_COMPLETIONS {
        return Err(Error::Invalid);
    }
    let mut live = Vec::new();
    for record in records {
        let nonce = record["nonce"]
            .as_str()
            .filter(|v| sha(v))
            .ok_or(Error::Invalid)?;
        let started = record["started"].as_u64().ok_or(Error::Invalid)?;
        let Some(age) = current_time.checked_sub(started) else {
            continue;
        };
        if age <= PENDING_COMPLETION_TTL {
            if live.iter().any(|other: &Value| other["nonce"] == nonce) {
                return Err(Error::Invalid);
            }
            live.push(record.clone());
        }
    }
    Ok(live)
}

fn save_pending(root: &Path, records: &[Value], key: &hmac::Key) -> Result<()> {
    if records.is_empty() {
        std::fs::remove_file(root.join("completion-pending.json"))?;
        return Ok(());
    }
    let value = json!(records);
    // Keep the existing authenticated-record read budget, including its MAC envelope.
    if records.len() > MAX_PENDING_COMPLETIONS || encode(&value)?.len() > 16_000 {
        return Err(Error::Unavailable);
    }
    save(root, "completion-pending.json", &value, key)
}

fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Invalid)?
        .as_micros()
        .try_into()
        .map_err(|_| Error::Invalid)
}
fn micros(value: &Value) -> Result<u64> {
    let s = value.as_str().ok_or(Error::Invalid)?;
    if !timestamp(s) || !s.ends_with('Z') {
        return Err(Error::Invalid);
    }
    let n = |a: usize, b: usize| {
        s.get(a..b)
            .and_then(|v| v.parse::<u64>().ok())
            .ok_or(Error::Invalid)
    };
    let (y, m, d) = (n(0, 4)?, n(5, 7)?, n(8, 10)?);
    if y < 1970 {
        return Err(Error::Invalid);
    }
    let leap = |y| y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let mut days = 0;
    for year in 1970..y {
        days += if leap(year) { 366 } else { 365 };
    }
    for month in 1..m {
        days += match month {
            2 if leap(y) => 29,
            2 => 28,
            4 | 6 | 9 | 11 => 30,
            _ => 31,
        };
    }
    let seconds = ((days + d - 1) * 24 + n(11, 13)?) * 3600 + n(14, 16)? * 60 + n(17, 19)?;
    let tail = s.get(19..s.len() - 1).ok_or(Error::Invalid)?;
    let fraction = if tail.is_empty() {
        0
    } else {
        let digits = tail
            .strip_prefix('.')
            .filter(|v| v.len() <= 6)
            .ok_or(Error::Invalid)?;
        digits.parse::<u64>().map_err(|_| Error::Invalid)? * 10u64.pow(6 - digits.len() as u32)
    };
    Ok(seconds * 1_000_000 + fraction)
}
fn key(root: &Path) -> Result<hmac::Key> {
    let path = root
        .parent()
        .ok_or(Error::Invalid)?
        .join("cloud-completion.key");
    if !path.exists() {
        let mut bytes = [0; 32];
        getrandom::fill(&mut bytes).map_err(|_| Error::Unavailable)?;
        cache::write(&path, &bytes)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = path.symlink_metadata()?;
        if meta.mode() & 0o077 != 0 || meta.uid() != nix::unistd::Uid::effective().as_raw() {
            return Err(Error::Invalid);
        }
    }
    let bytes = guard_secure_fs::read_bounded(&path, 32)
        .map_err(|_| Error::Invalid)?
        .bytes;
    if bytes.len() != 32 {
        return Err(Error::Invalid);
    }
    Ok(hmac::Key::new(hmac::HMAC_SHA256, &bytes))
}
fn save(root: &Path, name: &str, value: &Value, key: &hmac::Key) -> Result<()> {
    let data = encode(value)?;
    let signed = json!({"value":value,"mac":hex::encode(hmac::sign(key,&data))});
    let mut file = tempfile::NamedTempFile::new_in(root)?;
    use std::io::Write;
    file.write_all(&encode(&signed)?)?;
    file.as_file().sync_all()?;
    file.persist(root.join(name))
        .map_err(|_| Error::Unavailable)?;
    Ok(())
}
fn load(root: &Path, name: &str, key: &hmac::Key) -> Result<Value> {
    let bytes = guard_secure_fs::read_bounded(&root.join(name), 16384)
        .map_err(|_| Error::Unavailable)?
        .bytes;
    let signed: Value = serde_json::from_slice(&bytes).map_err(|_| Error::Invalid)?;
    let mac =
        hex::decode(signed["mac"].as_str().ok_or(Error::Invalid)?).map_err(|_| Error::Invalid)?;
    hmac::verify(key, &encode(&signed["value"])?, &mac).map_err(|_| Error::Invalid)?;
    Ok(signed["value"].clone())
}
fn current(request: &Value, root: &Path) -> Result<Value> {
    let token = request["token"]
        .as_str()
        .filter(|v| sha(v))
        .ok_or(Error::Invalid)?;
    let record = cache::record(&root.join(token))?;
    if digest(&record["manifest"])? != token || request["observation"] != record["observation"] {
        return Err(Error::Invalid);
    }
    cache::verify(&root.join(token), &record)?;
    Ok(record)
}
fn identity(value: &Value) -> Result<()> {
    let obj = value.as_object().ok_or(Error::Invalid)?;
    if obj.len() != 4
        || ["ownerUserId", "workspaceId", "deviceId", "runtimeId"]
            .iter()
            .any(|k| {
                !obj.get(*k)
                    .and_then(Value::as_str)
                    .is_some_and(|s| !s.is_empty() && s.len() <= 128)
            })
    {
        return Err(Error::Invalid);
    }
    Ok(())
}
/// Policy/readiness callers must authenticate the stored stamp, not a response
/// summary or a content-addressed metadata path.
pub fn validate(home: &Path, local: &Value) -> Result<Value> {
    let root = cache::directory(home)?;
    let lock = cache::lock_file(&root.join("cache.lock"))?;
    fs2::FileExt::lock_exclusive(&lock)?;
    let record = current(local, &root)?;
    let stamp = load(&root, "completion.json", &key(&root)?)?;
    if stamp["token"] != local["token"] || stamp["observation"] != record["observation"] {
        return Err(Error::Invalid);
    }
    let receipt = &stamp["receipt"];
    identity(&receipt["identity"])?;
    if local
        .get("identity")
        .is_some_and(|v| *v != receipt["identity"])
        || local
            .get("observed_at")
            .is_some_and(|v| *v != receipt["observedAt"])
    {
        return Err(Error::Invalid);
    }
    let observed = micros(&receipt["observedAt"])?;
    let age = now()?.checked_sub(observed).ok_or(Error::Invalid)?;
    if age > 900_000_000 {
        return Err(Error::Unavailable);
    }
    Ok(receipt.clone())
}
pub fn evaluate(request: &Value) -> Result<Value> {
    let home = Path::new(request["guard_home"].as_str().ok_or(Error::Invalid)?);
    if request["action"] == "completion_read" {
        return validate(home, request);
    }
    let root = cache::directory(home)?;
    let lock = cache::lock_file(&root.join("cache.lock"))?;
    fs2::FileExt::lock_exclusive(&lock)?;
    let key = key(&root)?;
    let record = current(request, &root)?;
    let mut challenges = pending(&root, &key, now()?)?;
    if request["action"] == "completion_begin" {
        let origin = request["origin"].as_str().ok_or(Error::Invalid)?;
        let url = url::Url::parse(origin).map_err(|_| Error::Invalid)?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.path() != "/api/guard/runtime/extension-catalog/sync-v2"
            || url.fragment().is_some()
            || !request["credential_binding"].as_str().is_some_and(sha)
        {
            return Err(Error::Invalid);
        }
        identity(&request["identity"])?;
        if challenges.len() >= MAX_PENDING_COMPLETIONS {
            return Err(Error::Unavailable);
        }
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).map_err(|_| Error::Unavailable)?;
        let nonce = hex::encode(nonce);
        let pending = json!({"nonce":nonce,"started":now()?,"origin":origin,
            "credential":request["credential_binding"],"identity":request["identity"],
            "token":request["token"],"observation":record["observation"]});
        challenges.push(pending);
        save_pending(&root, &challenges, &key)?;
        return Ok(
            json!({"operation":"observe","idempotencyKey":nonce,"manifest":record["manifest"]}),
        );
    }
    if request["action"] != "completion_accept" {
        return Err(Error::Invalid);
    }
    let response = &request["response"];
    let receipt = &response["observation"];
    let nonce = receipt["nonce"]
        .as_str()
        .filter(|v| sha(v))
        .ok_or(Error::Invalid)?;
    let index = challenges
        .iter()
        .position(|pending| pending["nonce"] == nonce)
        .ok_or(Error::Invalid)?;
    let pending = &challenges[index];
    let manifest = &record["manifest"];
    let started = pending["started"].as_u64().ok_or(Error::Invalid)?;
    let current_time = now()?;
    let observed = micros(&receipt["observedAt"])?;
    if current_time
        .checked_sub(started)
        .is_none_or(|age| age > PENDING_COMPLETION_TTL)
        // Date.toISOString rounds server timestamps down to milliseconds.
        || observed.saturating_add(999) < started
        || observed > current_time
        || pending["token"] != request["token"]
        || pending["observation"] != record["observation"]
        || pending["origin"] != request["origin"]
        || pending["credential"] != request["credential_binding"]
        || receipt.as_object().is_none_or(|o| o.len() != 9)
        || response.as_object().is_none_or(|o| o.len() != 5)
        || response["schemaVersion"] != "guard.extension-catalog-sync.v2"
        || response["accepted"] != true
        || response["complete"] != true
        || response["catalogDigest"] != manifest["catalogDigest"]
        || receipt["schemaVersion"] != "guard.catalog-observation.v2"
        || receipt["nonce"] != pending["nonce"]
        || receipt["credentialBinding"] != pending["credential"]
        || receipt["identity"] != pending["identity"]
        || [
            "catalogDigest",
            "enforcementCatalogDigest",
            "guardVersion",
            "controlSchemaVersion",
        ]
        .iter()
        .any(|k| receipt[k] != manifest[k])
    {
        return Err(Error::Invalid);
    }
    identity(&receipt["identity"])?;
    let stamp = json!({"token":request["token"],"observation":record["observation"],"receipt":receipt,
            "origin":pending["origin"],"credential":pending["credential"]});
    save(&root, "completion.json", &stamp, &key)?;
    challenges.remove(index);
    save_pending(&root, &challenges, &key)?;
    Ok(receipt.clone())
}

#[cfg(test)]
mod time_tests {
    use super::*;

    #[test]
    fn authenticated_single_pending_challenge_survives_upgrade_and_expires() {
        let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let root = directory.path();
        let key = hmac::Key::new(hmac::HMAC_SHA256, &[17; 32]);
        let started = 1_000_000_000u64;
        let record = json!({"nonce":"a".repeat(64),"started":started,
            "origin":"https://example.com","credential":"b".repeat(64)});
        save(root, "completion-pending.json", &record, &key).unwrap();
        let records = pending(root, &key, started).unwrap();
        assert_eq!(records, vec![record.clone()]);
        save_pending(root, &records, &key).unwrap();
        assert_eq!(
            load(root, "completion-pending.json", &key).unwrap(),
            json!([record])
        );
        assert!(pending(root, &key, started + PENDING_COMPLETION_TTL + 1)
            .unwrap()
            .is_empty());
        save(root, "completion-pending.json", &json!({}), &key).unwrap();
        assert!(pending(root, &key, started).is_err());
    }

    #[test]
    fn pending_challenges_are_bounded_authenticated_and_expire() {
        let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let root = directory.path();
        let key = hmac::Key::new(hmac::HMAC_SHA256, &[17; 32]);
        let started = 1_000_000_000u64;
        let mut records: Vec<Value> = (0..MAX_PENDING_COMPLETIONS)
            .map(|i| json!({"nonce":format!("{i:064x}"),"started":started}))
            .collect();
        save_pending(root, &records, &key).unwrap();
        assert_eq!(pending(root, &key, started).unwrap(), records);
        let before = std::fs::read(root.join("completion-pending.json")).unwrap();
        records.push(json!({"nonce":"f".repeat(64),"started":started}));
        assert!(save_pending(root, &records, &key).is_err());
        assert_eq!(
            std::fs::read(root.join("completion-pending.json")).unwrap(),
            before
        );
        assert!(pending(root, &key, started + PENDING_COMPLETION_TTL + 1)
            .unwrap()
            .is_empty());
        let live = json!({"nonce":"b".repeat(64),"started":started});
        save_pending(
            root,
            &[
                json!({"nonce":"a".repeat(64),"started":started + PENDING_COMPLETION_TTL}),
                live.clone(),
            ],
            &key,
        )
        .unwrap();
        assert_eq!(pending(root, &key, started).unwrap(), vec![live]);
        std::fs::write(root.join("completion-pending.json"), b"{}").unwrap();
        assert!(pending(root, &key, started).is_err());
    }

    #[test]
    fn observation_time_preserves_subsecond_precision() {
        let base = micros(&json!("2026-10-18T00:00:00Z")).unwrap();
        assert_eq!(
            micros(&json!("2026-10-18T00:00:00.000001Z")).unwrap(),
            base + 1
        );
        assert_eq!(
            micros(&json!("2026-10-18T00:00:00.999999Z")).unwrap(),
            base + 999_999
        );
        assert!(micros(&json!("2026-10-18T00:00:00.1234567Z")).is_err());
    }
}
