//! `CodexHookFileIdentity` - resident op deciding whether a packaged file on
//! disk is still the file an authenticated Codex hook manifest describes.
//!
//! Ported from `verify_regular_file_identity` and `validate_regular_file` in
//! `codex_hook_file_integrity.py`. Whether the live file still matches the
//! authenticated identity is what lets a Guard-managed hook run, so it is one
//! answer rather than one per caller.
//!
//! Two spellings stay with the asking interpreter and arrive in the request.
//! The canonical form of a path is the one the interpreter that wrote the
//! manifest produced, and whether a path sits under that interpreter's package
//! roots is a fact about its own install layout. Everything the answer turns
//! on - the file's type, owner, permissions, size and content - is read here.
//!
//! One question this op cannot close is whether a POSIX group is private to
//! the file's owner: proving it means enumerating the account database. When
//! the group-write bit is set on a file that would qualify for that exception,
//! the answer carries `private_group_question` and the remaining checks run as
//! if the group were private. The caller answers that question and refuses the
//! file when it is not, which is where `validate_regular_file` refuses it too,
//! so the order the failures arrive in is unchanged.

use std::fs;
use std::io::Read;
use std::path::Path;

use guard_contracts::{
    CodexHookFileIdentityQuestionV1, CodexHookFileIdentityRequestV1, CodexHookFileIdentityResultV1,
    CODEX_HOOK_FILE_IDENTITY_MAX_BYTES, CODEX_HOOK_FILE_IDENTITY_MAX_QUESTIONS,
    CODEX_HOOK_FILE_IDENTITY_REQUEST_SCHEMA, CODEX_HOOK_FILE_IDENTITY_RESULT_SCHEMA,
};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::package_authority_op::request_digest_with_limit;

/// Permission bits, named the way `stat` names them so the rules below read
/// like the Python they come from.
const S_IWOTH: u32 = 0o002;
const S_IWGRP: u32 = 0o020;
const S_IXANY: u32 = 0o111;

/// The file facts an answer turns on, read once per question.
struct FileFacts {
    mode: u32,
    uid: u32,
    gid: u32,
    size: u64,
}

pub(crate) fn evaluate_codex_hook_file_identity_request(
    request: &CodexHookFileIdentityRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest_with_limit(request, CODEX_HOOK_FILE_IDENTITY_MAX_BYTES)
        .map_err(|_| "native_codex_hook_file_identity_too_large".to_owned())?;
    let (status, code, payload) = match refusal(request) {
        Some(code) => ("error", code, None),
        None => ("ok", "ok", Some(evaluate_request(request))),
    };
    crate::encode_response(&CodexHookFileIdentityResultV1 {
        schema: CODEX_HOOK_FILE_IDENTITY_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: status.to_owned(),
        code: code.to_owned(),
        payload,
    })
}

/// The conditions the op refuses rather than answers.
fn refusal(request: &CodexHookFileIdentityRequestV1) -> Option<&'static str> {
    // A request naming another contract is not this op's to answer: the field
    // is the sender's own statement of which request shape it built.
    if request.schema != CODEX_HOOK_FILE_IDENTITY_REQUEST_SCHEMA {
        return Some("native_codex_hook_file_identity_schema_mismatch");
    }
    if request.questions.len() > CODEX_HOOK_FILE_IDENTITY_MAX_QUESTIONS {
        return Some("native_codex_hook_file_identity_too_many_questions");
    }
    // Where files carry POSIX ownership, the asking process has a uid:
    // `verify_regular_file_identity` reads it with `os.getuid`, which exists on
    // every host that reports `posix`. A request that claims POSIX and states
    // no uid is a shape the caller cannot produce, and answering it would skip
    // the owner check rather than fail it, so it is refused instead.
    if request.posix && request.current_uid.is_none() {
        return Some("native_codex_hook_file_identity_current_uid_missing");
    }
    None
}

/// One answer per question, in the request's order.
pub(crate) fn evaluate_request(request: &CodexHookFileIdentityRequestV1) -> Value {
    let answers: Vec<Value> = request
        .questions
        .iter()
        .map(|question| answer(request, question))
        .collect();
    json!({ "answers": answers })
}

/// The answer to one question, in the order `verify_regular_file_identity`
/// asks: the identity's own shape, then the live file, then the comparison.
fn answer(
    request: &CodexHookFileIdentityRequestV1,
    question: &CodexHookFileIdentityQuestionV1,
) -> Value {
    let Some(identity) = question.identity.as_object() else {
        // An identity that is not an object states no role, so it is refused
        // under the role `verify_regular_file_identity` falls back to. That
        // keeps one reason for a manifest that holds no identity and one that
        // holds an unreadable one, as the verifier this answers for does.
        return failed("file", "identity_invalid", None);
    };
    let role = role_of(identity);
    let Some(expected) = Expected::read(identity) else {
        return failed(&role, "identity_invalid", None);
    };
    let path = Path::new(&expected.path);
    let executable_required = identity.get("executable_required") == Some(&Value::Bool(true));

    // The name is looked up first only to tell a path that names nothing from
    // one that names something other than a regular file. Everything the
    // answer turns on is then read through a single open handle.
    let Ok(named) = fs::symlink_metadata(path) else {
        return failed(&role, "missing", None);
    };
    if named.file_type().is_symlink() || !named.file_type().is_file() {
        return failed(&role, "not_regular", None);
    }
    let Some((facts, file)) = open_regular(path) else {
        // The name said a regular file and the open disagreed, so the path was
        // replaced between the two or cannot be read at all. Either way the
        // content is what cannot be confirmed, and that is the reason Python
        // leaves a caller with when its own read of the file fails.
        return failed(&role, "hash_mismatch", None);
    };
    let mode = facts.mode & 0o7777;
    let mut private_group_question = None;
    if request.posix {
        if let Some(current_uid) = request.current_uid {
            if facts.uid != current_uid && facts.uid != 0 {
                return failed(&role, "owner_untrusted", None);
            }
        }
        // A file anyone may write is refused whatever the group says, so the
        // account database is never consulted for one.
        if mode & S_IWOTH != 0 {
            return failed(&role, "permissions_unsafe", None);
        }
        if mode & S_IWGRP != 0 {
            match group_write(request, question, &role, &facts) {
                GroupWrite::Trusted => {}
                GroupWrite::Unsafe => return failed(&role, "permissions_unsafe", None),
                GroupWrite::NeedsPrivateGroup { owner_uid } => {
                    private_group_question = Some(json!({
                        "owner_uid": owner_uid,
                        "group_gid": facts.gid,
                    }));
                }
            }
        }
        if executable_required && mode & S_IXANY == 0 {
            return failed(&role, "not_executable", private_group_question);
        }
    }
    // Off POSIX the execute bit has no meaning: `os.access(path, X_OK)` there
    // answers for any file that exists, and this one does.
    if question.canonical_path.as_deref() != Some(expected.path.as_str()) {
        return failed(&role, "path_mismatch", private_group_question);
    }
    if i64::from(mode) != expected.mode {
        return failed(&role, "mode_mismatch", private_group_question);
    }
    // The content is read only when the size already agrees: a file of another
    // length is a different file, and hashing it would say so at the cost of
    // reading all of it.
    if i64::try_from(facts.size).ok() != Some(expected.size)
        || !digest_matches(file, facts.size, &expected.sha256)
    {
        return failed(&role, "hash_mismatch", private_group_question);
    }
    if request.posix {
        if let Some(owner_uid) = expected_owner_uid(identity) {
            if i64::from(facts.uid) != owner_uid {
                return failed(&role, "owner_mismatch", private_group_question);
            }
        }
    }
    let mut answer = Map::new();
    answer.insert("outcome".to_owned(), Value::String("verified".to_owned()));
    answer.insert("role".to_owned(), Value::String(role));
    if let Some(question) = private_group_question {
        answer.insert("private_group_question".to_owned(), question);
    }
    Value::Object(answer)
}

/// Whether the group-write bit on this file is one Guard already trusts.
enum GroupWrite {
    Trusted,
    Unsafe,
    NeedsPrivateGroup { owner_uid: u32 },
}

fn group_write(
    request: &CodexHookFileIdentityRequestV1,
    question: &CodexHookFileIdentityQuestionV1,
    role: &str,
    facts: &FileFacts,
) -> GroupWrite {
    // Members of gid 0 already have the privilege needed to replace a
    // root-owned interpreter regardless of its group-write bit. The
    // GitHub-hosted Python toolcache uses this conventional 0775, root:root
    // layout.
    if role == "interpreter"
        && (request.current_uid == Some(facts.uid) || (facts.uid == 0 && facts.gid == 0))
    {
        return GroupWrite::Trusted;
    }
    let owner_is_asker = request.current_uid == Some(facts.uid);
    let exception_applies =
        owner_is_asker && (role == "config_target" || question.installed_python_package_file);
    match (exception_applies, request.current_uid) {
        (true, Some(owner_uid)) => GroupWrite::NeedsPrivateGroup { owner_uid },
        _ => GroupWrite::Unsafe,
    }
}

/// The fields an identity must carry for the comparison to mean anything.
struct Expected {
    path: String,
    sha256: String,
    mode: i64,
    size: i64,
}

impl Expected {
    fn read(identity: &Map<String, Value>) -> Option<Self> {
        let path = identity.get("path")?.as_str()?.to_owned();
        if !Path::new(&path).is_absolute() {
            return None;
        }
        let sha256 = identity.get("sha256")?.as_str()?.to_owned();
        let mode = whole_number(identity.get("mode")?)?;
        let size = whole_number(identity.get("size")?)?;
        Some(Self {
            path,
            sha256,
            mode,
            size,
        })
    }
}

/// A JSON integer that is not a boolean, the way `isinstance(value, int) and
/// not isinstance(value, bool)` reads it.
///
/// The value is kept as it arrived rather than narrowed to the width a mode or
/// a size can actually hold. A manifest holding a negative or outsized number
/// has a number where one belongs, so it fails the comparison it is in rather
/// than the shape check before it, which is where the Python puts it too.
fn whole_number(value: &Value) -> Option<i64> {
    let Value::Number(number) = value else {
        return None;
    };
    if number.is_f64() {
        return None;
    }
    // Above `i64::MAX` the value is still an integer the identity carries; no
    // file mode or size reaches it, so it compares unequal to whatever is on
    // disk, which is the answer either way.
    Some(number.as_i64().unwrap_or(i64::MAX))
}

/// The owner a manifest expects, read the way the Python reads it.
///
/// `isinstance(expected_owner, int)` is true for a JSON boolean as well, so a
/// manifest holding `true` there compares the live uid against 1. The shape
/// check above refuses a boolean `mode` or `size` explicitly and this one does
/// not, so the boolean keeps the meaning Python gives it rather than being
/// quietly ignored here.
fn expected_owner_uid(identity: &Map<String, Value>) -> Option<i64> {
    match identity.get("owner_uid") {
        Some(Value::Bool(value)) => Some(i64::from(*value)),
        Some(value) => whole_number(value),
        None => None,
    }
}

/// The role an identity names, or the one `verify_regular_file_identity`
/// falls back to.
fn role_of(identity: &Map<String, Value>) -> String {
    match identity.get("role").and_then(Value::as_str) {
        Some(role) if !role.is_empty() => role.to_owned(),
        _ => "file".to_owned(),
    }
}

fn failed(role: &str, kind: &str, private_group_question: Option<Value>) -> Value {
    let mut answer = Map::new();
    answer.insert("outcome".to_owned(), Value::String("failed".to_owned()));
    answer.insert("role".to_owned(), Value::String(role.to_owned()));
    answer.insert("kind".to_owned(), Value::String(kind.to_owned()));
    if let Some(question) = private_group_question {
        answer.insert("private_group_question".to_owned(), question);
    }
    Value::Object(answer)
}

/// The file's own facts, read through a handle opened on the very file they
/// describe.
///
/// The facts come from that handle and the content below is hashed from it
/// too, so a path replaced between the two cannot have its type, owner and
/// permissions read from one file and its bytes read from another. The open
/// itself refuses to resolve a link standing where a regular file belongs, and
/// does not block on a pipe or device standing there, so neither can be
/// swapped in after the name was checked.
fn open_regular(path: &Path) -> Option<(FileFacts, fs::File)> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // `FILE_FLAG_OPEN_REPARSE_POINT`, spelled as its value so this file
        // needs no Windows API crate: it opens a symlink or junction as the
        // reparse point it is rather than following it, which is what makes
        // the `is_file` check below refuse one.
        options.custom_flags(0x0020_0000);
    }
    let file = options.open(path).ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() {
        return None;
    }
    Some((
        FileFacts {
            mode: file_mode(path, &metadata),
            uid: file_uid(&metadata),
            gid: file_gid(&metadata),
            size: metadata.len(),
        },
        file,
    ))
}

#[cfg(unix)]
fn file_mode(_path: &Path, metadata: &fs::Metadata) -> u32 {
    std::os::unix::fs::MetadataExt::mode(metadata)
}

#[cfg(unix)]
fn file_uid(metadata: &fs::Metadata) -> u32 {
    std::os::unix::fs::MetadataExt::uid(metadata)
}

#[cfg(unix)]
fn file_gid(metadata: &fs::Metadata) -> u32 {
    std::os::unix::fs::MetadataExt::gid(metadata)
}

// Off POSIX a file carries no owner or group, and the request says so: the
// rules that read them run only when `posix` is set. The mode is still
// compared against the one the manifest recorded, so it is spelled the way the
// interpreter that wrote the manifest spells it on Windows - the read-only
// attribute, plus the execute bits that `os.stat` grants the four extensions
// the shell will run directly.
#[cfg(not(unix))]
fn file_mode(path: &Path, metadata: &fs::Metadata) -> u32 {
    let mut mode = if metadata.permissions().readonly() {
        0o444
    } else {
        0o666
    };
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if matches!(extension.as_str(), "bat" | "cmd" | "exe" | "com") {
        mode |= S_IXANY;
    }
    mode
}

#[cfg(not(unix))]
fn file_uid(_metadata: &fs::Metadata) -> u32 {
    0
}

#[cfg(not(unix))]
fn file_gid(_metadata: &fs::Metadata) -> u32 {
    0
}

/// Whether the file's content hashes to the digest the manifest recorded.
///
/// The comparison is length-constant the way `hmac.compare_digest` is, so a
/// digest that differs late tells an observer no more than one that differs
/// early. A file that cannot be read after the checks above is not the file
/// the manifest describes either, so it answers the same way rather than
/// carrying the read error out of the comparison.
fn digest_matches(file: fs::File, size: u64, expected: &str) -> bool {
    let Some(actual) = sha256_file(file, size) else {
        return false;
    };
    constant_time_equals(actual.as_bytes(), expected.as_bytes())
}

/// Hashes at most `size` bytes - the length this handle reported, which the
/// caller has already compared against the length the manifest recorded. A
/// writer extending the file underneath the read cannot hold the worker past
/// the length that was measured, and one truncating it hashes short, which the
/// comparison answers as the mismatch it is.
fn sha256_file(file: fs::File, size: u64) -> Option<String> {
    let mut file = file.take(size);
    let mut digest = Sha256::new();
    // A manifest names hook scripts far more often than interpreters, so the
    // read buffer follows the file rather than reserving a megabyte for every
    // question in a batch.
    let capacity = usize::try_from(size.clamp(1, 1024 * 1024)).unwrap_or(1024 * 1024);
    let mut buffer = vec![0_u8; capacity];
    loop {
        let read = file.read(&mut buffer).ok()?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Some(format!("{:x}", digest.finalize()))
}

fn constant_time_equals(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (one, other) in left.iter().zip(right) {
        difference |= one ^ other;
    }
    difference == 0
}

#[cfg(test)]
#[path = "codex_hook_file_identity_op_tests.rs"]
mod tests;
