use super::*;

pub(super) fn write(
    request: &HookAuthorityStateRequestV1,
    busy: Duration,
    work: impl FnOnce(&Env<'_>) -> Result<Value, &'static str>,
) -> Result<Value, &'static str> {
    let connection =
        Connection::open_with_flags(&request.store_path, OpenFlags::SQLITE_OPEN_READ_WRITE)
            .map_err(|_| ERROR_STORE)?;
    connection.busy_timeout(busy).map_err(|_| ERROR_STORE)?;
    // Keep the read and mutation in the same SQLite write transaction.
    connection
        .execute_batch("BEGIN IMMEDIATE")
        .map_err(|_| ERROR_STORE)?;
    let env = Env {
        connection: &connection,
        guard_home: Some(Path::new(&request.guard_home)),
        key: request
            .integrity_key_b64
            .as_deref()
            .and_then(|encoded| Base64UrlUnpadded::decode_vec(encoded).ok().map(Into::into)),
        key_id: request.integrity_key_id.as_deref(),
        now: &request.now,
        foreign_key: None,
    };
    match work(&env) {
        Ok(value) => {
            connection
                .execute_batch("COMMIT")
                .map_err(|_| ERROR_STORE)?;
            Ok(value)
        }
        Err(code) => {
            let _ = connection.execute_batch("ROLLBACK");
            Err(code)
        }
    }
}
